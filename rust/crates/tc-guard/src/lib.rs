#![forbid(unsafe_code)]

//! Pure-Rust migration of `client/manual_bandwidth.py`: safe, opt-in `tc`
//! `clsact` bandwidth policing for a host interface or isolated container
//! network namespaces (`incus`, `podman`, `runman`), including deterministic
//! filter handles, kernel readback verification, auto-throttle tier state
//! machine, and atomic JSON state persistence.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::fmt::{self, Write as _};
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proc_probe::json_escape;
use runtime_drivers::{ContainerSample, JsonVal};
use transport::sha256_hex;

pub const DEFAULT_STATE_PATH: &str = "/var/lib/narwhal-monitor/manual-bandwidth-limits.json";
pub const STATE_PATH_ENV: &str = "NARWHAL_MANUAL_BANDWIDTH_STATE";
pub const PREF_DOWNLOAD: u16 = 49150;
pub const PREF_UPLOAD: u16 = 49151;
pub const PREF_RANGE_START: u16 = 49150;
pub const PREF_RANGE_END: u16 = 65535;
pub const MAX_POLICIES: usize = 256;
pub const MAX_RATE_MBPS: u32 = 100_000;
pub const AUTO_THRESHOLD_PERCENT: u32 = 80;
pub const AUTO_TRIGGER_SECONDS: u64 = 300;
pub const AUTO_TIER_PERCENTAGES: [u32; 3] = [50, 25, 5];
pub const AUTO_MINIMUM_MBPS: u32 = 1;
pub const AUTO_RECOVERY_PERCENT: u32 = 50;
pub const AUTO_RECOVERY_SECONDS: u64 = 600;
const MAX_JSON_DEPTH: usize = 64;
const DEFAULT_CMD_TIMEOUT: Duration = Duration::from_secs(8);
const DEFAULT_OUTPUT_LIMIT: usize = 2000;
const MAX_INVENTORY_OUTPUT: usize = 8 * 1024 * 1024;
const MAX_INVENTORY_ITEMS: usize = 4096;
const PRUNE_DEPARTED_AFTER_SECS: u64 = 86_400;

static TEMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// 1. Errors and core enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BandwidthError {
    Policy(String),
    Mutation {
        message: String,
        rollback_state: String,
    },
}

pub type BandwidthPolicyError = BandwidthError;

impl BandwidthError {
    pub fn policy(msg: impl Into<String>) -> Self {
        Self::Policy(msg.into())
    }

    pub fn mutation(msg: impl Into<String>, rollback_state: impl Into<String>) -> Self {
        Self::Mutation {
            message: msg.into(),
            rollback_state: rollback_state.into(),
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Policy(m) => m,
            Self::Mutation { message, .. } => message,
        }
    }

    pub fn rollback_state(&self) -> Option<&str> {
        match self {
            Self::Policy(_) => None,
            Self::Mutation { rollback_state, .. } => Some(rollback_state.as_str()),
        }
    }
}

impl fmt::Display for BandwidthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for BandwidthError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    Host,
    Container,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Container => "container",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeKind {
    Incus,
    Podman,
    Runman,
}

impl RuntimeKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "incus" => Some(Self::Incus),
            "podman" => Some(Self::Podman),
            "runman" => Some(Self::Runman),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Incus => "incus",
            Self::Podman => "podman",
            Self::Runman => "runman",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    Download,
    Upload,
}

impl Direction {
    pub const BOTH: [Direction; 2] = [Direction::Download, Direction::Upload];

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "download" => Some(Self::Download),
            "upload" => Some(Self::Upload),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Upload => "upload",
        }
    }

    pub fn tc_direction(self) -> &'static str {
        match self {
            Self::Download => "ingress",
            Self::Upload => "egress",
        }
    }

    pub fn default_pref(self) -> u16 {
        match self {
            Self::Download => PREF_DOWNLOAD,
            Self::Upload => PREF_UPLOAD,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetnsError {
    NotFound,
    Unavailable(String),
}

impl fmt::Display for NetnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "network namespace not found"),
            Self::Unavailable(msg) => write!(f, "{msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Lossless pure-std JSON parser & serializer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut parser = JsonParser {
            src: input,
            bytes: input.as_bytes(),
            pos: 0,
        };
        let val = parser.parse_value(0)?;
        parser.skip_ws();
        if parser.pos < parser.bytes.len() {
            return Err(format!("trailing JSON data at offset {}", parser.pos));
        }
        Ok(val)
    }

    pub fn to_json(&self) -> String {
        match self {
            Self::Null => "null".to_string(),
            Self::Bool(true) => "true".to_string(),
            Self::Bool(false) => "false".to_string(),
            Self::Number(n) => n.clone(),
            Self::String(s) => format!("\"{}\"", json_escape(s)),
            Self::Array(arr) => {
                let mut out = String::from("[");
                for (idx, item) in arr.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    out.push_str(&item.to_json());
                }
                out.push(']');
                out
            }
            Self::Object(map) => {
                let mut out = String::from("{");
                for (idx, (k, v)) in map.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    let _ = write!(out, "\"{}\":{}", json_escape(k), v.to_json());
                }
                out.push('}');
                out
            }
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Strict integer check matching Python `type(v) is int`: rejects floats (`1.0`, `1e2`), bools, and strings.
    pub fn as_strict_i64(&self) -> Option<i64> {
        match self {
            Self::Number(raw) => {
                if raw.contains('.') || raw.contains('e') || raw.contains('E') {
                    return None;
                }
                raw.parse::<i64>().ok()
            }
            _ => None,
        }
    }

    pub fn as_i64_lenient(&self) -> Option<i64> {
        match self {
            Self::Number(raw) => {
                if let Ok(i) = raw.parse::<i64>() {
                    return Some(i);
                }
                if let Ok(f) = raw.parse::<f64>() {
                    if f.is_finite() && f >= (i64::MIN as f64) && f <= (i64::MAX as f64) {
                        return Some(f as i64);
                    }
                }
                None
            }
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(raw) => raw.parse::<f64>().ok().filter(|v| v.is_finite()),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            Self::Array(arr) => Some(arr.as_slice()),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            Self::Object(map) => Some(map),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        self.as_object()?.get(key)
    }
}

struct JsonParser<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, String> {
        if depth > MAX_JSON_DEPTH {
            return Err("JSON nesting depth exceeded".to_string());
        }
        self.skip_ws();
        let b = self
            .peek()
            .ok_or_else(|| "unexpected end of JSON".to_string())?;
        match b {
            b'n' => {
                if self.bytes[self.pos..].starts_with(b"null") {
                    self.pos += 4;
                    Ok(JsonValue::Null)
                } else {
                    Err(format!("invalid literal at {}", self.pos))
                }
            }
            b't' => {
                if self.bytes[self.pos..].starts_with(b"true") {
                    self.pos += 4;
                    Ok(JsonValue::Bool(true))
                } else {
                    Err(format!("invalid literal at {}", self.pos))
                }
            }
            b'f' => {
                if self.bytes[self.pos..].starts_with(b"false") {
                    self.pos += 5;
                    Ok(JsonValue::Bool(false))
                } else {
                    Err(format!("invalid literal at {}", self.pos))
                }
            }
            b'"' => self.parse_string().map(JsonValue::String),
            b'[' => self.parse_array(depth),
            b'{' => self.parse_object(depth),
            b'-' | b'0'..=b'9' => self.parse_number(),
            other => Err(format!("unexpected byte 0x{other:02x} at {}", self.pos)),
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(format!("invalid number at {start}")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(format!("invalid fraction at {start}"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(format!("invalid exponent at {start}"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let raw = &self.src[start..self.pos];
        let parsed = raw
            .parse::<f64>()
            .map_err(|_| format!("invalid float '{raw}'"))?;
        if !parsed.is_finite() {
            return Err(format!("non-finite number '{raw}'"));
        }
        Ok(JsonValue::Number(raw.to_string()))
    }

    fn parse_hex4(&mut self) -> Result<u16, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("truncated unicode escape".to_string());
        }
        let hex = &self.src[self.pos..self.pos + 4];
        self.pos += 4;
        u16::from_str_radix(hex, 16).map_err(|_| format!("invalid unicode escape \\u{hex}"))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.bytes.get(self.pos) != Some(&b'"') {
            return Err(format!("expected '\"' at {}", self.pos));
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                if self.pos >= self.bytes.len() {
                    return Err("unterminated escape".to_string());
                }
                let esc = self.bytes[self.pos];
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let code = self.parse_hex4()?;
                        if (0xD800..=0xDBFF).contains(&code) {
                            if self.pos + 2 <= self.bytes.len()
                                && self.bytes[self.pos] == b'\\'
                                && self.bytes[self.pos + 1] == b'u'
                            {
                                self.pos += 2;
                                let low = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err("invalid low surrogate".to_string());
                                }
                                let combined = 0x10000
                                    + (((code as u32 - 0xD800) << 10) | (low as u32 - 0xDC00));
                                let ch = char::from_u32(combined)
                                    .ok_or_else(|| "invalid surrogate pair".to_string())?;
                                out.push(ch);
                            } else {
                                return Err("unpaired high surrogate".to_string());
                            }
                        } else if (0xDC00..=0xDFFF).contains(&code) {
                            return Err("unpaired low surrogate".to_string());
                        } else {
                            let ch = char::from_u32(code as u32)
                                .ok_or_else(|| "invalid unicode scalar".to_string())?;
                            out.push(ch);
                        }
                    }
                    other => return Err(format!("invalid escape '\\{}'", other as char)),
                }
                continue;
            }
            if b < 0x20 {
                return Err(format!("unescaped control byte 0x{b:02x}"));
            }
            let ch = self.src[self.pos..]
                .chars()
                .next()
                .ok_or_else(|| "invalid UTF-8".to_string())?;
            out.push(ch);
            self.pos += ch.len_utf8();
        }
        Err("unterminated string".to_string())
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, String> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.parse_value(depth + 1)?);
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                return Err("unterminated array".to_string());
            }
            let delim = self.bytes[self.pos];
            self.pos += 1;
            match delim {
                b',' => continue,
                b']' => return Ok(JsonValue::Array(items)),
                _ => return Err(format!("expected ',' or ']' at {}", self.pos - 1)),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, String> {
        self.pos += 1;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(format!("expected object key at {}", self.pos));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b':') {
                return Err(format!("expected ':' at {}", self.pos));
            }
            self.pos += 1;
            let val = self.parse_value(depth + 1)?;
            map.insert(key, val);
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                return Err("unterminated object".to_string());
            }
            let delim = self.bytes[self.pos];
            self.pos += 1;
            match delim {
                b',' => continue,
                b'}' => return Ok(JsonValue::Object(map)),
                _ => return Err(format!("expected ',' or '}}' at {}", self.pos - 1)),
            }
        }
    }
}

fn format_f64_json(val: f64) -> String {
    let clean = if val == 0.0 { 0.0 } else { val };
    if clean.fract() == 0.0 {
        format!("{clean:.1}")
    } else {
        format!("{clean}")
    }
}

fn round3(val: f64) -> f64 {
    let r = (val * 1000.0).round() / 1000.0;
    if r == 0.0 {
        0.0
    } else {
        r
    }
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

// ---------------------------------------------------------------------------
// 3. Regex-equivalent character validators
// ---------------------------------------------------------------------------

fn is_iface_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'+' | b'-')
}

pub fn is_valid_iface_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 15 && s.bytes().all(is_iface_char)
}

fn is_safe_sysfs_iface(s: &str) -> bool {
    is_valid_iface_name(s) && s != "." && s != ".."
}

fn is_valid_container_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 200 && s.bytes().all(is_iface_char)
}

fn is_valid_container_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(is_iface_char)
}

fn is_valid_incus_project(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn is_valid_runtime_bin(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 240
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'+' | b'-'))
}

fn is_valid_hex64_lower(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_valid_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (idx, &ch) in b.iter().enumerate() {
        match idx {
            8 | 13 | 18 | 23 => {
                if ch != b'-' {
                    return false;
                }
            }
            _ => {
                if !ch.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// 4. Policy structures & `validate_policy`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedLimit {
    pub scope: Scope,
    pub interface: String,
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub container_id: String,
    pub upload_mbps: u32,
    pub download_mbps: u32,
}

impl NormalizedLimit {
    pub fn key(&self) -> String {
        match self.scope {
            Scope::Host => format!("host:{}", self.interface),
            Scope::Container => format!(
                "container:{}\0{}\0{}\0{}",
                self.runtime, self.project, self.container_name, self.container_id
            ),
        }
    }

    pub fn rate_for(&self, direction: Direction) -> u32 {
        match direction {
            Direction::Download => self.download_mbps,
            Direction::Upload => self.upload_mbps,
        }
    }

    pub fn target_label(&self) -> &str {
        match self.scope {
            Scope::Host => &self.interface,
            Scope::Container => &self.container_name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPolicy {
    pub schema: u32,
    pub host_id: String,
    pub expected_node_id: String,
    pub revision: i64,
    pub limits: Vec<NormalizedLimit>,
    pub auto_throttle_enabled: bool,
}

fn valid_int_range(value: Option<&JsonValue>, min: i64, max: i64) -> Result<i64, BandwidthError> {
    let Some(val) = value else {
        return Ok(0);
    };
    let Some(num) = val.as_strict_i64() else {
        return Err(BandwidthError::policy("invalid rate"));
    };
    if num < min || num > max {
        return Err(BandwidthError::policy("rate is outside the supported range"));
    }
    Ok(num)
}

fn optional_str_field<'a>(obj: &'a BTreeMap<String, JsonValue>, key: &str) -> &'a str {
    match obj.get(key) {
        Some(JsonValue::String(s)) => s.as_str(),
        _ => "",
    }
}

/// Validate and normalize a raw JSON bandwidth policy against expected `host_id` and `node_id`.
pub fn validate_policy(
    policy_json: &str,
    host_id: &str,
    node_id: &str,
) -> Result<NormalizedPolicy, BandwidthError> {
    let val = JsonValue::parse(policy_json)
        .map_err(|_| BandwidthError::policy("unsupported bandwidth policy"))?;
    validate_policy_value(&val, host_id, node_id)
}

/// Validate and normalize a parsed `JsonValue` bandwidth policy.
pub fn validate_policy_value(
    policy: &JsonValue,
    host_id: &str,
    node_id: &str,
) -> Result<NormalizedPolicy, BandwidthError> {
    let Some(obj) = policy.as_object() else {
        return Err(BandwidthError::policy("unsupported bandwidth policy"));
    };
    if obj.get("schema").and_then(JsonValue::as_strict_i64) != Some(1) {
        return Err(BandwidthError::policy("unsupported bandwidth policy"));
    }
    if obj.get("host_id").and_then(JsonValue::as_str) != Some(host_id)
        || obj.get("expected_node_id").and_then(JsonValue::as_str) != Some(node_id)
    {
        return Err(BandwidthError::policy(
            "bandwidth policy host identity mismatch",
        ));
    }
    let Some(limits) = obj.get("limits").and_then(JsonValue::as_array) else {
        return Err(BandwidthError::policy("invalid bandwidth policy list"));
    };
    if limits.len() > MAX_POLICIES {
        return Err(BandwidthError::policy("invalid bandwidth policy list"));
    }

    let mut normalized = Vec::with_capacity(limits.len());
    let mut identities = HashSet::with_capacity(limits.len());
    let mut host_limits = 0usize;

    for raw_item in limits {
        let Some(item) = raw_item.as_object() else {
            return Err(BandwidthError::policy("invalid bandwidth policy item"));
        };
        let upload =
            valid_int_range(item.get("upload_mbps"), 0, MAX_RATE_MBPS as i64)? as u32;
        let download =
            valid_int_range(item.get("download_mbps"), 0, MAX_RATE_MBPS as i64)? as u32;
        if upload == 0 && download == 0 {
            return Err(BandwidthError::policy(
                "at least one direction needs a non-zero rate",
            ));
        }

        let scope_str = item.get("scope").and_then(JsonValue::as_str).unwrap_or("");
        let entry = match scope_str {
            "host" => {
                let iface = optional_str_field(item, "interface");
                if !is_valid_iface_name(iface) {
                    return Err(BandwidthError::policy("invalid host interface"));
                }
                host_limits += 1;
                NormalizedLimit {
                    scope: Scope::Host,
                    interface: iface.to_string(),
                    runtime: String::new(),
                    project: String::new(),
                    container_name: String::new(),
                    container_id: String::new(),
                    upload_mbps: upload,
                    download_mbps: download,
                }
            }
            "container" => {
                let runtime = optional_str_field(item, "runtime");
                let project = optional_str_field(item, "project");
                let name = optional_str_field(item, "container_name");
                let container_id = optional_str_field(item, "container_id");
                if RuntimeKind::parse(runtime).is_none() {
                    return Err(BandwidthError::policy(
                        "only Incus, Podman, and Runman containers can be limited",
                    ));
                }
                if !is_valid_container_name(name) {
                    return Err(BandwidthError::policy("invalid container name"));
                }
                if !project.is_empty() && !is_valid_incus_project(project) {
                    return Err(BandwidthError::policy("invalid Incus project"));
                }
                if !is_valid_container_id(container_id) {
                    return Err(BandwidthError::policy("container ID is required"));
                }
                NormalizedLimit {
                    scope: Scope::Container,
                    interface: String::new(),
                    runtime: runtime.to_string(),
                    project: project.to_string(),
                    container_name: name.to_string(),
                    container_id: container_id.to_string(),
                    upload_mbps: upload,
                    download_mbps: download,
                }
            }
            _ => {
                return Err(BandwidthError::policy("scope must be host or container"));
            }
        };

        let key = entry.key();
        if !identities.insert(key) {
            return Err(BandwidthError::policy("duplicate bandwidth target"));
        }
        normalized.push(entry);
    }

    if host_limits > 1 {
        return Err(BandwidthError::policy(
            "only one host interface can be configured",
        ));
    }

    let auto_enabled = match obj.get("auto_throttle") {
        None | Some(JsonValue::Null) => host_limits == 1,
        Some(JsonValue::Object(auto_obj)) => match auto_obj.get("enabled") {
            Some(JsonValue::Bool(b)) => *b,
            _ => {
                return Err(BandwidthError::policy(
                    "invalid automatic bandwidth protection setting",
                ))
            }
        },
        _ => {
            return Err(BandwidthError::policy(
                "invalid automatic bandwidth protection setting",
            ))
        }
    };

    if auto_enabled && host_limits != 1 {
        return Err(BandwidthError::policy(
            "automatic container limiting requires one host bandwidth interface",
        ));
    }

    let revision = valid_int_range(obj.get("revision"), 0, i32::MAX as i64)?;

    Ok(NormalizedPolicy {
        schema: 1,
        host_id: host_id.to_string(),
        expected_node_id: node_id.to_string(),
        revision,
        limits: normalized,
        auto_throttle_enabled: auto_enabled,
    })
}

// ---------------------------------------------------------------------------
// 5. Deterministic tc filter handles, command generation, & readback parsing
// ---------------------------------------------------------------------------

/// Compute the deterministic 32-bit `tc` filter handle `"0x6" + sha256_hex(owner_key\0direction)[..7]`.
pub fn filter_handle_str(owner_key: &str, direction: &str) -> String {
    let mut input = Vec::with_capacity(owner_key.len() + 1 + direction.len());
    input.extend_from_slice(owner_key.as_bytes());
    input.push(0);
    input.extend_from_slice(direction.as_bytes());
    let digest = sha256_hex(&input);
    format!("0x6{}", &digest[..7])
}

/// Compute the deterministic `tc` filter handle for a typed `Direction`.
pub fn filter_handle(owner_key: &str, direction: Direction) -> String {
    filter_handle_str(owner_key, direction.as_str())
}

/// Build `tc filter <add|change>` arguments (plus optional `nsenter` prefix).
pub fn build_tc_filter_command(
    prefix: &[String],
    interface: &str,
    direction: Direction,
    verb: &str,
    pref: u16,
    handle: &str,
    rate_mbps: u32,
) -> Vec<String> {
    let mut args = Vec::with_capacity(prefix.len() + 18);
    args.extend(prefix.iter().cloned());
    args.extend([
        "tc".to_string(),
        "filter".to_string(),
        verb.to_string(),
        "dev".to_string(),
        interface.to_string(),
        direction.tc_direction().to_string(),
        "protocol".to_string(),
        "all".to_string(),
        "pref".to_string(),
        pref.to_string(),
        "handle".to_string(),
        handle.to_string(),
        "matchall".to_string(),
        "action".to_string(),
        "police".to_string(),
        "rate".to_string(),
        format!("{rate_mbps}mbit"),
        "burst".to_string(),
        "256k".to_string(),
        "conform-exceed".to_string(),
        "drop".to_string(),
    ]);
    args
}

/// Build `tc filter del` arguments (plus optional `nsenter` prefix).
pub fn build_tc_filter_del_command(
    prefix: &[String],
    interface: &str,
    direction: Direction,
    pref: u16,
    handle: &str,
) -> Vec<String> {
    let mut args = Vec::with_capacity(prefix.len() + 12);
    args.extend(prefix.iter().cloned());
    args.extend([
        "tc".to_string(),
        "filter".to_string(),
        "del".to_string(),
        "dev".to_string(),
        interface.to_string(),
        direction.tc_direction().to_string(),
        "protocol".to_string(),
        "all".to_string(),
        "pref".to_string(),
        pref.to_string(),
        "handle".to_string(),
        handle.to_string(),
    ]);
    args
}

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn contains_word(haystack: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let h = haystack.as_bytes();
    let mut start = 0;
    while let Some(rel) = haystack[start..].find(word) {
        let idx = start + rel;
        let left_ok = idx == 0 || !is_word_char(h[idx - 1]);
        let end = idx + word.len();
        let right_ok = end == h.len() || !is_word_char(h[end]);
        if left_ok && right_ok {
            return true;
        }
        start = idx + 1;
    }
    false
}

/// Split `tc filter show` output on `"filter protocol "` boundaries (keeping each marker).
pub fn split_filter_blocks(listing: &str) -> Vec<&str> {
    let marker = "filter protocol ";
    let mut starts = Vec::new();
    let mut offset = 0usize;
    while let Some(rel) = listing[offset..].find(marker) {
        let pos = offset + rel;
        starts.push(pos);
        offset = pos + marker.len();
    }
    if starts.is_empty() {
        return vec![listing];
    }
    let mut blocks = Vec::with_capacity(starts.len() + 1);
    if starts[0] > 0 {
        blocks.push(&listing[..starts[0]]);
    } else {
        blocks.push("");
    }
    for idx in 0..starts.len() {
        let begin = starts[idx];
        let end = starts.get(idx + 1).copied().unwrap_or(listing.len());
        blocks.push(&listing[begin..end]);
    }
    blocks
}

fn block_has_kv_token(block: &str, key: &str, expected_val: &str) -> bool {
    let bytes = block.as_bytes();
    let mut offset = 0usize;
    while let Some(rel) = block[offset..].find(key) {
        let idx = offset + rel;
        let left_ok = idx == 0 || !is_word_char(bytes[idx - 1]);
        let mut pos = idx + key.len();
        if left_ok && pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if block[pos..].starts_with(expected_val) {
                let val_end = pos + expected_val.len();
                if val_end == bytes.len() || !is_word_char(bytes[val_end]) {
                    return true;
                }
            }
        }
        offset = idx + 1;
    }
    false
}

fn find_all_prefs_in_text(text: &str) -> Vec<u16> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut offset = 0usize;
    while let Some(rel) = text[offset..].find("pref") {
        let idx = offset + rel;
        let left_ok = idx == 0 || !is_word_char(bytes[idx - 1]);
        let mut pos = idx + 4;
        if left_ok && pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            let d_start = pos;
            while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                pos += 1;
            }
            if pos > d_start && (pos == bytes.len() || !is_word_char(bytes[pos])) {
                if let Ok(pref) = text[d_start..pos].parse::<u32>() {
                    if (1..=65535).contains(&pref) {
                        out.push(pref as u16);
                    }
                }
            }
        }
        offset = idx + 1;
    }
    out
}

/// Parse `\brate\s+([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?bit(?:/s)?|[kmgt]?bps)\b` (case-insensitive) to Mbps.
pub fn parse_police_rate_mbps(block: &str) -> Option<f64> {
    let bytes = block.as_bytes();
    let mut i = 0usize;
    while i + 4 < bytes.len() {
        if (i == 0 || !is_word_char(bytes[i - 1]))
            && bytes[i..i + 4].eq_ignore_ascii_case(b"rate")
            && bytes[i + 4].is_ascii_whitespace()
        {
            let mut j = i + 4;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let num_start = j;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > num_start {
                if j + 1 < bytes.len() && bytes[j] == b'.' && bytes[j + 1].is_ascii_digit() {
                    j += 1;
                    while j < bytes.len() && bytes[j].is_ascii_digit() {
                        j += 1;
                    }
                }
                let num_end = j;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len() {
                    let prefix_mult = match bytes[j].to_ascii_lowercase() {
                        b'k' => {
                            j += 1;
                            Some(1_000.0_f64)
                        }
                        b'm' => {
                            j += 1;
                            Some(1_000_000.0_f64)
                        }
                        b'g' => {
                            j += 1;
                            Some(1_000_000_000.0_f64)
                        }
                        b't' => {
                            j += 1;
                            Some(1_000_000_000_000.0_f64)
                        }
                        _ => None,
                    };
                    let mult = prefix_mult.unwrap_or(1.0);
                    let rest = &bytes[j..];
                    let unit_len = if rest.len() >= 3 && rest[..3].eq_ignore_ascii_case(b"bit") {
                        if rest.len() >= 5 && rest[3..5].eq_ignore_ascii_case(b"/s") {
                            Some(5)
                        } else {
                            Some(3)
                        }
                    } else if rest.len() >= 3 && rest[..3].eq_ignore_ascii_case(b"bps") {
                        Some(3)
                    } else {
                        None
                    };
                    if let Some(ulen) = unit_len {
                        let u_end = j + ulen;
                        if u_end == bytes.len() || !is_word_char(bytes[u_end]) {
                            if let Ok(val) = block[num_start..num_end].parse::<f64>() {
                                if val.is_finite() {
                                    return Some(val * mult / 1_000_000.0);
                                }
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }
    None
}

pub fn filter_present(listing: &str, handle: &str, pref: u16) -> bool {
    let pref_str = pref.to_string();
    for block in split_filter_blocks(listing) {
        if block_has_kv_token(block, "handle", handle)
            && block_has_kv_token(block, "pref", &pref_str)
        {
            return true;
        }
    }
    false
}

pub fn filter_has_police_action(
    listing: &str,
    handle: &str,
    pref: u16,
    rate_mbps: Option<u32>,
) -> bool {
    let pref_str = pref.to_string();
    for block in split_filter_blocks(listing) {
        if !(block_has_kv_token(block, "handle", handle)
            && block_has_kv_token(block, "pref", &pref_str)
            && block.contains("police"))
        {
            continue;
        }
        let Some(target_mbps) = rate_mbps else {
            return true;
        };
        if let Some(actual_mbps) = parse_police_rate_mbps(block) {
            let target_f = target_mbps as f64;
            let tol = 0.001_f64.max(target_f * 0.001);
            if (actual_mbps - target_f).abs() <= tol {
                return true;
            }
        }
    }
    false
}

pub fn filter_preference(listing: &str, handle: &str) -> Option<u16> {
    for block in split_filter_blocks(listing) {
        if !block_has_kv_token(block, "handle", handle) {
            continue;
        }
        if let Some(pref) = find_all_prefs_in_text(block).into_iter().next() {
            return Some(pref);
        }
    }
    None
}

pub fn occupied_preferences(listing: &str) -> BTreeSet<u16> {
    find_all_prefs_in_text(listing).into_iter().collect()
}

pub fn next_free_preference(listing: &str, direction: Direction, preferred: Option<u16>) -> u16 {
    let occupied = occupied_preferences(listing);
    let first = preferred
        .filter(|&p| (PREF_RANGE_START..PREF_RANGE_END).contains(&p))
        .unwrap_or_else(|| direction.default_pref());
    if !occupied.contains(&first) {
        return first;
    }
    for candidate in PREF_RANGE_START..PREF_RANGE_END {
        if candidate != first && !occupied.contains(&candidate) {
            return candidate;
        }
    }
    0
}

/// Extract field 22 (`starttime` ticks) from `/proc/<pid>/stat`, tolerating spaces/parens in `comm`.
pub fn parse_proc_start_ticks(raw: &str) -> Result<String, String> {
    let Some(close) = raw.rfind(')') else {
        return Err("malformed proc stat".to_string());
    };
    let after = &raw[close + 1..];
    let Some(value) = after.split_whitespace().nth(19) else {
        return Err("malformed proc stat".to_string());
    };
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid proc start time".to_string());
    }
    Ok(value.to_string())
}

// ---------------------------------------------------------------------------
// 6. Auto-throttle tier state machine (`auto_tier_rates`, `advance_direction`)
// ---------------------------------------------------------------------------

/// Return descending per-container caps (`50%`, `25%`, `5%`), ending at 1 Mbps where possible.
pub fn auto_tier_rates(base_mbps: u32) -> Vec<u32> {
    let mut rates: Vec<u32> = Vec::new();
    for pct in AUTO_TIER_PERCENTAGES {
        let computed = ((base_mbps as u64) * (pct as u64) / 100) as u32;
        let rate = computed.max(AUTO_MINIMUM_MBPS);
        if rate < base_mbps && rates.last().map_or(true, |&prev| rate < prev) {
            rates.push(rate);
        }
    }
    if base_mbps > AUTO_MINIMUM_MBPS && rates.last().map_or(true, |&prev| prev > AUTO_MINIMUM_MBPS)
    {
        rates.push(AUTO_MINIMUM_MBPS);
    }
    rates
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectionThrottleState {
    pub base_mbps: Option<u32>,
    pub stage: usize,
    pub high_seconds: u64,
    pub low_seconds: u64,
    pub last_sample_at: u64,
    pub last_usage_mbps: f64,
}

impl DirectionThrottleState {
    fn from_json(val: &JsonValue) -> Self {
        let Some(obj) = val.as_object() else {
            return Self::default();
        };
        let base_mbps = obj
            .get("base_mbps")
            .and_then(JsonValue::as_i64_lenient)
            .and_then(|v| u32::try_from(v).ok());
        let stage = obj
            .get("stage")
            .and_then(JsonValue::as_i64_lenient)
            .map(|v| v.max(0) as usize)
            .unwrap_or(0);
        let high_seconds = obj
            .get("high_seconds")
            .and_then(JsonValue::as_i64_lenient)
            .map(|v| v.max(0) as u64)
            .unwrap_or(0);
        let low_seconds = obj
            .get("low_seconds")
            .and_then(JsonValue::as_i64_lenient)
            .map(|v| v.max(0) as u64)
            .unwrap_or(0);
        let last_sample_at = obj
            .get("last_sample_at")
            .and_then(JsonValue::as_i64_lenient)
            .map(|v| v.max(0) as u64)
            .unwrap_or(0);
        let last_usage_mbps = obj
            .get("last_usage_mbps")
            .and_then(JsonValue::as_f64)
            .unwrap_or(0.0);
        Self {
            base_mbps,
            stage,
            high_seconds,
            low_seconds,
            last_sample_at,
            last_usage_mbps,
        }
    }

    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        if let Some(base) = self.base_mbps {
            map.insert("base_mbps".to_string(), JsonValue::Number(base.to_string()));
        }
        map.insert("stage".to_string(), JsonValue::Number(self.stage.to_string()));
        map.insert(
            "high_seconds".to_string(),
            JsonValue::Number(self.high_seconds.to_string()),
        );
        map.insert(
            "low_seconds".to_string(),
            JsonValue::Number(self.low_seconds.to_string()),
        );
        map.insert(
            "last_sample_at".to_string(),
            JsonValue::Number(self.last_sample_at.to_string()),
        );
        map.insert(
            "last_usage_mbps".to_string(),
            JsonValue::Number(format_f64_json(self.last_usage_mbps)),
        );
        JsonValue::Object(map)
    }
}

/// Advance one direction's auto-throttle state by `sample_window_seconds` at `sample_at`.
pub fn advance_direction(
    record: &mut DirectionThrottleState,
    base_mbps: u32,
    usage_mbps: f64,
    sample_at: u64,
    sample_window_seconds: u64,
) {
    let tiers = auto_tier_rates(base_mbps);
    if let Some(prev_base) = record.base_mbps {
        if prev_base != base_mbps {
            record.stage = 0;
            record.high_seconds = 0;
            record.low_seconds = 0;
        }
    }
    record.base_mbps = Some(base_mbps);
    if tiers.is_empty() {
        record.stage = 0;
        record.high_seconds = 0;
        record.low_seconds = 0;
        record.last_sample_at = sample_at;
        return;
    }
    let stage = record.stage.min(tiers.len());
    let window = sample_window_seconds.clamp(1, 86_400);
    let current_limit = if stage > 0 {
        tiers[stage - 1]
    } else {
        base_mbps
    };
    let high_threshold = (current_limit as f64) * (AUTO_THRESHOLD_PERCENT as f64) / 100.0;
    let recovery_threshold = (current_limit as f64) * (AUTO_RECOVERY_PERCENT as f64) / 100.0;

    if stage < tiers.len() && usage_mbps >= high_threshold {
        let high_seconds = record.high_seconds.saturating_add(window);
        record.low_seconds = 0;
        if high_seconds >= AUTO_TRIGGER_SECONDS {
            record.stage = stage + 1;
            record.high_seconds = 0;
            record.low_seconds = 0;
        } else {
            record.high_seconds = high_seconds;
        }
    } else if stage > 0 && usage_mbps < recovery_threshold {
        let low_seconds = record.low_seconds.saturating_add(window);
        record.high_seconds = 0;
        if low_seconds >= AUTO_RECOVERY_SECONDS {
            record.stage = stage - 1;
            record.low_seconds = 0;
        } else {
            record.low_seconds = low_seconds;
        }
    } else {
        record.high_seconds = 0;
        record.low_seconds = 0;
    }
    record.last_sample_at = sample_at;
    record.last_usage_mbps = round3(usage_mbps);
}

// ---------------------------------------------------------------------------
// 7. Runner trait & live host implementation
// ---------------------------------------------------------------------------

pub trait TcRunner {
    fn run_cmd(&mut self, args: &[&str], output_limit: usize) -> (i32, String);

    fn which(&mut self, binary: &str) -> Option<String> {
        let _ = binary;
        None
    }

    fn host_ifindex(&mut self, interface: &str) -> Result<u32, String> {
        let _ = interface;
        Err("host interface lookup unavailable".to_string())
    }

    fn netns_inode(&mut self, pid: u32) -> Result<u64, NetnsError> {
        let _ = pid;
        Err(NetnsError::Unavailable(
            "network namespace lookup unavailable".to_string(),
        ))
    }

    fn read_proc_stat(&mut self, pid: u32) -> Result<String, String> {
        let _ = pid;
        Err("proc stat unavailable".to_string())
    }

    fn read_text(&mut self, path: &Path) -> std::io::Result<String> {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ))
    }

    fn list_dir(&mut self, path: &Path) -> std::io::Result<Vec<String>> {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "directory not found",
        ))
    }

    fn read_link_basename(&mut self, path: &Path) -> std::io::Result<String> {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "symlink not found",
        ))
    }

    fn now_unix(&self) -> u64 {
        current_unix_ts()
    }
}

pub fn current_unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Default)]
pub struct LiveRunner;

fn read_bounded_pipe<R: std::io::Read>(mut reader: R, max_bytes: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut limited = reader.by_ref().take(max_bytes as u64);
    let _ = limited.read_to_end(&mut buf);
    buf
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    meta.is_file() && (meta.permissions().mode() & 0o111) != 0
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

impl TcRunner for LiveRunner {
    fn run_cmd(&mut self, args: &[&str], output_limit: usize) -> (i32, String) {
        if args.is_empty() {
            return (127, "command unavailable or timed out".to_string());
        }
        let Ok(mut child) = Command::new(args[0])
            .args(&args[1..])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        else {
            return (127, "command unavailable or timed out".to_string());
        };

        let cap = output_limit.saturating_add(4096);
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let stdout_handle = thread::spawn(move || {
            stdout_pipe
                .map(|r| read_bounded_pipe(r, cap))
                .unwrap_or_default()
        });
        let stderr_handle = thread::spawn(move || {
            stderr_pipe
                .map(|r| read_bounded_pipe(r, cap))
                .unwrap_or_default()
        });

        let deadline = Instant::now() + DEFAULT_CMD_TIMEOUT;
        let mut exit_code: Option<i32> = None;
        let mut timed_out = false;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_code = Some(status.code().unwrap_or(1));
                    break;
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
            }
        }

        let stdout_bytes = stdout_handle.join().unwrap_or_default();
        let stderr_bytes = stderr_handle.join().unwrap_or_default();
        if timed_out {
            return (127, "command unavailable or timed out".to_string());
        }
        let stdout_str = String::from_utf8_lossy(&stdout_bytes).trim().to_string();
        let selected = if !stdout_str.is_empty() {
            stdout_str
        } else {
            String::from_utf8_lossy(&stderr_bytes).trim().to_string()
        };
        (
            exit_code.unwrap_or(127),
            truncate_chars(&selected, output_limit),
        )
    }

    fn which(&mut self, binary: &str) -> Option<String> {
        if binary.is_empty() {
            return None;
        }
        if binary.contains('/') || binary.contains('\\') {
            let p = Path::new(binary);
            if is_executable_file(p) {
                let resolved = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
                return Some(resolved.to_string_lossy().into_owned());
            }
            return None;
        }
        if let Some(paths) = env::var_os("PATH") {
            for dir in env::split_paths(&paths) {
                let candidate = dir.join(binary);
                if is_executable_file(&candidate) {
                    let resolved =
                        fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
                    return Some(resolved.to_string_lossy().into_owned());
                }
            }
        }
        for fallback in ["/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"] {
            let candidate = Path::new(fallback).join(binary);
            if is_executable_file(&candidate) {
                let resolved = fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
                return Some(resolved.to_string_lossy().into_owned());
            }
        }
        None
    }

    fn host_ifindex(&mut self, interface: &str) -> Result<u32, String> {
        if !is_safe_sysfs_iface(interface) {
            return Err("invalid interface name".to_string());
        }
        let sysfs_path = Path::new("/sys/class/net").join(interface).join("ifindex");
        match fs::read_to_string(&sysfs_path) {
            Ok(raw) => {
                let idx = raw
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| "invalid sysfs ifindex".to_string())?;
                if idx > 0 {
                    return Ok(idx);
                }
                return Err("zero sysfs ifindex".to_string());
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // Fall back to ip -j link show only if sysfs tree itself is absent
                if Path::new("/sys/class/net").is_dir() {
                    return Err("interface not found".to_string());
                }
            }
            Err(_) => {}
        }
        let (code, output) = self.run_cmd(
            &["ip", "-j", "link", "show", "dev", interface],
            DEFAULT_OUTPUT_LIMIT,
        );
        if code == 0 {
            if let Ok(JsonVal::Arr(arr)) = JsonVal::parse(&output) {
                if let Some(idx) = arr
                    .first()
                    .and_then(|v| v.get_u64("ifindex"))
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|&v| v > 0)
                {
                    return Ok(idx);
                }
            }
        }
        Err("selected host interface no longer exists".to_string())
    }

    fn netns_inode(&mut self, pid: u32) -> Result<u64, NetnsError> {
        #[cfg(unix)]
        {
            let path = format!("/proc/{pid}/ns/net");
            match fs::metadata(&path) {
                Ok(meta) => Ok(meta.ino()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(NetnsError::NotFound),
                Err(err) => Err(NetnsError::Unavailable(err.to_string())),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            Err(NetnsError::Unavailable(
                "network namespaces require Unix".to_string(),
            ))
        }
    }

    fn read_proc_stat(&mut self, pid: u32) -> Result<String, String> {
        fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| e.to_string())
    }

    fn read_text(&mut self, path: &Path) -> std::io::Result<String> {
        fs::read_to_string(path)
    }

    fn list_dir(&mut self, path: &Path) -> std::io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(path)? {
            if let Ok(item) = entry {
                names.push(item.file_name().to_string_lossy().into_owned());
            }
        }
        Ok(names)
    }

    fn read_link_basename(&mut self, path: &Path) -> std::io::Result<String> {
        let target = fs::read_link(path)?;
        target
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no basename"))
    }
}

// ---------------------------------------------------------------------------
// 8. Input models & runtime / network verification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInput {
    pub runtime: String,
    pub runtime_bin: String,
    pub project: String,
    pub name: String,
    pub id: String,
    pub instance_id: String,
    pub status: String,
    pub pid: Option<u32>,
}

impl From<&ContainerSample> for ContainerInput {
    fn from(c: &ContainerSample) -> Self {
        Self {
            runtime: c.runtime.clone(),
            runtime_bin: c.runtime_bin.clone(),
            project: c.project.clone(),
            name: c.name.clone(),
            id: c.id.clone(),
            instance_id: c.instance_id.clone(),
            status: c.status.clone(),
            pid: c.pid,
        }
    }
}

impl ContainerInput {
    fn identity(&self) -> (String, String, String, String) {
        let cid = if self.runtime == "runman" {
            self.instance_id.clone()
        } else if !self.id.is_empty() {
            self.id.clone()
        } else {
            String::new()
        };
        (
            self.runtime.clone(),
            self.project.clone(),
            self.name.clone(),
            cid,
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TrafficSampleInput {
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub container_id: String,
    pub traffic_counters_available: bool,
    pub net_tx_bps: Option<f64>,
    pub net_rx_bps: Option<f64>,
}

impl TrafficSampleInput {
    fn identity(&self) -> (String, String, String, String) {
        (
            self.runtime.clone(),
            self.project.clone(),
            self.container_name.clone(),
            self.container_id.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeInterfaceInput {
    pub name: String,
    pub kind: String,
    pub runtimes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerEntry {
    pub runtime: String,
    pub project: String,
    pub container_id: String,
    pub pid: u32,
}

fn parse_csv(raw: &str) -> Vec<Vec<String>> {
    if raw.is_empty() {
        return Vec::new();
    }
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut at_start = true;
    let mut chars = raw.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    let _ = chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(ch);
            }
            continue;
        }
        match ch {
            '"' if at_start => {
                in_quotes = true;
                at_start = false;
            }
            ',' => {
                row.push(std::mem::take(&mut field));
                at_start = true;
            }
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    let _ = chars.next();
                }
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                at_start = true;
            }
            '\n' => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                at_start = true;
            }
            other => {
                field.push(other);
                at_start = false;
            }
        }
    }
    if !at_start || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// Read all running runtime peers (`incus`, `podman`, `runman`), including unmonitored peers.
pub fn running_container_inventory<R: TcRunner>(
    containers: &[ContainerInput],
    runner: &mut R,
) -> Result<Vec<PeerEntry>, BandwidthError> {
    let mut incus_bins: BTreeSet<String> = BTreeSet::new();
    let mut podman_bins: BTreeSet<String> = BTreeSet::new();

    for candidate in containers {
        if candidate.runtime != "incus" && candidate.runtime != "podman" {
            continue;
        }
        let binary = if candidate.runtime_bin.is_empty() {
            candidate.runtime.as_str()
        } else {
            candidate.runtime_bin.as_str()
        };
        if !is_valid_runtime_bin(binary) {
            return Err(BandwidthError::policy(
                "container runtime executable could not be verified",
            ));
        }
        let Some(resolved) = runner.which(binary) else {
            return Err(BandwidthError::policy(
                "container runtime inventory executable is unavailable",
            ));
        };
        if candidate.runtime == "incus" {
            incus_bins.insert(resolved);
        } else {
            podman_bins.insert(resolved);
        }
    }

    if let Some(resolved) = runner.which("incus") {
        incus_bins.insert(resolved);
    }
    if let Some(resolved) = runner.which("podman") {
        podman_bins.insert(resolved);
    }
    if podman_bins.is_empty() {
        if let Some(resolved) = runner.which("podman-remote") {
            podman_bins.insert(resolved);
        }
    }

    let mut peers: BTreeSet<PeerEntry> = BTreeSet::new();
    for item in containers {
        if item.runtime != "runman" || item.status != "running" {
            continue;
        }
        let pid = item.pid.unwrap_or(0);
        if !is_valid_uuid(&item.instance_id) || pid <= 1 {
            return Err(BandwidthError::policy(
                "running Runman inventory is incomplete; network isolation cannot be verified",
            ));
        }
        let project = if item.project.is_empty() {
            "default".to_string()
        } else {
            item.project.clone()
        };
        peers.insert(PeerEntry {
            runtime: "runman".to_string(),
            project,
            container_id: item.instance_id.to_ascii_lowercase(),
            pid,
        });
    }

    for binary in incus_bins {
        let (code, output) = runner.run_cmd(
            &[
                binary.as_str(),
                "list",
                "--all-projects",
                "type=container",
                "status=running",
                "--format=csv",
                "--columns=nepst",
            ],
            MAX_INVENTORY_OUTPUT + 1,
        );
        if code != 0 || output.len() > MAX_INVENTORY_OUTPUT {
            return Err(BandwidthError::policy(
                "all-running Incus inventory is unavailable",
            ));
        }
        let rows = parse_csv(&output);
        if rows.len() > MAX_INVENTORY_ITEMS {
            return Err(BandwidthError::policy(
                "all-running Incus inventory could not be verified",
            ));
        }
        for row in rows {
            if row.len() != 5 {
                return Err(BandwidthError::policy(
                    "all-running Incus inventory could not be verified",
                ));
            }
            let name = row[0].as_str();
            let project = if row[1].is_empty() {
                "default"
            } else {
                row[1].as_str()
            };
            let pid_text = row[2].as_str();
            let status = row[3].as_str();
            let instance_type = row[4].as_str();
            let pid = pid_text.parse::<u32>().unwrap_or(0);
            if !status.eq_ignore_ascii_case("RUNNING")
                || !instance_type.eq_ignore_ascii_case("CONTAINER")
                || name.is_empty()
                || pid <= 1
            {
                return Err(BandwidthError::policy(
                    "all-running Incus inventory could not be verified",
                ));
            }
            peers.insert(PeerEntry {
                runtime: "incus".to_string(),
                project: project.to_string(),
                container_id: name.to_string(),
                pid,
            });
        }
    }

    for binary in podman_bins {
        let (code, output) = runner.run_cmd(
            &[binary.as_str(), "ps", "--no-trunc", "--format", "{{.ID}}"],
            MAX_INVENTORY_OUTPUT + 1,
        );
        if code != 0 || output.len() > MAX_INVENTORY_OUTPUT {
            return Err(BandwidthError::policy(
                "all-running Podman inventory is unavailable",
            ));
        }
        let ids: Vec<&str> = if output.is_empty() {
            Vec::new()
        } else {
            output.split('\n').map(|s| s.trim_end_matches('\r')).collect()
        };
        if ids.len() > MAX_INVENTORY_ITEMS || ids.iter().any(|id| !is_valid_hex64_lower(id)) {
            return Err(BandwidthError::policy(
                "all-running Podman inventory could not be verified",
            ));
        }
        if ids.is_empty() {
            continue;
        }
        let mut args: Vec<&str> = Vec::with_capacity(4 + ids.len());
        args.extend([binary.as_str(), "inspect", "--format", "{{.Id}}|{{.State.Pid}}"]);
        args.extend(ids.iter().copied());
        let (code, inspect_out) = runner.run_cmd(&args, MAX_INVENTORY_OUTPUT + 1);
        let rows: Vec<&str> = if inspect_out.is_empty() {
            Vec::new()
        } else {
            inspect_out
                .split('\n')
                .map(|s| s.trim_end_matches('\r'))
                .collect()
        };
        if code != 0 || inspect_out.len() > MAX_INVENTORY_OUTPUT || rows.len() != ids.len() {
            return Err(BandwidthError::policy(
                "all-running Podman process inventory is unavailable",
            ));
        }
        let id_set: HashSet<&str> = ids.iter().copied().collect();
        let mut found_ids: HashSet<&str> = HashSet::with_capacity(ids.len());
        for row in rows {
            let Some((cid, pid_str)) = row.split_once('|') else {
                return Err(BandwidthError::policy(
                    "all-running Podman process inventory could not be verified",
                ));
            };
            if pid_str.contains('|') {
                return Err(BandwidthError::policy(
                    "all-running Podman process inventory could not be verified",
                ));
            }
            let pid = pid_str.parse::<u32>().unwrap_or(0);
            if !id_set.contains(cid) || !found_ids.insert(cid) || pid <= 1 {
                return Err(BandwidthError::policy(
                    "all-running Podman process inventory could not be verified",
                ));
            }
            peers.insert(PeerEntry {
                runtime: "podman".to_string(),
                project: String::new(),
                container_id: cid.to_string(),
                pid,
            });
        }
    }

    Ok(peers.into_iter().collect())
}

pub fn container_process_pid<R: TcRunner>(
    item: &NormalizedLimit,
    matched: &ContainerInput,
    runner: &mut R,
) -> Result<u32, BandwidthError> {
    let mut pid = matched.pid.unwrap_or(0);
    if item.runtime == "podman" && pid <= 1 {
        let runtime_bin = if matched.runtime_bin.is_empty() {
            "podman"
        } else {
            matched.runtime_bin.as_str()
        };
        if !is_valid_runtime_bin(runtime_bin) {
            return Err(BandwidthError::policy(
                "Podman runtime executable could not be verified",
            ));
        }
        let (code, output) = runner.run_cmd(
            &[
                runtime_bin,
                "inspect",
                "--format",
                "{{.Id}}|{{.State.Pid}}",
                item.container_name.as_str(),
            ],
            DEFAULT_OUTPUT_LIMIT,
        );
        let fields = output.split_once('|');
        let valid = match fields {
            Some((cid, _)) => code == 0 && cid.starts_with(&item.container_id),
            None => false,
        };
        if !valid {
            return Err(BandwidthError::policy(
                "Podman container ID or state could not be verified",
            ));
        }
        pid = fields
            .and_then(|(_, p)| p.parse::<u32>().ok())
            .unwrap_or(0);
    }
    if pid <= 1 {
        return Err(BandwidthError::policy(
            "container is not running or its init PID is unavailable",
        ));
    }
    Ok(pid)
}

pub fn verify_container_namespace<R: TcRunner>(
    item: &NormalizedLimit,
    pid: u32,
    namespace_inode: &str,
    containers: &[ContainerInput],
    peer_inventory: Option<&[PeerEntry]>,
    runner: &mut R,
) -> Result<(), BandwidthError> {
    let host_ns = runner.netns_inode(1).map_err(|_| {
        BandwidthError::policy(
            "host network namespace is unavailable; container isolation cannot be verified",
        )
    })?;
    if namespace_inode == host_ns.to_string() {
        return Err(BandwidthError::policy(
            "single-container limiting cannot target the host network namespace",
        ));
    }
    let owned_peers;
    let peers = match peer_inventory {
        Some(p) => p,
        None => {
            owned_peers = running_container_inventory(containers, runner)?;
            &owned_peers
        }
    };

    let mut target_found = false;
    for peer in peers {
        let is_target = peer.runtime == item.runtime
            && peer.project == item.project
            && if peer.runtime == "incus" || peer.runtime == "runman" {
                peer.container_id == item.container_id
            } else {
                peer.container_id.starts_with(&item.container_id)
            };
        if is_target && peer.pid != pid {
            return Err(BandwidthError::policy(
                "container process changed during isolation verification",
            ));
        }
        let peer_ns = runner
            .netns_inode(peer.pid)
            .map_err(|_| {
                BandwidthError::policy(
                    "running container peer namespace is unavailable; isolation cannot be verified",
                )
            })?
            .to_string();
        if is_target {
            target_found = true;
            if peer_ns != namespace_inode {
                return Err(BandwidthError::policy(
                    "container network namespace changed during verification",
                ));
            }
        } else if peer_ns == namespace_inode {
            return Err(BandwidthError::policy(
                "single-container limiting cannot target a shared container network namespace",
            ));
        }
    }
    if !target_found {
        return Err(BandwidthError::policy(
            "container is absent from the verified all-running runtime inventory",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub key: String,
    pub owner_key: String,
    pub scope: Scope,
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub container_id: String,
    pub prefix: Vec<String>,
    pub pid: u32,
    pub process_generation: String,
    pub interface: String,
    pub interface_index: u32,
    pub peer_index: u32,
    pub namespace_inode: String,
}

fn call_with_prefix<R: TcRunner>(
    runner: &mut R,
    prefix: &[String],
    args: &[&str],
) -> (i32, String) {
    let mut full: Vec<&str> = Vec::with_capacity(prefix.len() + args.len());
    for p in prefix {
        full.push(p.as_str());
    }
    full.extend_from_slice(args);
    runner.run_cmd(&full, DEFAULT_OUTPUT_LIMIT)
}

fn parse_first_default_route_dev(json_str: &str) -> Option<String> {
    let JsonVal::Arr(routes) = JsonVal::parse(json_str).ok()? else {
        return None;
    };
    for route in routes {
        if let Some(dev) = route.get_str("dev") {
            if is_valid_iface_name(dev) {
                return Some(dev.to_string());
            }
        }
    }
    None
}

fn parse_link_indices(json_str: &str) -> Option<(u32, u32)> {
    let JsonVal::Arr(links) = JsonVal::parse(json_str).ok()? else {
        return None;
    };
    let first = links.first()?;
    let ifindex = first
        .get_u64("ifindex")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    let peer_index = first
        .get_u64("link_index")
        .or_else(|| first.get_u64("iflink"))
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    Some((ifindex, peer_index))
}

pub fn resolve_entry<R: TcRunner>(
    host_id: &str,
    item: &NormalizedLimit,
    containers: &[ContainerInput],
    peer_inventory: Option<&[PeerEntry]>,
    runner: &mut R,
) -> Result<ResolvedTarget, BandwidthError> {
    if item.scope == Scope::Host {
        let iface = &item.interface;
        let interface_index = runner
            .host_ifindex(iface)
            .map_err(|_| BandwidthError::policy("selected host interface no longer exists"))?;
        let key = format!("host:{iface}");
        return Ok(ResolvedTarget {
            owner_key: format!("{host_id}:{key}"),
            key,
            scope: Scope::Host,
            runtime: String::new(),
            project: String::new(),
            container_name: String::new(),
            container_id: String::new(),
            prefix: Vec::new(),
            pid: 0,
            process_generation: String::new(),
            interface: iface.clone(),
            interface_index,
            peer_index: 0,
            namespace_inode: "host".to_string(),
        });
    }

    let matched = containers
        .iter()
        .find(|c| {
            let cid = if item.runtime == "runman" {
                c.instance_id.as_str()
            } else {
                c.id.as_str()
            };
            c.runtime == item.runtime
                && c.project == item.project
                && c.name == item.container_name
                && cid == item.container_id
        })
        .ok_or_else(|| {
            BandwidthError::policy("container identity is not present in the current runtime inventory")
        })?;

    let pid = container_process_pid(item, matched, runner)?;
    let ns_inode = runner
        .netns_inode(pid)
        .map_err(|_| BandwidthError::policy("container process identity could not be verified"))?
        .to_string();
    let raw_stat = runner
        .read_proc_stat(pid)
        .map_err(|_| BandwidthError::policy("container process identity could not be verified"))?;
    let start_ticks = parse_proc_start_ticks(&raw_stat)
        .map_err(|_| BandwidthError::policy("container process identity could not be verified"))?;

    verify_container_namespace(item, pid, &ns_inode, containers, peer_inventory, runner)?;

    let prefix = vec![
        "nsenter".to_string(),
        "--target".to_string(),
        pid.to_string(),
        "--net".to_string(),
    ];
    let (code, route_out) =
        call_with_prefix(runner, &prefix, &["ip", "-j", "route", "show", "default"]);
    if code != 0 {
        return Err(BandwidthError::policy(
            "container default network interface is unavailable",
        ));
    }
    let interface = parse_first_default_route_dev(&route_out).ok_or_else(|| {
        BandwidthError::policy("container has no verified default route interface")
    })?;

    let (code, link_out) =
        call_with_prefix(runner, &prefix, &["ip", "-j", "link", "show", "dev", &interface]);
    if code != 0 {
        return Err(BandwidthError::policy(
            "container interface disappeared during verification",
        ));
    }
    let (interface_index, peer_index) = parse_link_indices(&link_out).unwrap_or((0, 0));
    if interface_index == 0 {
        return Err(BandwidthError::policy(
            "container interface index could not be verified",
        ));
    }

    let key = item.key();
    Ok(ResolvedTarget {
        owner_key: format!("{host_id}:{key}"),
        key,
        scope: Scope::Container,
        runtime: item.runtime.clone(),
        project: item.project.clone(),
        container_name: item.container_name.clone(),
        container_id: item.container_id.clone(),
        prefix,
        pid,
        process_generation: start_ticks,
        interface,
        interface_index,
        peer_index,
        namespace_inode: ns_inode,
    })
}

// ---------------------------------------------------------------------------
// 9. tc qdisc / filter application, removal, & rollback
// ---------------------------------------------------------------------------

pub fn ensure_clsact<R: TcRunner>(
    prefix: &[String],
    interface: &str,
    runner: &mut R,
) -> Result<(), BandwidthError> {
    let (code, listing) =
        call_with_prefix(runner, prefix, &["tc", "qdisc", "show", "dev", interface]);
    if code == 0 && contains_word(&listing, "clsact") {
        return Ok(());
    }
    let (add_code, message) =
        call_with_prefix(runner, prefix, &["tc", "qdisc", "add", "dev", interface, "clsact"]);
    if add_code != 0 {
        let (re_code, re_listing) =
            call_with_prefix(runner, prefix, &["tc", "qdisc", "show", "dev", interface]);
        if re_code != 0 || !contains_word(&re_listing, "clsact") {
            let reason = if message.is_empty() {
                "tc failed"
            } else {
                message.as_str()
            };
            return Err(BandwidthError::policy(format!(
                "cannot add an agent-managed clsact qdisc: {}",
                truncate_chars(reason, 240)
            )));
        }
    }
    Ok(())
}

fn filter_listing<R: TcRunner>(
    prefix: &[String],
    interface: &str,
    direction: Direction,
    runner: &mut R,
) -> Result<String, BandwidthError> {
    let (code, listing) = call_with_prefix(
        runner,
        prefix,
        &[
            "tc",
            "filter",
            "show",
            "dev",
            interface,
            direction.tc_direction(),
        ],
    );
    if code != 0 {
        return Err(BandwidthError::policy(
            "cannot verify existing filters on interface",
        ));
    }
    Ok(listing)
}

pub fn apply_filter<R: TcRunner>(
    prefix: &[String],
    interface: &str,
    owner_key: &str,
    direction: Direction,
    rate_mbps: u32,
    previously_owned: bool,
    preferred_pref: Option<u16>,
    runner: &mut R,
) -> Result<u16, BandwidthError> {
    let handle = filter_handle(owner_key, direction);
    ensure_clsact(prefix, interface, runner)?;
    let mut listing = filter_listing(prefix, interface, direction, runner)?;
    let owned_pref = filter_preference(&listing, &handle);
    if owned_pref.is_some() && !previously_owned {
        return Err(BandwidthError::policy(
            "reserved filter identity already exists; left unchanged",
        ));
    }
    let mut pref = owned_pref.unwrap_or_else(|| {
        next_free_preference(
            &listing,
            direction,
            Some(preferred_pref.unwrap_or_else(|| direction.default_pref())),
        )
    });
    if pref == 0 {
        return Err(BandwidthError::policy(
            "no free tc filter priority is available on this interface",
        ));
    }

    for _attempt in 0..5 {
        let replacing_owned = previously_owned && owned_pref == Some(pref);
        let verb = if replacing_owned { "change" } else { "add" };
        let cmd = build_tc_filter_command(
            prefix,
            interface,
            direction,
            verb,
            pref,
            &handle,
            rate_mbps,
        );
        let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
        let (code, message) = runner.run_cmd(&refs, DEFAULT_OUTPUT_LIMIT);
        if code == 0 {
            let verified = filter_listing(prefix, interface, direction, runner)?;
            if !filter_has_police_action(&verified, &handle, pref, Some(rate_mbps)) {
                return Err(BandwidthError::policy(format!(
                    "bandwidth policer readback did not confirm {rate_mbps} Mbps at priority {pref}"
                )));
            }
            return Ok(pref);
        }
        let msg_lower = message.to_ascii_lowercase();
        if replacing_owned && msg_lower.contains("file exists") {
            let verified = filter_listing(prefix, interface, direction, runner)?;
            if filter_has_police_action(&verified, &handle, pref, Some(rate_mbps)) {
                return Ok(pref);
            }
            let detail = if message.is_empty() {
                "tc failed"
            } else {
                message.as_str()
            };
            return Err(BandwidthError::policy(format!(
                "owned bandwidth filter change failed at priority {pref}; readback did not confirm {rate_mbps} Mbps: {}",
                truncate_chars(detail, 180)
            )));
        }
        if verb == "add" && msg_lower.contains("file exists") {
            listing = filter_listing(prefix, interface, direction, runner)?;
            if filter_preference(&listing, &handle).is_some() {
                return Err(BandwidthError::policy(
                    "filter identity appeared during apply; left unchanged",
                ));
            }
            let next_preferred = if pref < PREF_RANGE_END {
                Some(pref + 1)
            } else {
                None
            };
            pref = next_free_preference(&listing, direction, next_preferred);
            if pref != 0 {
                continue;
            }
            return Err(BandwidthError::policy(
                "no free tc filter priority is available on this interface",
            ));
        }
        let detail = if message.is_empty() {
            "tc failed"
        } else {
            message.as_str()
        };
        return Err(BandwidthError::policy(format!(
            "bandwidth policer was not confirmed (tc filter {verb}, priority {pref}, {}): {}",
            direction.as_str(),
            truncate_chars(detail, 200)
        )));
    }

    Err(BandwidthError::policy(
        "tc filter priorities kept colliding; no foreign filter was changed",
    ))
}

pub fn remove_filter<R: TcRunner>(
    prefix: &[String],
    interface: &str,
    owner_key: &str,
    direction: Direction,
    preferred_pref: Option<u16>,
    runner: &mut R,
) -> Result<bool, BandwidthError> {
    let handle = filter_handle(owner_key, direction);
    let listing = filter_listing(prefix, interface, direction, runner)?;
    let pref = preferred_pref
        .filter(|&p| filter_present(&listing, &handle, p))
        .or_else(|| filter_preference(&listing, &handle));
    let Some(pref) = pref else {
        return Ok(false);
    };
    let cmd = build_tc_filter_del_command(prefix, interface, direction, pref, &handle);
    let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
    let (code, message) = runner.run_cmd(&refs, DEFAULT_OUTPUT_LIMIT);
    if code != 0 {
        let detail = if message.is_empty() {
            "tc failed"
        } else {
            message.as_str()
        };
        return Err(BandwidthError::policy(format!(
            "owned bandwidth filter could not be removed: {}",
            truncate_chars(detail, 240)
        )));
    }
    let after = filter_listing(prefix, interface, direction, runner)?;
    if filter_present(&after, &handle, pref) {
        return Err(BandwidthError::policy(
            "owned bandwidth filter remains after removal",
        ));
    }
    Ok(true)
}

#[derive(Debug, Clone)]
struct RollbackOperation {
    prefix: Vec<String>,
    interface: String,
    owner_key: String,
    direction: Direction,
    previously_owned: bool,
    previous_rate_mbps: Option<u32>,
    previous_pref: Option<u16>,
}

fn rollback_bandwidth_mutation<R: TcRunner>(
    op: &RollbackOperation,
    runner: &mut R,
) -> Result<(), BandwidthError> {
    if op.previously_owned {
        let rate = op.previous_rate_mbps.unwrap_or(0);
        if rate == 0 {
            return Err(BandwidthError::policy(
                "previous owned tc rate is unavailable; rollback cannot be verified",
            ));
        }
        apply_filter(
            &op.prefix,
            &op.interface,
            &op.owner_key,
            op.direction,
            rate,
            true,
            op.previous_pref,
            runner,
        )?;
        return Ok(());
    }
    let _ = remove_filter(
        &op.prefix,
        &op.interface,
        &op.owner_key,
        op.direction,
        None,
        runner,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 10. Host link discovery & auto-throttle engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct HostLinkInfo {
    ifname: String,
    master_name: String,
    master_index: Option<u32>,
}

fn sysfs_host_links<R: TcRunner>(runner: &mut R) -> (BTreeMap<u32, HostLinkInfo>, String) {
    let root = Path::new("/sys/class/net");
    let names = match runner.list_dir(root) {
        Ok(list) => list,
        Err(err) => return (BTreeMap::new(), format!("cannot read /sys/class/net: {err}")),
    };
    let mut links = BTreeMap::new();
    for name in names.into_iter().take(512) {
        if !is_safe_sysfs_iface(&name) {
            continue;
        }
        let base = root.join(&name);
        let Ok(idx_raw) = runner.read_text(&base.join("ifindex")) else {
            continue;
        };
        let Ok(index) = idx_raw.trim().parse::<u32>() else {
            continue;
        };
        if index == 0 {
            continue;
        }
        let master_name = runner
            .read_link_basename(&base.join("master"))
            .unwrap_or_default();
        links.insert(
            index,
            HostLinkInfo {
                ifname: name,
                master_name,
                master_index: None,
            },
        );
    }
    let err = if links.is_empty() {
        "/sys/class/net contained no readable interfaces".to_string()
    } else {
        String::new()
    };
    (links, err)
}

fn proc_default_routes<R: TcRunner>(runner: &mut R) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    if let Ok(raw) = runner.read_text(Path::new("/proc/net/route")) {
        for line in raw.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 4 && fields[1] == "00000000" {
                let flags = u32::from_str_radix(fields[3], 16).unwrap_or(0);
                if (flags & 0x1) != 0 && is_valid_iface_name(fields[0]) {
                    result.insert(fields[0].to_string());
                }
            }
        }
    }
    if let Ok(raw) = runner.read_text(Path::new("/proc/net/ipv6_route")) {
        for line in raw.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 10
                && !fields[0].is_empty()
                && fields[0].bytes().all(|b| b == b'0')
                && fields[1] == "00"
                && is_valid_iface_name(fields[9])
            {
                result.insert(fields[9].to_string());
            }
        }
    }
    result
}

fn parse_host_links_array(val: &JsonVal) -> Option<BTreeMap<u32, HostLinkInfo>> {
    let JsonVal::Arr(arr) = val else {
        return None;
    };
    if arr.is_empty() {
        return None;
    }
    let mut map = BTreeMap::new();
    for item in arr.iter().take(512) {
        let Some(index) = item
            .get_u64("ifindex")
            .and_then(|v| u32::try_from(v).ok())
            .filter(|&i| i > 0)
        else {
            continue;
        };
        let ifname = item.get_str("ifname").unwrap_or("");
        if !is_valid_iface_name(ifname) {
            continue;
        }
        let (master_name, master_index) = match item.get("master") {
            Some(JsonVal::Str(s)) => (s.clone(), None),
            Some(JsonVal::Num(_)) => (
                String::new(),
                item.get_u64("master").and_then(|v| u32::try_from(v).ok()),
            ),
            _ => (String::new(), None),
        };
        map.insert(
            index,
            HostLinkInfo {
                ifname: ifname.to_string(),
                master_name,
                master_index,
            },
        );
    }
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

fn host_link_snapshot<R: TcRunner>(
    runner: &mut R,
) -> (BTreeMap<u32, HostLinkInfo>, BTreeSet<String>, String) {
    let (code, output) = runner.run_cmd(&["ip", "-j", "link", "show"], DEFAULT_OUTPUT_LIMIT);
    let mut link_error = if code != 0 {
        format!("ip -j link show failed ({code}): {output}")
    } else {
        String::new()
    };
    let mut links = match JsonVal::parse(&output) {
        Ok(val) => parse_host_links_array(&val),
        Err(_) => {
            link_error = "ip -j link show returned invalid JSON".to_string();
            None
        }
    };

    if links.is_none() {
        let (fb_code, fb_output) =
            runner.run_cmd(&["ip", "-j", "address", "show"], DEFAULT_OUTPUT_LIMIT);
        let fb_parsed = if fb_code == 0 {
            JsonVal::parse(&fb_output)
                .ok()
                .and_then(|v| parse_host_links_array(&v))
        } else {
            None
        };
        if let Some(parsed) = fb_parsed {
            links = Some(parsed);
            link_error.clear();
        } else {
            link_error.push_str(&format!(
                "; ip -j address show failed ({fb_code}): {fb_output}"
            ));
        }
    }

    let return_links = if let Some(parsed) = links {
        parsed
    } else {
        let (sys_links, sys_err) = sysfs_host_links(runner);
        if sys_links.is_empty() {
            return (
                BTreeMap::new(),
                BTreeSet::new(),
                truncate_chars(&format!("{link_error}; {sys_err}"), 500),
            );
        }
        link_error.clear();
        sys_links
    };
    let _ = link_error;

    let (r_code, r_output) =
        runner.run_cmd(&["ip", "-j", "route", "show", "default"], DEFAULT_OUTPUT_LIMIT);
    let mut defaults = BTreeSet::new();
    if r_code == 0 {
        if let Ok(JsonVal::Arr(routes)) = JsonVal::parse(&r_output) {
            for route in routes {
                if let Some(dev) = route.get_str("dev") {
                    if is_valid_iface_name(dev) {
                        defaults.insert(dev.to_string());
                    }
                }
            }
        }
    }
    let mut route_error = if r_code != 0 {
        format!("ip -j route show default failed ({r_code}): {r_output}")
    } else {
        String::new()
    };
    if defaults.is_empty() {
        defaults.extend(proc_default_routes(runner));
        if !defaults.is_empty() {
            route_error.clear();
        }
    }
    (return_links, defaults, truncate_chars(&route_error, 500))
}

fn uses_selected_host_interface(
    selected: &str,
    peer_index: u32,
    host_links: &BTreeMap<u32, HostLinkInfo>,
    default_routes: &BTreeSet<String>,
    bridge_inventory: &[BridgeInterfaceInput],
) -> bool {
    if peer_index == 0 {
        return false;
    }
    let Some(peer) = host_links.get(&peer_index) else {
        return false;
    };
    let master_name = if let Some(midx) = peer.master_index {
        host_links
            .get(&midx)
            .map(|l| l.ifname.as_str())
            .unwrap_or("")
    } else {
        peer.master_name.as_str()
    };
    if peer.ifname == selected || master_name == selected {
        return true;
    }
    if !default_routes.contains(selected) || master_name.is_empty() {
        return false;
    }
    bridge_inventory.iter().any(|item| {
        item.kind == "bridge"
            && item.name == master_name
            && item
                .runtimes
                .iter()
                .any(|rt| RuntimeKind::parse(rt).is_some())
    })
}

fn finite_rate(val: Option<f64>) -> Option<f64> {
    val.filter(|&r| r.is_finite() && (0.0..1e15).contains(&r))
}

#[derive(Debug, Clone, Default)]
pub struct TrackedContainerState {
    pub identity: [String; 4],
    pub process_generation: String,
    pub namespace_inode: String,
    pub interface_index: u32,
    pub network_interface: String,
    pub state: String,
    pub sampling_state: String,
    pub message: String,
    pub last_sample_at: u64,
    pub directions: BTreeMap<String, DirectionThrottleState>,
}

impl TrackedContainerState {
    fn from_json(val: &JsonValue) -> Option<Self> {
        let obj = val.as_object()?;
        let id_arr = obj.get("identity").and_then(JsonValue::as_array)?;
        if id_arr.len() != 4 {
            return None;
        }
        let identity = [
            id_arr[0].as_str().unwrap_or("").to_string(),
            id_arr[1].as_str().unwrap_or("").to_string(),
            id_arr[2].as_str().unwrap_or("").to_string(),
            id_arr[3].as_str().unwrap_or("").to_string(),
        ];
        let mut directions = BTreeMap::new();
        if let Some(dir_obj) = obj.get("directions").and_then(JsonValue::as_object) {
            for (k, v) in dir_obj {
                if v.as_object().map_or(false, |m| !m.is_empty()) {
                    directions.insert(k.clone(), DirectionThrottleState::from_json(v));
                }
            }
        }
        Some(Self {
            identity,
            process_generation: obj
                .get("process_generation")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            namespace_inode: obj
                .get("namespace_inode")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            interface_index: obj
                .get("interface_index")
                .and_then(JsonValue::as_i64_lenient)
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0),
            network_interface: obj
                .get("network_interface")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            state: obj
                .get("state")
                .and_then(JsonValue::as_str)
                .unwrap_or("monitoring")
                .to_string(),
            sampling_state: obj
                .get("sampling_state")
                .and_then(JsonValue::as_str)
                .unwrap_or("unknown")
                .to_string(),
            message: obj
                .get("message")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            last_sample_at: obj
                .get("last_sample_at")
                .and_then(JsonValue::as_i64_lenient)
                .map(|v| v.max(0) as u64)
                .unwrap_or(0),
            directions,
        })
    }

    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "identity".to_string(),
            JsonValue::Array(
                self.identity
                    .iter()
                    .map(|s| JsonValue::String(s.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "process_generation".to_string(),
            JsonValue::String(self.process_generation.clone()),
        );
        map.insert(
            "namespace_inode".to_string(),
            JsonValue::String(self.namespace_inode.clone()),
        );
        map.insert(
            "interface_index".to_string(),
            JsonValue::Number(self.interface_index.to_string()),
        );
        map.insert(
            "network_interface".to_string(),
            JsonValue::String(self.network_interface.clone()),
        );
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        map.insert(
            "sampling_state".to_string(),
            JsonValue::String(self.sampling_state.clone()),
        );
        if !self.message.is_empty() {
            map.insert(
                "message".to_string(),
                JsonValue::String(self.message.clone()),
            );
        }
        map.insert(
            "last_sample_at".to_string(),
            JsonValue::Number(self.last_sample_at.to_string()),
        );
        let mut dirs = BTreeMap::new();
        for (k, v) in &self.directions {
            dirs.insert(k.clone(), v.to_json_val());
        }
        map.insert("directions".to_string(), JsonValue::Object(dirs));
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, Default)]
pub struct AutoThrottlePersistedState {
    pub interface: String,
    pub last_sample_at: u64,
    pub status: String,
    pub mapped_containers: usize,
    pub unmapped_containers: usize,
    pub unavailable_samples: usize,
    pub mapping_reason: String,
    pub mapping_error: String,
    pub containers: BTreeMap<String, TrackedContainerState>,
}

impl AutoThrottlePersistedState {
    fn from_json(val: &JsonValue) -> Option<Self> {
        let obj = val.as_object()?;
        let mut containers = BTreeMap::new();
        if let Some(c_obj) = obj.get("containers").and_then(JsonValue::as_object) {
            for (k, v) in c_obj {
                if let Some(tc) = TrackedContainerState::from_json(v) {
                    containers.insert(k.clone(), tc);
                }
            }
        }
        Some(Self {
            interface: obj
                .get("interface")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            last_sample_at: obj
                .get("last_sample_at")
                .and_then(JsonValue::as_i64_lenient)
                .map(|v| v.max(0) as u64)
                .unwrap_or(0),
            status: obj
                .get("status")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            mapped_containers: obj
                .get("mapped_containers")
                .and_then(JsonValue::as_i64_lenient)
                .map(|v| v.max(0) as usize)
                .unwrap_or(0),
            unmapped_containers: obj
                .get("unmapped_containers")
                .and_then(JsonValue::as_i64_lenient)
                .map(|v| v.max(0) as usize)
                .unwrap_or(0),
            unavailable_samples: obj
                .get("unavailable_samples")
                .and_then(JsonValue::as_i64_lenient)
                .map(|v| v.max(0) as usize)
                .unwrap_or(0),
            mapping_reason: obj
                .get("mapping_reason")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            mapping_error: obj
                .get("mapping_error")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            containers,
        })
    }

    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "interface".to_string(),
            JsonValue::String(self.interface.clone()),
        );
        map.insert(
            "last_sample_at".to_string(),
            JsonValue::Number(self.last_sample_at.to_string()),
        );
        if !self.status.is_empty() {
            map.insert("status".to_string(), JsonValue::String(self.status.clone()));
        }
        map.insert(
            "mapped_containers".to_string(),
            JsonValue::Number(self.mapped_containers.to_string()),
        );
        map.insert(
            "unmapped_containers".to_string(),
            JsonValue::Number(self.unmapped_containers.to_string()),
        );
        map.insert(
            "unavailable_samples".to_string(),
            JsonValue::Number(self.unavailable_samples.to_string()),
        );
        map.insert(
            "mapping_reason".to_string(),
            JsonValue::String(self.mapping_reason.clone()),
        );
        map.insert(
            "mapping_error".to_string(),
            JsonValue::String(self.mapping_error.clone()),
        );
        let mut c_map = BTreeMap::new();
        for (k, v) in &self.containers {
            c_map.insert(k.clone(), v.to_json_val());
        }
        map.insert("containers".to_string(), JsonValue::Object(c_map));
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AutoThrottleStatusItem {
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub container_id: String,
    pub state: String,
    pub sampling_state: String,
    pub network_interface: String,
    pub upload_mbps: u32,
    pub download_mbps: u32,
    pub upload_current_mbps: f64,
    pub download_current_mbps: f64,
    pub upload_baseline_mbps: u32,
    pub download_baseline_mbps: u32,
    pub upload_high_seconds: u64,
    pub download_high_seconds: u64,
    pub upload_low_seconds: u64,
    pub download_low_seconds: u64,
}

impl AutoThrottleStatusItem {
    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "runtime".to_string(),
            JsonValue::String(self.runtime.clone()),
        );
        map.insert(
            "project".to_string(),
            JsonValue::String(self.project.clone()),
        );
        map.insert(
            "container_name".to_string(),
            JsonValue::String(self.container_name.clone()),
        );
        map.insert(
            "container_id".to_string(),
            JsonValue::String(self.container_id.clone()),
        );
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        map.insert(
            "sampling_state".to_string(),
            JsonValue::String(self.sampling_state.clone()),
        );
        map.insert(
            "network_interface".to_string(),
            JsonValue::String(self.network_interface.clone()),
        );
        map.insert(
            "upload_mbps".to_string(),
            JsonValue::Number(self.upload_mbps.to_string()),
        );
        map.insert(
            "download_mbps".to_string(),
            JsonValue::Number(self.download_mbps.to_string()),
        );
        map.insert(
            "upload_current_mbps".to_string(),
            JsonValue::Number(format_f64_json(self.upload_current_mbps)),
        );
        map.insert(
            "download_current_mbps".to_string(),
            JsonValue::Number(format_f64_json(self.download_current_mbps)),
        );
        map.insert(
            "upload_baseline_mbps".to_string(),
            JsonValue::Number(self.upload_baseline_mbps.to_string()),
        );
        map.insert(
            "download_baseline_mbps".to_string(),
            JsonValue::Number(self.download_baseline_mbps.to_string()),
        );
        map.insert(
            "upload_high_seconds".to_string(),
            JsonValue::Number(self.upload_high_seconds.to_string()),
        );
        map.insert(
            "download_high_seconds".to_string(),
            JsonValue::Number(self.download_high_seconds.to_string()),
        );
        map.insert(
            "upload_low_seconds".to_string(),
            JsonValue::Number(self.upload_low_seconds.to_string()),
        );
        map.insert(
            "download_low_seconds".to_string(),
            JsonValue::Number(self.download_low_seconds.to_string()),
        );
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AutoThrottleStatus {
    pub enabled: bool,
    pub state: String,
    pub interface: String,
    pub threshold_percent: u32,
    pub trigger_seconds: u64,
    pub tier_percentages: Vec<u32>,
    pub minimum_mbps: u32,
    pub recovery_percent: u32,
    pub recovery_seconds: u64,
    pub mapped_containers: Option<usize>,
    pub unmapped_containers: Option<usize>,
    pub unavailable_samples: Option<usize>,
    pub message: Option<String>,
    pub items: Vec<AutoThrottleStatusItem>,
}

impl AutoThrottleStatus {
    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("enabled".to_string(), JsonValue::Bool(self.enabled));
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        map.insert(
            "interface".to_string(),
            JsonValue::String(self.interface.clone()),
        );
        map.insert(
            "threshold_percent".to_string(),
            JsonValue::Number(self.threshold_percent.to_string()),
        );
        map.insert(
            "trigger_seconds".to_string(),
            JsonValue::Number(self.trigger_seconds.to_string()),
        );
        map.insert(
            "tier_percentages".to_string(),
            JsonValue::Array(
                self.tier_percentages
                    .iter()
                    .map(|p| JsonValue::Number(p.to_string()))
                    .collect(),
            ),
        );
        map.insert(
            "minimum_mbps".to_string(),
            JsonValue::Number(self.minimum_mbps.to_string()),
        );
        map.insert(
            "recovery_percent".to_string(),
            JsonValue::Number(self.recovery_percent.to_string()),
        );
        map.insert(
            "recovery_seconds".to_string(),
            JsonValue::Number(self.recovery_seconds.to_string()),
        );
        if let Some(v) = self.mapped_containers {
            map.insert(
                "mapped_containers".to_string(),
                JsonValue::Number(v.to_string()),
            );
        }
        if let Some(v) = self.unmapped_containers {
            map.insert(
                "unmapped_containers".to_string(),
                JsonValue::Number(v.to_string()),
            );
        }
        if let Some(v) = self.unavailable_samples {
            map.insert(
                "unavailable_samples".to_string(),
                JsonValue::Number(v.to_string()),
            );
        }
        if let Some(ref msg) = self.message {
            map.insert("message".to_string(), JsonValue::String(msg.clone()));
        }
        map.insert(
            "items".to_string(),
            JsonValue::Array(self.items.iter().map(AutoThrottleStatusItem::to_json_val).collect()),
        );
        JsonValue::Object(map)
    }
}

fn identity_key(id: &(String, String, String, String)) -> String {
    format!("{}\0{}\0{}\0{}", id.0, id.1, id.2, id.3)
}

fn compute_automatic_limits<R: TcRunner>(
    enabled: bool,
    host_limit: Option<&NormalizedLimit>,
    host_id: &str,
    containers: &[ContainerInput],
    traffic_samples: &[TrafficSampleInput],
    sample_at: u64,
    sample_interval_seconds: u64,
    bridge_inventory: &[BridgeInterfaceInput],
    state: &mut BandwidthState,
    runner: &mut R,
    peer_cache: &mut Option<Result<Vec<PeerEntry>, BandwidthError>>,
) -> (Vec<NormalizedLimit>, AutoThrottleStatus) {
    let host_limit = if enabled { host_limit } else { None };
    let enabled = enabled && host_limit.is_some();
    let interface = host_limit
        .map(|h| h.interface.clone())
        .unwrap_or_default();

    let mut auto_state = match state.auto_throttle_state.take() {
        Some(prev) if prev.interface == interface => prev,
        _ => AutoThrottlePersistedState {
            interface: interface.clone(),
            ..Default::default()
        },
    };

    if !enabled {
        state.auto_throttle_state = Some(AutoThrottlePersistedState {
            interface: String::new(),
            last_sample_at: sample_at,
            status: "disabled".to_string(),
            ..Default::default()
        });
        return (
            Vec::new(),
            AutoThrottleStatus {
                enabled: false,
                state: "disabled".to_string(),
                interface: String::new(),
                threshold_percent: AUTO_THRESHOLD_PERCENT,
                trigger_seconds: AUTO_TRIGGER_SECONDS,
                tier_percentages: AUTO_TIER_PERCENTAGES.to_vec(),
                minimum_mbps: AUTO_MINIMUM_MBPS,
                recovery_percent: AUTO_RECOVERY_PERCENT,
                recovery_seconds: AUTO_RECOVERY_SECONDS,
                mapped_containers: None,
                unmapped_containers: None,
                unavailable_samples: None,
                message: None,
                items: Vec::new(),
            },
        );
    }

    let host_limit = host_limit.expect("checked Some");
    let mut candidates: BTreeMap<(String, String, String, String), &ContainerInput> = BTreeMap::new();
    for item in containers {
        let id = item.identity();
        if RuntimeKind::parse(&id.0).is_some() && !id.2.is_empty() && !id.3.is_empty() {
            candidates.insert(id, item);
        }
    }

    let current_sample = sample_at;
    let previous_sample = auto_state.last_sample_at;
    if current_sample > previous_sample {
        let mut samples_map: BTreeMap<(String, String, String, String), &TrafficSampleInput> =
            BTreeMap::new();
        for s in traffic_samples {
            let id = s.identity();
            if RuntimeKind::parse(&id.0).is_some() && !id.2.is_empty() && !id.3.is_empty() {
                samples_map.insert(id, s);
            }
        }

        let (host_links, default_routes, host_network_error) = host_link_snapshot(runner);
        let mut mapping_reason = if host_links.is_empty() {
            "host_link_inventory_unavailable".to_string()
        } else {
            String::new()
        };
        if !host_network_error.is_empty() && mapping_reason.is_empty() {
            mapping_reason = "host_route_inventory_unavailable".to_string();
        }
        let host_namespace_inode = match runner.netns_inode(1) {
            Ok(ino) => ino.to_string(),
            Err(_) => {
                mapping_reason = "host_namespace_unavailable".to_string();
                String::new()
            }
        };

        let mut mapped_identities: BTreeSet<(String, String, String, String)> = BTreeSet::new();
        let mut unmapped_identities: BTreeSet<(String, String, String, String)> = BTreeSet::new();
        let mut unavailable_samples = 0usize;
        let mut namespace_owners: HashMap<String, Vec<(String, String, String, String)>> =
            HashMap::new();

        for identity in candidates.keys() {
            let item = NormalizedLimit {
                scope: Scope::Container,
                interface: String::new(),
                runtime: identity.0.clone(),
                project: identity.1.clone(),
                container_name: identity.2.clone(),
                container_id: identity.3.clone(),
                upload_mbps: 1,
                download_mbps: 1,
            };
            let key = identity_key(identity);
            let target = match resolve_container_cached(
                host_id,
                &item,
                containers,
                runner,
                peer_cache,
            ) {
                Ok(t) => t,
                Err(exc) => {
                    unmapped_identities.insert(identity.clone());
                    if let Some(prev) = auto_state.containers.get_mut(&key) {
                        prev.sampling_state = "target_unavailable".to_string();
                        prev.message = truncate_chars(exc.message(), 180);
                    }
                    continue;
                }
            };

            let ns_inode = target.namespace_inode.as_str();
            if ns_inode.is_empty()
                || host_namespace_inode.is_empty()
                || ns_inode == host_namespace_inode
            {
                unmapped_identities.insert(identity.clone());
                if let Some(prev) = auto_state.containers.get_mut(&key) {
                    prev.state = "unmapped".to_string();
                    prev.sampling_state = if host_namespace_inode.is_empty() {
                        "host_namespace_unavailable".to_string()
                    } else {
                        "unsafe_shared_namespace".to_string()
                    };
                    prev.directions.clear();
                }
                continue;
            }

            let shared_with = namespace_owners.entry(ns_inode.to_string()).or_default();
            if !shared_with.is_empty() {
                for existing_id in shared_with.iter().chain(std::iter::once(identity)) {
                    mapped_identities.remove(existing_id);
                    unmapped_identities.insert(existing_id.clone());
                    let skey = identity_key(existing_id);
                    if let Some(srec) = auto_state.containers.get_mut(&skey) {
                        srec.state = "unmapped".to_string();
                        srec.sampling_state = "shared_network_namespace".to_string();
                        srec.directions.clear();
                    }
                }
                shared_with.push(identity.clone());
                continue;
            }
            shared_with.push(identity.clone());

            if !uses_selected_host_interface(
                &interface,
                target.peer_index,
                &host_links,
                &default_routes,
                bridge_inventory,
            ) {
                unmapped_identities.insert(identity.clone());
                if let Some(prev) = auto_state.containers.get_mut(&key) {
                    prev.state = "unmapped".to_string();
                    prev.sampling_state = "interface_unmapped".to_string();
                    prev.directions.clear();
                }
                continue;
            }

            mapped_identities.insert(identity.clone());
            let Some(sample) = samples_map
                .get(identity)
                .filter(|s| s.traffic_counters_available)
            else {
                unavailable_samples += 1;
                if let Some(prev) = auto_state.containers.get_mut(&key) {
                    prev.sampling_state = "unavailable".to_string();
                }
                continue;
            };

            let same_process = auto_state.containers.get(&key).map_or(false, |prev| {
                prev.process_generation == target.process_generation
                    && prev.namespace_inode == target.namespace_inode
                    && prev.interface_index == target.interface_index
            });

            let mut record = if same_process {
                auto_state.containers.get(&key).cloned().unwrap_or_default()
            } else {
                TrackedContainerState {
                    identity: [
                        identity.0.clone(),
                        identity.1.clone(),
                        identity.2.clone(),
                        identity.3.clone(),
                    ],
                    process_generation: target.process_generation.clone(),
                    namespace_inode: target.namespace_inode.clone(),
                    interface_index: target.interface_index,
                    network_interface: target.interface.clone(),
                    ..Default::default()
                }
            };

            for (dir_name, rate_opt, base_mbps) in [
                ("upload", sample.net_tx_bps, host_limit.upload_mbps),
                ("download", sample.net_rx_bps, host_limit.download_mbps),
            ] {
                let Some(rate_bps) = finite_rate(rate_opt).filter(|_| base_mbps > 0) else {
                    record.directions.remove(dir_name);
                    continue;
                };
                let dir_state = record.directions.entry(dir_name.to_string()).or_default();
                if dir_state.last_sample_at >= current_sample {
                    continue;
                }
                advance_direction(
                    dir_state,
                    base_mbps,
                    rate_bps * 8.0 / 1_000_000.0,
                    current_sample,
                    sample_interval_seconds,
                );
            }

            let is_limited = record.directions.values().any(|d| d.stage > 0);
            record.identity = [
                identity.0.clone(),
                identity.1.clone(),
                identity.2.clone(),
                identity.3.clone(),
            ];
            record.process_generation = target.process_generation;
            record.namespace_inode = target.namespace_inode;
            record.interface_index = target.interface_index;
            record.network_interface = target.interface;
            record.state = if is_limited {
                "limited".to_string()
            } else {
                "monitoring".to_string()
            };
            record.sampling_state = "healthy".to_string();
            record.last_sample_at = current_sample;
            auto_state.containers.insert(key, record);
        }

        auto_state.last_sample_at = current_sample;
        auto_state.status = "monitoring".to_string();
        auto_state.mapped_containers = mapped_identities.len();
        auto_state.unmapped_containers = unmapped_identities.len();
        auto_state.unavailable_samples = unavailable_samples;
        auto_state.mapping_error = if !mapping_reason.is_empty() && !host_network_error.is_empty() {
            truncate_chars(&host_network_error, 500)
        } else {
            String::new()
        };
        auto_state.mapping_reason = mapping_reason;
    }

    auto_state.containers.retain(|_, rec| {
        !(current_sample > 0
            && rec.last_sample_at > 0
            && current_sample.saturating_sub(rec.last_sample_at) > PRUNE_DEPARTED_AFTER_SECS)
    });

    let mut auto_limits: Vec<NormalizedLimit> = Vec::new();
    let mut status_items: Vec<AutoThrottleStatusItem> = Vec::new();

    for rec in auto_state.containers.values() {
        let rt = &rec.identity[0];
        if RuntimeKind::parse(rt).is_none() {
            continue;
        }
        let upload_tiers = auto_tier_rates(host_limit.upload_mbps);
        let download_tiers = auto_tier_rates(host_limit.download_mbps);
        let upload_dir = rec.directions.get("upload");
        let download_dir = rec.directions.get("download");

        let upload_rate = upload_dir
            .filter(|d| d.stage >= 1 && d.stage <= upload_tiers.len())
            .map(|d| upload_tiers[d.stage - 1])
            .unwrap_or(0);
        let download_rate = download_dir
            .filter(|d| d.stage >= 1 && d.stage <= download_tiers.len())
            .map(|d| download_tiers[d.stage - 1])
            .unwrap_or(0);

        if upload_rate > 0 || download_rate > 0 {
            auto_limits.push(NormalizedLimit {
                scope: Scope::Container,
                interface: String::new(),
                runtime: rec.identity[0].clone(),
                project: rec.identity[1].clone(),
                container_name: rec.identity[2].clone(),
                container_id: rec.identity[3].clone(),
                upload_mbps: upload_rate,
                download_mbps: download_rate,
            });
        }

        status_items.push(AutoThrottleStatusItem {
            runtime: rec.identity[0].clone(),
            project: rec.identity[1].clone(),
            container_name: rec.identity[2].clone(),
            container_id: rec.identity[3].clone(),
            state: if rec.state.is_empty() {
                "monitoring".to_string()
            } else {
                rec.state.clone()
            },
            sampling_state: if rec.sampling_state.is_empty() {
                "unknown".to_string()
            } else {
                rec.sampling_state.clone()
            },
            network_interface: rec.network_interface.clone(),
            upload_mbps: upload_rate,
            download_mbps: download_rate,
            upload_current_mbps: upload_dir.map_or(0.0, |d| d.last_usage_mbps),
            download_current_mbps: download_dir.map_or(0.0, |d| d.last_usage_mbps),
            upload_baseline_mbps: host_limit.upload_mbps,
            download_baseline_mbps: host_limit.download_mbps,
            upload_high_seconds: upload_dir.map_or(0, |d| d.high_seconds),
            download_high_seconds: download_dir.map_or(0, |d| d.high_seconds),
            upload_low_seconds: upload_dir.map_or(0, |d| d.low_seconds),
            download_low_seconds: download_dir.map_or(0, |d| d.low_seconds),
        });
    }

    let status_state = if !auto_state.mapping_reason.is_empty() {
        "verification_unavailable"
    } else if auto_limits.is_empty() && auto_state.mapped_containers == 0 {
        "no_mapped_containers"
    } else if auto_limits.is_empty() && auto_state.unavailable_samples > 0 {
        "sampling_unavailable"
    } else if !auto_limits.is_empty() {
        "limited"
    } else {
        "monitoring"
    };

    let message = match auto_state.mapping_reason.as_str() {
        "host_namespace_unavailable" => {
            Some("宿主机网络命名空间不可读，已跳过自动限速路径核验".to_string())
        }
        "host_link_inventory_unavailable" => {
            let suffix = if auto_state.mapping_error.is_empty() {
                String::new()
            } else {
                format!("：{}", auto_state.mapping_error)
            };
            Some(format!(
                "宿主机网卡清单不可读，已跳过自动限速路径核验{suffix}"
            ))
        }
        "host_route_inventory_unavailable" => {
            let suffix = if auto_state.mapping_error.is_empty() {
                String::new()
            } else {
                format!("：{}", auto_state.mapping_error)
            };
            Some(format!(
                "宿主机路由清单不可读，无法确认容器是否经过所选网卡，已跳过自动限速路径核验{suffix}"
            ))
        }
        _ => None,
    };

    status_items.truncate(500);
    let status = AutoThrottleStatus {
        enabled: true,
        state: status_state.to_string(),
        interface,
        threshold_percent: AUTO_THRESHOLD_PERCENT,
        trigger_seconds: AUTO_TRIGGER_SECONDS,
        tier_percentages: AUTO_TIER_PERCENTAGES.to_vec(),
        minimum_mbps: AUTO_MINIMUM_MBPS,
        recovery_percent: AUTO_RECOVERY_PERCENT,
        recovery_seconds: AUTO_RECOVERY_SECONDS,
        mapped_containers: Some(auto_state.mapped_containers),
        unmapped_containers: Some(auto_state.unmapped_containers),
        unavailable_samples: Some(auto_state.unavailable_samples),
        message,
        items: status_items,
    };

    state.auto_throttle_state = Some(auto_state);
    (auto_limits, status)
}

pub fn merge_automatic_limits(
    manual_limits: &[NormalizedLimit],
    automatic_limits: &[NormalizedLimit],
) -> Vec<NormalizedLimit> {
    let mut merged = manual_limits.to_vec();
    let mut by_identity: HashMap<(String, String, String, String), usize> = HashMap::new();
    for (idx, item) in merged.iter().enumerate() {
        if item.scope == Scope::Container {
            by_identity.insert(
                (
                    item.runtime.clone(),
                    item.project.clone(),
                    item.container_name.clone(),
                    item.container_id.clone(),
                ),
                idx,
            );
        }
    }
    for automatic in automatic_limits {
        let id = (
            automatic.runtime.clone(),
            automatic.project.clone(),
            automatic.container_name.clone(),
            automatic.container_id.clone(),
        );
        if let Some(&idx) = by_identity.get(&id) {
            let current = &mut merged[idx];
            if automatic.upload_mbps > 0 {
                current.upload_mbps = if current.upload_mbps > 0 {
                    current.upload_mbps.min(automatic.upload_mbps)
                } else {
                    automatic.upload_mbps
                };
            }
            if automatic.download_mbps > 0 {
                current.download_mbps = if current.download_mbps > 0 {
                    current.download_mbps.min(automatic.download_mbps)
                } else {
                    automatic.download_mbps
                };
            }
        } else {
            by_identity.insert(id, merged.len());
            merged.push(automatic.clone());
        }
    }
    merged
}

// ---------------------------------------------------------------------------
// 11. Atomic JSON state persistence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct StoredEntry {
    pub key: String,
    pub owner_key: String,
    pub expected_node_id: String,
    pub scope: String,
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub container_id: String,
    pub prefix: Vec<String>,
    pub pid: u32,
    pub process_generation: String,
    pub interface: String,
    pub interface_index: u32,
    pub peer_index: u32,
    pub namespace_inode: String,
    pub directions: Vec<String>,
    pub rates_mbps: BTreeMap<String, u32>,
    pub filter_prefs: BTreeMap<String, u16>,
    pub confirmed_at: BTreeMap<String, u64>,
    pub last_confirmed_at: u64,
}

impl StoredEntry {
    fn from_json(key_hint: &str, val: &JsonValue) -> Option<Self> {
        let obj = val.as_object()?;
        let prefix = obj
            .get("prefix")
            .and_then(JsonValue::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let directions = obj
            .get("directions")
            .and_then(JsonValue::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let mut rates_mbps = BTreeMap::new();
        if let Some(r_obj) = obj.get("rates_mbps").and_then(JsonValue::as_object) {
            for (k, v) in r_obj {
                if let Some(n) = v.as_i64_lenient().and_then(|n| u32::try_from(n).ok()) {
                    rates_mbps.insert(k.clone(), n);
                }
            }
        }
        let mut filter_prefs = BTreeMap::new();
        if let Some(p_obj) = obj.get("filter_prefs").and_then(JsonValue::as_object) {
            for (k, v) in p_obj {
                if let Some(n) = v.as_i64_lenient().and_then(|n| u16::try_from(n).ok()) {
                    filter_prefs.insert(k.clone(), n);
                }
            }
        }
        let mut confirmed_at = BTreeMap::new();
        if let Some(c_obj) = obj.get("confirmed_at").and_then(JsonValue::as_object) {
            for (k, v) in c_obj {
                if let Some(n) = v.as_i64_lenient().filter(|&n| n >= 0) {
                    confirmed_at.insert(k.clone(), n as u64);
                }
            }
        }
        let ns_inode = match obj.get("namespace_inode") {
            Some(JsonValue::String(s)) => s.clone(),
            Some(JsonValue::Number(n)) => n.clone(),
            _ => String::new(),
        };
        Some(Self {
            key: obj
                .get("key")
                .and_then(JsonValue::as_str)
                .unwrap_or(key_hint)
                .to_string(),
            owner_key: obj
                .get("owner_key")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            expected_node_id: obj
                .get("expected_node_id")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            scope: obj
                .get("scope")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            runtime: obj
                .get("runtime")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            project: obj
                .get("project")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            container_name: obj
                .get("container_name")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            container_id: obj
                .get("container_id")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            prefix,
            pid: obj
                .get("pid")
                .and_then(JsonValue::as_i64_lenient)
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0),
            process_generation: obj
                .get("process_generation")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            interface: obj
                .get("interface")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            interface_index: obj
                .get("interface_index")
                .and_then(JsonValue::as_i64_lenient)
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0),
            peer_index: obj
                .get("peer_index")
                .and_then(JsonValue::as_i64_lenient)
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0),
            namespace_inode: ns_inode,
            directions,
            rates_mbps,
            filter_prefs,
            confirmed_at,
            last_confirmed_at: obj
                .get("last_confirmed_at")
                .and_then(JsonValue::as_i64_lenient)
                .map(|v| v.max(0) as u64)
                .unwrap_or(0),
        })
    }

    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("key".to_string(), JsonValue::String(self.key.clone()));
        map.insert(
            "owner_key".to_string(),
            JsonValue::String(self.owner_key.clone()),
        );
        map.insert(
            "expected_node_id".to_string(),
            JsonValue::String(self.expected_node_id.clone()),
        );
        map.insert("scope".to_string(), JsonValue::String(self.scope.clone()));
        if self.scope == "container" || !self.runtime.is_empty() {
            map.insert(
                "runtime".to_string(),
                JsonValue::String(self.runtime.clone()),
            );
            map.insert(
                "project".to_string(),
                JsonValue::String(self.project.clone()),
            );
            map.insert(
                "container_name".to_string(),
                JsonValue::String(self.container_name.clone()),
            );
            map.insert(
                "container_id".to_string(),
                JsonValue::String(self.container_id.clone()),
            );
            map.insert(
                "pid".to_string(),
                JsonValue::Number(self.pid.to_string()),
            );
            map.insert(
                "process_generation".to_string(),
                JsonValue::String(self.process_generation.clone()),
            );
            map.insert(
                "peer_index".to_string(),
                JsonValue::Number(self.peer_index.to_string()),
            );
        }
        map.insert(
            "prefix".to_string(),
            JsonValue::Array(self.prefix.iter().map(|s| JsonValue::String(s.clone())).collect()),
        );
        map.insert(
            "interface".to_string(),
            JsonValue::String(self.interface.clone()),
        );
        map.insert(
            "interface_index".to_string(),
            JsonValue::Number(self.interface_index.to_string()),
        );
        map.insert(
            "namespace_inode".to_string(),
            JsonValue::String(self.namespace_inode.clone()),
        );
        map.insert(
            "directions".to_string(),
            JsonValue::Array(
                self.directions
                    .iter()
                    .map(|s| JsonValue::String(s.clone()))
                    .collect(),
            ),
        );
        let mut r_map = BTreeMap::new();
        for (k, v) in &self.rates_mbps {
            r_map.insert(k.clone(), JsonValue::Number(v.to_string()));
        }
        map.insert("rates_mbps".to_string(), JsonValue::Object(r_map));
        let mut p_map = BTreeMap::new();
        for (k, v) in &self.filter_prefs {
            p_map.insert(k.clone(), JsonValue::Number(v.to_string()));
        }
        map.insert("filter_prefs".to_string(), JsonValue::Object(p_map));
        let mut c_map = BTreeMap::new();
        for (k, v) in &self.confirmed_at {
            c_map.insert(k.clone(), JsonValue::Number(v.to_string()));
        }
        map.insert("confirmed_at".to_string(), JsonValue::Object(c_map));
        map.insert(
            "last_confirmed_at".to_string(),
            JsonValue::Number(self.last_confirmed_at.to_string()),
        );
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone)]
pub struct BandwidthState {
    pub schema: i64,
    pub host_id: String,
    pub expected_node_id: String,
    pub revision: i64,
    pub entries: BTreeMap<String, StoredEntry>,
    pub auto_throttle_state: Option<AutoThrottlePersistedState>,
    pub status: Option<JsonValue>,
}

impl Default for BandwidthState {
    fn default() -> Self {
        Self {
            schema: 1,
            host_id: String::new(),
            expected_node_id: String::new(),
            revision: 0,
            entries: BTreeMap::new(),
            auto_throttle_state: None,
            status: None,
        }
    }
}

impl BandwidthState {
    pub fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("schema".to_string(), JsonValue::Number(self.schema.to_string()));
        map.insert(
            "host_id".to_string(),
            JsonValue::String(self.host_id.clone()),
        );
        map.insert(
            "expected_node_id".to_string(),
            JsonValue::String(self.expected_node_id.clone()),
        );
        map.insert(
            "revision".to_string(),
            JsonValue::Number(self.revision.to_string()),
        );
        let mut entries_map = BTreeMap::new();
        for (k, v) in &self.entries {
            entries_map.insert(k.clone(), v.to_json_val());
        }
        map.insert("entries".to_string(), JsonValue::Object(entries_map));
        if let Some(ref auto) = self.auto_throttle_state {
            map.insert("auto_throttle_state".to_string(), auto.to_json_val());
        }
        if let Some(ref status) = self.status {
            map.insert("status".to_string(), status.clone());
        }
        JsonValue::Object(map)
    }

    pub fn to_json(&self) -> String {
        self.to_json_val().to_json()
    }
}

pub fn default_state_path() -> PathBuf {
    env::var(STATE_PATH_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_PATH))
}

pub fn read_state(path: &Path) -> BandwidthState {
    let Ok(raw) = fs::read_to_string(path) else {
        return BandwidthState::default();
    };
    let Ok(val) = JsonValue::parse(&raw) else {
        return BandwidthState::default();
    };
    let Some(obj) = val.as_object() else {
        return BandwidthState::default();
    };
    if obj.get("schema").and_then(JsonValue::as_strict_i64) != Some(1) {
        return BandwidthState::default();
    }
    let Some(entries_obj) = obj.get("entries").and_then(JsonValue::as_object) else {
        return BandwidthState::default();
    };
    let mut entries = BTreeMap::new();
    for (k, v) in entries_obj {
        if let Some(entry) = StoredEntry::from_json(k, v) {
            entries.insert(k.clone(), entry);
        }
    }
    BandwidthState {
        schema: 1,
        host_id: obj
            .get("host_id")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string(),
        expected_node_id: obj
            .get("expected_node_id")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string(),
        revision: obj
            .get("revision")
            .and_then(JsonValue::as_i64_lenient)
            .unwrap_or(0),
        entries,
        auto_throttle_state: obj
            .get("auto_throttle_state")
            .and_then(AutoThrottlePersistedState::from_json),
        status: obj.get("status").cloned(),
    }
}

struct TempFileCleanup<'a>(&'a Path);

impl Drop for TempFileCleanup<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0);
    }
}

#[cfg(unix)]
fn set_dir_mode_700(dir: &Path) {
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_mode_700(_dir: &Path) {}

#[cfg(unix)]
fn set_file_mode_600(path: &Path) -> std::io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_file_mode_600(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn open_exclusive_600(path: &Path) -> std::io::Result<fs::File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_exclusive_600(path: &Path) -> std::io::Result<fs::File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Atomically persist `state` as compact JSON with `0600` permissions on Unix.
pub fn write_state_atomic(path: &Path, state: &BandwidthState) -> std::io::Result<()> {
    let directory = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let dir_existed = directory.exists();
    fs::create_dir_all(directory)?;
    if !dir_existed {
        set_dir_mode_700(directory);
    }

    let pid = std::process::id();
    let mut temp_path = PathBuf::new();
    let mut opened: Option<fs::File> = None;
    for _ in 0..8 {
        let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let candidate = directory.join(format!(".manual-bandwidth-{pid}-{nanos}-{seq}.tmp"));
        match open_exclusive_600(&candidate) {
            Ok(file) => {
                temp_path = candidate;
                opened = Some(file);
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    let Some(mut file) = opened else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "unable to create a unique bandwidth state temporary file",
        ));
    };
    let _cleanup = TempFileCleanup(&temp_path);
    set_file_mode_600(&temp_path)?;
    let encoded = state.to_json();
    file.write_all(encoded.as_bytes())?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp_path, path)?;
    set_file_mode_600(path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 12. Status structs & reconciliation engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusItem {
    pub scope: String,
    pub target: String,
    pub interface: Option<String>,
    pub runtime: Option<String>,
    pub project: Option<String>,
    pub container_name: Option<String>,
    pub container_id: Option<String>,
    pub direction: Option<String>,
    pub rate_mbps: Option<u32>,
    pub state: String,
    pub message: Option<String>,
}

impl StatusItem {
    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("scope".to_string(), JsonValue::String(self.scope.clone()));
        map.insert("target".to_string(), JsonValue::String(self.target.clone()));
        if let Some(ref v) = self.interface {
            map.insert("interface".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(ref v) = self.runtime {
            map.insert("runtime".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(ref v) = self.project {
            map.insert("project".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(ref v) = self.container_name {
            map.insert("container_name".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(ref v) = self.container_id {
            map.insert("container_id".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(ref v) = self.direction {
            map.insert("direction".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(v) = self.rate_mbps {
            map.insert("rate_mbps".to_string(), JsonValue::Number(v.to_string()));
        }
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        if let Some(ref v) = self.message {
            map.insert("message".to_string(), JsonValue::String(v.clone()));
        }
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryStatus {
    pub state: String,
}

impl RetryStatus {
    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        map.insert("attempts".to_string(), JsonValue::Null);
        map.insert("after_seconds".to_string(), JsonValue::Null);
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackAttemptResult {
    pub state: String,
    pub direction: String,
    pub message: Option<String>,
}

impl RollbackAttemptResult {
    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        map.insert(
            "direction".to_string(),
            JsonValue::String(self.direction.clone()),
        );
        if let Some(ref msg) = self.message {
            map.insert("message".to_string(), JsonValue::String(msg.clone()));
        }
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackStatus {
    pub state: String,
    pub attempted: bool,
    pub results: Option<Vec<RollbackAttemptResult>>,
    pub restored: Option<usize>,
    pub errors: Option<Vec<String>>,
}

impl RollbackStatus {
    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        map.insert("attempted".to_string(), JsonValue::Bool(self.attempted));
        if let Some(ref res) = self.results {
            map.insert(
                "results".to_string(),
                JsonValue::Array(
                    res.iter()
                        .take(8)
                        .map(RollbackAttemptResult::to_json_val)
                        .collect(),
                ),
            );
        }
        if let Some(restored) = self.restored {
            map.insert(
                "restored".to_string(),
                JsonValue::Number(restored.to_string()),
            );
        }
        if let Some(ref errors) = self.errors {
            map.insert(
                "errors".to_string(),
                JsonValue::Array(
                    errors
                        .iter()
                        .take(5)
                        .map(|e| JsonValue::String(e.clone()))
                        .collect(),
                ),
            );
        }
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveLimitItem {
    pub scope: String,
    pub target: String,
    pub interface: String,
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub container_id: String,
    pub upload_mbps: u32,
    pub download_mbps: u32,
    pub last_confirmed_at: u64,
}

impl ActiveLimitItem {
    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("scope".to_string(), JsonValue::String(self.scope.clone()));
        map.insert("target".to_string(), JsonValue::String(self.target.clone()));
        map.insert(
            "interface".to_string(),
            JsonValue::String(self.interface.clone()),
        );
        map.insert(
            "runtime".to_string(),
            JsonValue::String(self.runtime.clone()),
        );
        map.insert(
            "project".to_string(),
            JsonValue::String(self.project.clone()),
        );
        map.insert(
            "container_name".to_string(),
            JsonValue::String(self.container_name.clone()),
        );
        map.insert(
            "container_id".to_string(),
            JsonValue::String(self.container_id.clone()),
        );
        map.insert(
            "upload_mbps".to_string(),
            JsonValue::Number(self.upload_mbps.to_string()),
        );
        map.insert(
            "download_mbps".to_string(),
            JsonValue::Number(self.download_mbps.to_string()),
        );
        map.insert(
            "last_confirmed_at".to_string(),
            JsonValue::Number(self.last_confirmed_at.to_string()),
        );
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReconcileStatus {
    pub revision: i64,
    pub state: String,
    pub message: Option<String>,
    pub items: Vec<StatusItem>,
    pub retry: Option<RetryStatus>,
    pub rollback: Option<RollbackStatus>,
    pub auto_throttle: Option<AutoThrottleStatus>,
    pub updated_at: Option<u64>,
    pub active_limits: Option<Vec<ActiveLimitItem>>,
}

impl Default for ReconcileStatus {
    fn default() -> Self {
        Self {
            revision: 0,
            state: "unconfigured".to_string(),
            message: None,
            items: Vec::new(),
            retry: None,
            rollback: None,
            auto_throttle: None,
            updated_at: None,
            active_limits: None,
        }
    }
}

impl ReconcileStatus {
    pub fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "revision".to_string(),
            JsonValue::Number(self.revision.to_string()),
        );
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        if let Some(ref msg) = self.message {
            map.insert("message".to_string(), JsonValue::String(msg.clone()));
        }
        map.insert(
            "items".to_string(),
            JsonValue::Array(self.items.iter().map(StatusItem::to_json_val).collect()),
        );
        if let Some(ref retry) = self.retry {
            map.insert("retry".to_string(), retry.to_json_val());
        }
        if let Some(ref rollback) = self.rollback {
            map.insert("rollback".to_string(), rollback.to_json_val());
        }
        if let Some(ref auto) = self.auto_throttle {
            map.insert("auto_throttle".to_string(), auto.to_json_val());
        }
        if let Some(ts) = self.updated_at {
            map.insert("updated_at".to_string(), JsonValue::Number(ts.to_string()));
        }
        if let Some(ref active) = self.active_limits {
            map.insert(
                "active_limits".to_string(),
                JsonValue::Array(active.iter().map(ActiveLimitItem::to_json_val).collect()),
            );
        }
        JsonValue::Object(map)
    }

    pub fn to_json(&self) -> String {
        self.to_json_val().to_json()
    }
}

fn active_bandwidth_limits(
    entries: &BTreeMap<String, StoredEntry>,
    previous_status: Option<&JsonValue>,
) -> Vec<ActiveLimitItem> {
    let mut legacy_rates: HashMap<(String, String), BTreeMap<String, u32>> = HashMap::new();
    let mut legacy_full_rates: HashMap<(String, String, String, String), BTreeMap<String, u32>> =
        HashMap::new();

    if let Some(prev_items) = previous_status
        .and_then(|s| s.get("items"))
        .and_then(JsonValue::as_array)
    {
        for raw_item in prev_items {
            let Some(item) = raw_item.as_object() else {
                continue;
            };
            let state = item.get("state").and_then(JsonValue::as_str).unwrap_or("");
            if state != "applied" && state != "partial" {
                continue;
            }
            let scope = item.get("scope").and_then(JsonValue::as_str).unwrap_or("");
            let target = item
                .get("target")
                .or_else(|| item.get("container_name"))
                .or_else(|| item.get("interface"))
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            if scope.is_empty() || target.is_empty() {
                continue;
            }
            let mut rates = BTreeMap::new();
            if let Some(dir) = item.get("direction").and_then(JsonValue::as_str) {
                if dir == "upload" || dir == "download" {
                    let rate = item
                        .get("rate_mbps")
                        .and_then(JsonValue::as_i64_lenient)
                        .and_then(|v| u32::try_from(v).ok())
                        .unwrap_or(0);
                    if rate > 0 {
                        rates.insert(dir.to_string(), rate);
                    }
                }
            } else {
                for name in ["upload", "download"] {
                    let rate = item
                        .get(&format!("{name}_mbps"))
                        .and_then(JsonValue::as_i64_lenient)
                        .and_then(|v| u32::try_from(v).ok())
                        .unwrap_or(0);
                    if rate > 0 {
                        rates.insert(name.to_string(), rate);
                    }
                }
            }
            if rates.is_empty() {
                continue;
            }
            let short_key = (scope.to_string(), target.to_string());
            let entry = legacy_rates.entry(short_key).or_default();
            for (k, v) in &rates {
                entry.insert(k.clone(), *v);
            }
            let runtime = item
                .get("runtime")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            let project = item
                .get("project")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            let container_id = item
                .get("container_id")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            if scope == "container" && !runtime.is_empty() && !container_id.is_empty() {
                let full_key = (
                    scope.to_string(),
                    runtime.to_string(),
                    project.to_string(),
                    container_id.to_string(),
                );
                let full_entry = legacy_full_rates.entry(full_key).or_default();
                for (k, v) in &rates {
                    full_entry.insert(k.clone(), *v);
                }
            }
        }
    }

    let mut active = Vec::new();
    for entry in entries.values() {
        let scope = entry.scope.as_str();
        let target = if !entry.container_name.is_empty() {
            entry.container_name.as_str()
        } else {
            entry.interface.as_str()
        };
        if (scope != "host" && scope != "container") || target.is_empty() {
            continue;
        }
        let mut normalized_rates: BTreeMap<String, u32> = BTreeMap::new();
        for dir in ["upload", "download"] {
            if let Some(&r) = entry.rates_mbps.get(dir).filter(|&&r| r > 0) {
                normalized_rates.insert(dir.to_string(), r);
            }
        }
        if normalized_rates.is_empty() {
            if scope == "container" {
                let full_key = (
                    scope.to_string(),
                    entry.runtime.clone(),
                    entry.project.clone(),
                    entry.container_id.clone(),
                );
                if let Some(m) = legacy_full_rates.get(&full_key) {
                    normalized_rates = m.clone();
                } else if let Some(m) = legacy_rates.get(&(scope.to_string(), target.to_string()))
                {
                    normalized_rates = m.clone();
                }
            } else if let Some(m) = legacy_rates.get(&(scope.to_string(), target.to_string())) {
                normalized_rates = m.clone();
            }
        }
        if normalized_rates.is_empty() {
            continue;
        }
        active.push(ActiveLimitItem {
            scope: scope.to_string(),
            target: target.to_string(),
            interface: entry.interface.clone(),
            runtime: entry.runtime.clone(),
            project: entry.project.clone(),
            container_name: entry.container_name.clone(),
            container_id: entry.container_id.clone(),
            upload_mbps: *normalized_rates.get("upload").unwrap_or(&0),
            download_mbps: *normalized_rates.get("download").unwrap_or(&0),
            last_confirmed_at: entry.last_confirmed_at,
        });
    }
    active.sort_by(|a, b| {
        (
            a.scope.as_str(),
            a.runtime.as_str(),
            a.container_name.as_str(),
            a.interface.as_str(),
        )
            .cmp(&(
                b.scope.as_str(),
                b.runtime.as_str(),
                b.container_name.as_str(),
                b.interface.as_str(),
            ))
    });
    active
}

fn remove_entry<R: TcRunner>(
    entry: &StoredEntry,
    expected_host: &str,
    actual_host: &str,
    actual_node: &str,
    runner: &mut R,
) -> Result<Vec<Direction>, BandwidthError> {
    if expected_host != actual_host || entry.expected_node_id != actual_node {
        return Err(BandwidthError::policy(
            "stored tc ownership belongs to a different host enrollment",
        ));
    }
    if !is_valid_iface_name(&entry.interface) {
        return Err(BandwidthError::policy(
            "stored tc ownership has an invalid interface identity",
        ));
    }

    if entry.scope == "host" {
        match runner.host_ifindex(&entry.interface) {
            Ok(idx) => {
                if idx != entry.interface_index {
                    return Ok(Vec::new());
                }
            }
            Err(_) => {
                if entry.interface_index > 0 {
                    return Ok(Vec::new());
                }
                return Err(BandwidthError::policy(
                    "stored host interface identity could not be verified",
                ));
            }
        }
    } else {
        let pid = entry.pid;
        let ns_inode: u64 = entry.namespace_inode.parse().unwrap_or(0);
        if pid == 0 || ns_inode == 0 {
            return Err(BandwidthError::policy(
                "stored container network namespace identity is unavailable",
            ));
        }
        match runner.netns_inode(pid) {
            Err(NetnsError::NotFound) => return Ok(Vec::new()),
            Err(NetnsError::Unavailable(e)) => {
                return Err(BandwidthError::policy(format!(
                    "container network namespace cleanup could not be verified: {}",
                    truncate_chars(&e, 160)
                )))
            }
            Ok(current_ns) => {
                if current_ns != ns_inode {
                    return Err(BandwidthError::policy(
                        "container network namespace changed; prior filter cleanup cannot be verified",
                    ));
                }
            }
        }
        let (code, output) = call_with_prefix(
            runner,
            &entry.prefix,
            &["ip", "-j", "link", "show", "dev", &entry.interface],
        );
        if code != 0 {
            return Err(BandwidthError::policy(
                "container interface inventory is unavailable during cleanup",
            ));
        }
        let (current_idx, _) = parse_link_indices(&output).ok_or_else(|| {
            BandwidthError::policy("container interface identity could not be verified")
        })?;
        if current_idx == 0 {
            return Err(BandwidthError::policy(
                "container interface identity could not be verified",
            ));
        }
        if current_idx != entry.interface_index {
            return Ok(Vec::new());
        }
    }

    let mut removed: Vec<Direction> = Vec::new();
    for direction in Direction::BOTH {
        let pref = entry.filter_prefs.get(direction.as_str()).copied();
        match remove_filter(
            &entry.prefix,
            &entry.interface,
            &entry.owner_key,
            direction,
            pref,
            runner,
        ) {
            Ok(true) => removed.push(direction),
            Ok(false) => {}
            Err(remove_err) => {
                let mut rollback_errors: Vec<String> = Vec::new();
                for &rb_dir in removed.iter().rev() {
                    let rate = entry.rates_mbps.get(rb_dir.as_str()).copied().unwrap_or(0);
                    let res = if rate == 0 {
                        Err(BandwidthError::policy(format!(
                            "previous {} rate is unavailable",
                            rb_dir.as_str()
                        )))
                    } else {
                        apply_filter(
                            &entry.prefix,
                            &entry.interface,
                            &entry.owner_key,
                            rb_dir,
                            rate,
                            true,
                            entry.filter_prefs.get(rb_dir.as_str()).copied(),
                            runner,
                        )
                        .map(|_| ())
                    };
                    if let Err(rb_err) = res {
                        rollback_errors.push(format!(
                            "{}: {}",
                            rb_dir.as_str(),
                            truncate_chars(rb_err.message(), 120)
                        ));
                    }
                }
                let detail = if !rollback_errors.is_empty() {
                    format!(
                        "; rollback could not be verified: {}",
                        rollback_errors
                            .iter()
                            .take(3)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                } else if !removed.is_empty() {
                    let dirs = removed
                        .iter()
                        .rev()
                        .map(|d| d.as_str())
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("; removed filters restored and readback verified: {dirs}")
                } else {
                    String::new()
                };
                let rb_state = if !rollback_errors.is_empty() {
                    "failed"
                } else if !removed.is_empty() {
                    "verified"
                } else {
                    "not_needed"
                };
                return Err(BandwidthError::mutation(
                    format!(
                        "owned bandwidth filter cleanup failed: {}{detail}",
                        truncate_chars(remove_err.message(), 180)
                    ),
                    rb_state,
                ));
            }
        }
    }
    Ok(removed)
}

fn resolve_container_cached<R: TcRunner>(
    host_id: &str,
    item: &NormalizedLimit,
    containers: &[ContainerInput],
    runner: &mut R,
    peer_cache: &mut Option<Result<Vec<PeerEntry>, BandwidthError>>,
) -> Result<ResolvedTarget, BandwidthError> {
    if item.scope == Scope::Container {
        if peer_cache.is_none() {
            *peer_cache = Some(running_container_inventory(containers, runner));
        }
        let peers = match peer_cache.as_ref().expect("just populated") {
            Ok(p) => p.as_slice(),
            Err(e) => return Err(e.clone()),
        };
        return resolve_entry(host_id, item, containers, Some(peers), runner);
    }
    resolve_entry(host_id, item, containers, None, runner)
}

pub struct ReconcileRequest<'a> {
    pub policy_json: &'a str,
    pub host_id: &'a str,
    pub node_id: &'a str,
    pub containers: &'a [ContainerInput],
    pub state_path: &'a Path,
    pub traffic_samples: &'a [TrafficSampleInput],
    pub sample_at: u64,
    pub sample_interval_seconds: u64,
    pub bridge_inventory: &'a [BridgeInterfaceInput],
}

/// Reconcile bandwidth policy against kernel `tc` state using a provided `TcRunner`.
pub fn reconcile_with_runner<R: TcRunner>(
    req: &ReconcileRequest<'_>,
    runner: &mut R,
) -> ReconcileStatus {
    let mut state = read_state(req.state_path);
    if (!state.host_id.is_empty() && state.host_id != req.host_id)
        || (!state.expected_node_id.is_empty() && state.expected_node_id != req.node_id)
    {
        state = BandwidthState {
            schema: 1,
            host_id: req.host_id.to_string(),
            expected_node_id: req.node_id.to_string(),
            ..Default::default()
        };
    }
    state.host_id = req.host_id.to_string();
    state.expected_node_id = req.node_id.to_string();

    let previous_status = state.status.clone();
    let mut status = ReconcileStatus {
        revision: 0,
        state: "unconfigured".to_string(),
        message: None,
        items: Vec::new(),
        retry: Some(RetryStatus {
            state: "not_scheduled".to_string(),
        }),
        rollback: Some(RollbackStatus {
            state: "not_needed".to_string(),
            attempted: false,
            results: None,
            restored: None,
            errors: None,
        }),
        auto_throttle: None,
        updated_at: None,
        active_limits: None,
    };

    let normalized = match validate_policy(req.policy_json, req.host_id, req.node_id) {
        Ok(p) => p,
        Err(exc) => {
            status.state = "rejected".to_string();
            status.message = Some(exc.message().to_string());
            return status;
        }
    };
    status.revision = normalized.revision;

    let mut peer_cache: Option<Result<Vec<PeerEntry>, BandwidthError>> = None;
    let host_limit = normalized
        .limits
        .iter()
        .find(|item| item.scope == Scope::Host);
    let (automatic_limits, automatic_status) = compute_automatic_limits(
        normalized.auto_throttle_enabled,
        host_limit,
        req.host_id,
        req.containers,
        req.traffic_samples,
        req.sample_at,
        req.sample_interval_seconds.max(1),
        req.bridge_inventory,
        &mut state,
        runner,
        &mut peer_cache,
    );
    let effective_limits = merge_automatic_limits(&normalized.limits, &automatic_limits);
    status.auto_throttle = Some(automatic_status);

    let mut desired: Vec<(String, NormalizedLimit, ResolvedTarget)> = Vec::new();
    let mut desired_keys: HashSet<String> = HashSet::new();
    let mut requested_keys: HashSet<String> = HashSet::new();
    let mut cleanup_blocked_keys: HashSet<String> = HashSet::new();
    let mut failures = false;

    for item in &effective_limits {
        requested_keys.insert(item.key());
        match resolve_container_cached(
            req.host_id,
            item,
            req.containers,
            runner,
            &mut peer_cache,
        ) {
            Ok(target) => {
                let k = target.key.clone();
                if let Some(pos) = desired.iter().position(|(dk, _, _)| dk == &k) {
                    desired[pos] = (k, item.clone(), target);
                } else {
                    desired_keys.insert(k.clone());
                    desired.push((k, item.clone(), target));
                }
            }
            Err(exc) => {
                failures = true;
                status.items.push(StatusItem {
                    scope: item.scope.as_str().to_string(),
                    target: item.target_label().to_string(),
                    interface: None,
                    runtime: None,
                    project: None,
                    container_name: None,
                    container_id: None,
                    direction: None,
                    rate_mbps: None,
                    state: "failed".to_string(),
                    message: Some(truncate_chars(exc.message(), 240)),
                });
            }
        }
    }

    let mut rollback_operations: Vec<RollbackOperation> = Vec::new();
    let mut rollback_attempts: Vec<RollbackAttemptResult> = Vec::new();
    let existing_keys: Vec<String> = state.entries.keys().cloned().collect();

    for key in existing_keys {
        if requested_keys.contains(&key) && !desired_keys.contains(&key) {
            continue;
        }
        let Some(old) = state.entries.get(&key).cloned() else {
            continue;
        };
        let same_netns = desired.iter().find(|(dk, _, _)| dk == &key).map_or(
            false,
            |(_, _, new_target)| {
                old.namespace_inode == new_target.namespace_inode
                    && old.interface == new_target.interface
                    && old.interface_index == new_target.interface_index
            },
        );
        if same_netns {
            continue;
        }
        match remove_entry(&old, req.host_id, req.host_id, req.node_id, runner) {
            Ok(removed_dirs) => {
                for dir in removed_dirs {
                    rollback_operations.push(RollbackOperation {
                        prefix: old.prefix.clone(),
                        interface: old.interface.clone(),
                        owner_key: old.owner_key.clone(),
                        direction: dir,
                        previously_owned: true,
                        previous_rate_mbps: old.rates_mbps.get(dir.as_str()).copied(),
                        previous_pref: old.filter_prefs.get(dir.as_str()).copied(),
                    });
                }
                state.entries.remove(&key);
            }
            Err(exc) => {
                failures = true;
                cleanup_blocked_keys.insert(key.clone());
                if let Some(rb_state) = exc.rollback_state() {
                    if rb_state != "not_needed" {
                        rollback_attempts.push(RollbackAttemptResult {
                            state: rb_state.to_string(),
                            direction: "cleanup".to_string(),
                            message: Some(truncate_chars(exc.message(), 180)),
                        });
                    }
                }
                let target_label = if !old.container_name.is_empty() {
                    old.container_name.clone()
                } else {
                    old.interface.clone()
                };
                status.items.push(StatusItem {
                    scope: old.scope.clone(),
                    target: target_label,
                    interface: None,
                    runtime: None,
                    project: None,
                    container_name: None,
                    container_id: None,
                    direction: None,
                    rate_mbps: None,
                    state: "cleanup_failed".to_string(),
                    message: Some(truncate_chars(exc.message(), 240)),
                });
            }
        }
    }

    for (key, item, target) in &desired {
        if cleanup_blocked_keys.contains(key) {
            status.items.push(StatusItem {
                scope: item.scope.as_str().to_string(),
                target: item.target_label().to_string(),
                interface: None,
                runtime: None,
                project: None,
                container_name: None,
                container_id: None,
                direction: None,
                rate_mbps: None,
                state: "failed".to_string(),
                message: Some(
                    "旧的 tc 所有限额无法确认清理，已保留原记录并跳过新规则应用".to_string(),
                ),
            });
            continue;
        }

        let old = state.entries.get(key).cloned();
        let same_target = old.as_ref().map_or(false, |o| {
            o.namespace_inode == target.namespace_inode
                && o.interface == target.interface
                && o.interface_index == target.interface_index
        });

        if let Err(exc) = ensure_clsact(&target.prefix, &target.interface, runner) {
            failures = true;
            status.items.push(StatusItem {
                scope: item.scope.as_str().to_string(),
                target: item.target_label().to_string(),
                interface: Some(target.interface.clone()),
                runtime: Some(item.runtime.clone()),
                project: Some(item.project.clone()),
                container_name: Some(item.container_name.clone()),
                container_id: Some(item.container_id.clone()),
                direction: None,
                rate_mbps: None,
                state: "failed".to_string(),
                message: Some(truncate_chars(exc.message(), 240)),
            });
            continue;
        }

        let old_directions: BTreeSet<String> = if same_target {
            old.as_ref()
                .map(|o| o.directions.iter().cloned().collect())
                .unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        let mut rates: BTreeMap<String, u32> = BTreeMap::new();
        let mut filter_prefs: BTreeMap<String, u16> = BTreeMap::new();
        let mut confirmed_at: BTreeMap<String, u64> = BTreeMap::new();
        if same_target {
            if let Some(ref o) = old {
                for d in &old_directions {
                    if let Some(&r) = o.rates_mbps.get(d) {
                        rates.insert(d.clone(), r);
                    }
                    if let Some(&p) = o.filter_prefs.get(d) {
                        filter_prefs.insert(d.clone(), p);
                    }
                    if let Some(&c) = o.confirmed_at.get(d) {
                        confirmed_at.insert(d.clone(), c);
                    }
                }
            }
        }
        let mut installed = old_directions.clone();

        for direction in Direction::BOTH {
            let dir_str = direction.as_str();
            let rate = item.rate_for(direction);
            let owned = old_directions.contains(dir_str);
            let prev_rate = old
                .as_ref()
                .filter(|_| same_target)
                .and_then(|o| o.rates_mbps.get(dir_str).copied());
            let prev_pref = old
                .as_ref()
                .filter(|_| same_target)
                .and_then(|o| o.filter_prefs.get(dir_str).copied());

            if rate > 0 {
                let op = RollbackOperation {
                    prefix: target.prefix.clone(),
                    interface: target.interface.clone(),
                    owner_key: target.owner_key.clone(),
                    direction,
                    previously_owned: owned,
                    previous_rate_mbps: prev_rate,
                    previous_pref: prev_pref,
                };
                match apply_filter(
                    &target.prefix,
                    &target.interface,
                    &target.owner_key,
                    direction,
                    rate,
                    owned,
                    filter_prefs.get(dir_str).copied(),
                    runner,
                ) {
                    Ok(applied_pref) => {
                        let applied_pref = if (PREF_RANGE_START..PREF_RANGE_END)
                            .contains(&applied_pref)
                        {
                            applied_pref
                        } else {
                            filter_prefs
                                .get(dir_str)
                                .copied()
                                .filter(|&p| (PREF_RANGE_START..PREF_RANGE_END).contains(&p))
                                .unwrap_or_else(|| direction.default_pref())
                        };
                        installed.insert(dir_str.to_string());
                        rates.insert(dir_str.to_string(), rate);
                        filter_prefs.insert(dir_str.to_string(), applied_pref);
                        confirmed_at.insert(dir_str.to_string(), runner.now_unix());
                        rollback_operations.push(op);
                        status.items.push(StatusItem {
                            scope: item.scope.as_str().to_string(),
                            target: item.target_label().to_string(),
                            interface: Some(target.interface.clone()),
                            runtime: Some(item.runtime.clone()),
                            project: Some(item.project.clone()),
                            container_name: Some(item.container_name.clone()),
                            container_id: Some(item.container_id.clone()),
                            direction: Some(dir_str.to_string()),
                            rate_mbps: Some(rate),
                            state: "applied".to_string(),
                            message: None,
                        });
                    }
                    Err(exc) => {
                        match rollback_bandwidth_mutation(&op, runner) {
                            Ok(()) => rollback_attempts.push(RollbackAttemptResult {
                                state: "verified".to_string(),
                                direction: dir_str.to_string(),
                                message: None,
                            }),
                            Err(rb_exc) => rollback_attempts.push(RollbackAttemptResult {
                                state: "failed".to_string(),
                                direction: dir_str.to_string(),
                                message: Some(truncate_chars(rb_exc.message(), 180)),
                            }),
                        }
                        failures = true;
                        status.items.push(StatusItem {
                            scope: item.scope.as_str().to_string(),
                            target: item.target_label().to_string(),
                            interface: Some(target.interface.clone()),
                            runtime: Some(item.runtime.clone()),
                            project: Some(item.project.clone()),
                            container_name: Some(item.container_name.clone()),
                            container_id: Some(item.container_id.clone()),
                            direction: Some(dir_str.to_string()),
                            rate_mbps: Some(rate),
                            state: "failed".to_string(),
                            message: Some(truncate_chars(exc.message(), 240)),
                        });
                    }
                }
            } else if owned {
                let op = RollbackOperation {
                    prefix: target.prefix.clone(),
                    interface: target.interface.clone(),
                    owner_key: target.owner_key.clone(),
                    direction,
                    previously_owned: true,
                    previous_rate_mbps: prev_rate,
                    previous_pref: prev_pref,
                };
                match remove_filter(
                    &target.prefix,
                    &target.interface,
                    &target.owner_key,
                    direction,
                    filter_prefs.get(dir_str).copied(),
                    runner,
                ) {
                    Ok(_) => {
                        rollback_operations.push(op);
                        installed.remove(dir_str);
                        rates.remove(dir_str);
                        filter_prefs.remove(dir_str);
                        confirmed_at.remove(dir_str);
                        status.items.push(StatusItem {
                            scope: item.scope.as_str().to_string(),
                            target: item.target_label().to_string(),
                            interface: Some(target.interface.clone()),
                            runtime: Some(item.runtime.clone()),
                            project: Some(item.project.clone()),
                            container_name: Some(item.container_name.clone()),
                            container_id: Some(item.container_id.clone()),
                            direction: Some(dir_str.to_string()),
                            rate_mbps: Some(0),
                            state: "removed".to_string(),
                            message: None,
                        });
                    }
                    Err(exc) => {
                        failures = true;
                        status.items.push(StatusItem {
                            scope: item.scope.as_str().to_string(),
                            target: item.target_label().to_string(),
                            interface: Some(target.interface.clone()),
                            runtime: Some(item.runtime.clone()),
                            project: Some(item.project.clone()),
                            container_name: Some(item.container_name.clone()),
                            container_id: Some(item.container_id.clone()),
                            direction: Some(dir_str.to_string()),
                            rate_mbps: Some(0),
                            state: "failed".to_string(),
                            message: Some(truncate_chars(exc.message(), 240)),
                        });
                    }
                }
            }
        }

        if !installed.is_empty() {
            let last_confirmed_at = confirmed_at.values().copied().max().unwrap_or(0);
            state.entries.insert(
                key.clone(),
                StoredEntry {
                    key: target.key.clone(),
                    owner_key: target.owner_key.clone(),
                    expected_node_id: req.node_id.to_string(),
                    scope: target.scope.as_str().to_string(),
                    runtime: target.runtime.clone(),
                    project: target.project.clone(),
                    container_name: target.container_name.clone(),
                    container_id: target.container_id.clone(),
                    prefix: target.prefix.clone(),
                    pid: target.pid,
                    process_generation: target.process_generation.clone(),
                    interface: target.interface.clone(),
                    interface_index: target.interface_index,
                    peer_index: target.peer_index,
                    namespace_inode: target.namespace_inode.clone(),
                    directions: installed.into_iter().collect(),
                    rates_mbps: rates,
                    filter_prefs,
                    confirmed_at,
                    last_confirmed_at,
                },
            );
        } else {
            state.entries.remove(key);
        }
    }

    status.state = if failures {
        "failed"
    } else if !desired.is_empty() {
        "applied"
    } else {
        "unconfigured"
    }
    .to_string();
    status.retry = Some(RetryStatus {
        state: if failures {
            "next_agent_cycle"
        } else {
            "not_scheduled"
        }
        .to_string(),
    });
    if !rollback_attempts.is_empty() {
        let rb_failed = rollback_attempts.iter().any(|r| r.state == "failed");
        status.rollback = Some(RollbackStatus {
            state: if rb_failed { "failed" } else { "verified" }.to_string(),
            attempted: true,
            results: Some(rollback_attempts.into_iter().take(8).collect()),
            restored: None,
            errors: None,
        });
    }
    status.updated_at = Some(runner.now_unix());
    status.active_limits = Some(active_bandwidth_limits(
        &state.entries,
        previous_status.as_ref(),
    ));
    state.revision = normalized.revision;
    state.status = Some(status.to_json_val());

    if write_state_atomic(req.state_path, &state).is_err() {
        let mut rollback_errors = Vec::new();
        let mut restored = 0usize;
        for op in rollback_operations.iter().rev() {
            match rollback_bandwidth_mutation(op, runner) {
                Ok(()) => restored += 1,
                Err(exc) => rollback_errors.push(truncate_chars(exc.message(), 180)),
            }
        }
        let persisted = read_state(req.state_path);
        status.active_limits = Some(active_bandwidth_limits(
            &persisted.entries,
            persisted.status.as_ref(),
        ));
        status.rollback = Some(RollbackStatus {
            state: if rollback_errors.is_empty() {
                "verified"
            } else {
                "failed"
            }
            .to_string(),
            attempted: !rollback_operations.is_empty(),
            results: None,
            restored: Some(restored),
            errors: Some(rollback_errors.iter().take(5).cloned().collect()),
        });
        status.retry = Some(RetryStatus {
            state: "next_agent_cycle".to_string(),
        });
        status.state = "failed".to_string();
        status.message = Some(format!(
            "本地 tc 所有权状态保存失败；{}",
            if rollback_errors.is_empty() {
                "已恢复保存前的限额并逐项读回确认"
            } else {
                "回滚存在未确认项"
            }
        ));
    }

    status
}

/// Live entry point using `LiveRunner` against the real OS (`tc`, `ip`, `nsenter`, `/proc`, `/sys`).
pub fn reconcile_live(req: &ReconcileRequest<'_>) -> ReconcileStatus {
    let mut runner = LiveRunner;
    reconcile_with_runner(req, &mut runner)
}

/// Convenience live reconciliation wrapper accepting `runtime_drivers::ContainerSample`.
pub fn reconcile_live_samples(
    policy_json: &str,
    host_id: &str,
    node_id: &str,
    containers: &[ContainerSample],
    state_path: &Path,
    traffic_samples: &[TrafficSampleInput],
    sample_at: u64,
    sample_interval_seconds: u64,
    bridge_inventory: &[BridgeInterfaceInput],
) -> ReconcileStatus {
    let converted: Vec<ContainerInput> = containers.iter().map(ContainerInput::from).collect();
    let req = ReconcileRequest {
        policy_json,
        host_id,
        node_id,
        containers: &converted,
        state_path,
        traffic_samples,
        sample_at,
        sample_interval_seconds,
        bridge_inventory,
    };
    reconcile_live(&req)
}

/// Read the last persisted `status` JSON object from `state_path`, or return the unconfigured default.
pub fn last_status_json(state_path: &Path) -> String {
    let state = read_state(state_path);
    match state.status {
        Some(val) if val.as_object().is_some() => val.to_json(),
        _ => ReconcileStatus::default().to_json(),
    }
}

// ---------------------------------------------------------------------------
// 13. Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn temp_dir(label: &str) -> PathBuf {
        let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!(
            "narwhal_tc_guard_{label}_{}_{seq}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    const HOST: &str = "node-a";
    const NODE: &str = "enrollment-a";

    fn base_policy_json() -> &'static str {
        r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","revision":1,"limits":[{"scope":"host","interface":"eth0","upload_mbps":50,"download_mbps":80}]}"#
    }

    #[derive(Default)]
    struct MockRunner {
        cmd_log: Vec<Vec<String>>,
        handler: Option<Box<dyn FnMut(&[&str], usize) -> (i32, String)>>,
        bins: HashMap<String, String>,
        ifindices: HashMap<String, Result<u32, String>>,
        netns: HashMap<u32, Result<u64, NetnsError>>,
        proc_stats: HashMap<u32, Result<String, String>>,
        texts: HashMap<PathBuf, String>,
        dirs: HashMap<PathBuf, Vec<String>>,
        links: HashMap<PathBuf, String>,
        now: u64,
    }

    impl MockRunner {
        fn new(now: u64) -> Self {
            Self {
                now,
                ..Default::default()
            }
        }
    }

    impl TcRunner for MockRunner {
        fn run_cmd(&mut self, args: &[&str], output_limit: usize) -> (i32, String) {
            self.cmd_log
                .push(args.iter().map(|s| (*s).to_string()).collect());
            if let Some(ref mut f) = self.handler {
                f(args, output_limit)
            } else {
                (1, "unmocked command".to_string())
            }
        }

        fn which(&mut self, binary: &str) -> Option<String> {
            self.bins.get(binary).cloned()
        }

        fn host_ifindex(&mut self, interface: &str) -> Result<u32, String> {
            self.ifindices
                .get(interface)
                .cloned()
                .unwrap_or_else(|| Err("not found".to_string()))
        }

        fn netns_inode(&mut self, pid: u32) -> Result<u64, NetnsError> {
            self.netns
                .get(&pid)
                .cloned()
                .unwrap_or(Err(NetnsError::NotFound))
        }

        fn read_proc_stat(&mut self, pid: u32) -> Result<String, String> {
            self.proc_stats
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| Err("not found".to_string()))
        }

        fn read_text(&mut self, path: &Path) -> std::io::Result<String> {
            self.texts.get(path).cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "mock file not found")
            })
        }

        fn list_dir(&mut self, path: &Path) -> std::io::Result<Vec<String>> {
            self.dirs.get(path).cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "mock dir not found")
            })
        }

        fn read_link_basename(&mut self, path: &Path) -> std::io::Result<String> {
            self.links.get(path).cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "mock symlink not found")
            })
        }

        fn now_unix(&self) -> u64 {
            self.now
        }
    }

    // --- 1. Policy validation tests ---

    #[test]
    fn test_validate_policy_accepts_valid_host_and_defaults_auto_throttle() {
        let p = validate_policy(base_policy_json(), HOST, NODE).expect("valid host policy");
        assert_eq!(p.schema, 1);
        assert_eq!(p.revision, 1);
        assert!(p.auto_throttle_enabled);
        assert_eq!(p.limits.len(), 1);
        assert_eq!(p.limits[0].scope, Scope::Host);
        assert_eq!(p.limits[0].interface, "eth0");
        assert_eq!(p.limits[0].upload_mbps, 50);
        assert_eq!(p.limits[0].download_mbps, 80);
    }

    #[test]
    fn test_validate_policy_rejects_identity_schema_and_rate_errors() {
        // Host/node mismatch
        let bad_node = r#"{"schema":1,"host_id":"node-a","expected_node_id":"other","limits":[]}"#;
        assert_eq!(
            validate_policy(bad_node, HOST, NODE).unwrap_err().message(),
            "bandwidth policy host identity mismatch"
        );
        // Schema != 1 (float 1.0 or 2 or bool)
        for bad_schema in [
            r#"{"schema":2,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[]}"#,
            r#"{"schema":1.0,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[]}"#,
            r#"{"schema":true,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[]}"#,
        ] {
            assert_eq!(
                validate_policy(bad_schema, HOST, NODE)
                    .unwrap_err()
                    .message(),
                "unsupported bandwidth policy"
            );
        }
        // Float rate 1.0 rejected (strict int check matching Python `type(v) is int`)
        let float_rate = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0","upload_mbps":1.0,"download_mbps":80}]}"#;
        assert_eq!(
            validate_policy(float_rate, HOST, NODE)
                .unwrap_err()
                .message(),
            "invalid rate"
        );
        // Bool rate rejected
        let bool_rate = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0","upload_mbps":true,"download_mbps":80}]}"#;
        assert_eq!(
            validate_policy(bool_rate, HOST, NODE)
                .unwrap_err()
                .message(),
            "invalid rate"
        );
        // Out of range (> 100_000 Mbps)
        let over_rate = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0","upload_mbps":100001,"download_mbps":0}]}"#;
        assert_eq!(
            validate_policy(over_rate, HOST, NODE)
                .unwrap_err()
                .message(),
            "rate is outside the supported range"
        );
        // Both zero
        let zero_rates = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0","upload_mbps":0,"download_mbps":0}]}"#;
        assert_eq!(
            validate_policy(zero_rates, HOST, NODE)
                .unwrap_err()
                .message(),
            "at least one direction needs a non-zero rate"
        );
    }

    #[test]
    fn test_validate_policy_limits_count_and_interfaces_and_runtimes() {
        // Max 256 policies
        let mut items = Vec::new();
        for i in 0..257 {
            items.push(format!(
                r#"{{"scope":"container","runtime":"podman","project":"","container_name":"c{i}","container_id":"id{i}","upload_mbps":10,"download_mbps":0}}"#
            ));
        }
        let too_many = format!(
            r#"{{"schema":1,"host_id":"{HOST}","expected_node_id":"{NODE}","limits":[{}]}}"#,
            items.join(",")
        );
        assert_eq!(
            validate_policy(&too_many, HOST, NODE)
                .unwrap_err()
                .message(),
            "invalid bandwidth policy list"
        );

        // Invalid host interface (> 15 chars or bad char)
        let bad_iface = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0_too_long_16","upload_mbps":10,"download_mbps":10}]}"#;
        assert_eq!(
            validate_policy(bad_iface, HOST, NODE)
                .unwrap_err()
                .message(),
            "invalid host interface"
        );

        // Reject unsupported runtime (`docker`)
        let bad_rt = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"container","runtime":"docker","project":"","container_name":"c1","container_id":"abc","upload_mbps":10,"download_mbps":0}],"auto_throttle":{"enabled":false}}"#;
        assert_eq!(
            validate_policy(bad_rt, HOST, NODE).unwrap_err().message(),
            "only Incus, Podman, and Runman containers can be limited"
        );

        // Accept incus, podman, runman
        for rt in ["incus", "podman", "runman"] {
            let ok_rt = format!(
                r#"{{"schema":1,"host_id":"{HOST}","expected_node_id":"{NODE}","limits":[{{"scope":"container","runtime":"{rt}","project":"default","container_name":"vm-1","container_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","upload_mbps":5,"download_mbps":10}}],"auto_throttle":{{"enabled":false}}}}"#
            );
            let parsed = validate_policy(&ok_rt, HOST, NODE).expect("supported runtime");
            assert_eq!(parsed.limits[0].runtime, rt);
        }

        // Duplicate target
        let dup = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0","upload_mbps":10,"download_mbps":0},{"scope":"host","interface":"eth0","upload_mbps":20,"download_mbps":0}]}"#;
        assert_eq!(
            validate_policy(dup, HOST, NODE).unwrap_err().message(),
            "duplicate bandwidth target"
        );

        // Multiple host interfaces
        let two_hosts = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0","upload_mbps":10,"download_mbps":0},{"scope":"host","interface":"eth1","upload_mbps":20,"download_mbps":0}]}"#;
        assert_eq!(
            validate_policy(two_hosts, HOST, NODE)
                .unwrap_err()
                .message(),
            "only one host interface can be configured"
        );

        // auto_throttle enabled requires 1 host limit
        let auto_no_host = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[],"auto_throttle":{"enabled":true}}"#;
        assert_eq!(
            validate_policy(auto_no_host, HOST, NODE)
                .unwrap_err()
                .message(),
            "automatic container limiting requires one host bandwidth interface"
        );
    }

    // --- 2. Handle determinism & /proc/stat parsing ---

    #[test]
    fn test_filter_handle_determinism_matches_python_sha256_contract() {
        assert_eq!(filter_handle("node-a:host:eth0", Direction::Download), "0x6f3bc15e");
        assert_eq!(filter_handle("node-a:host:eth0", Direction::Upload), "0x691d5461");
        assert_eq!(
            filter_handle_str("node-a:container:podman\0\0proxy\0abc123", "download"),
            "0x6ce74db8"
        );
        assert_ne!(
            filter_handle("node-a:host:eth0", Direction::Download),
            filter_handle("node-a:host:eth1", Direction::Download)
        );
    }

    #[test]
    fn test_parse_proc_start_ticks_handles_spaces_in_comm() {
        let mut parts = vec!["S"];
        parts.extend(std::iter::repeat("0").take(18));
        parts.push("987654");
        let stat = format!("12 (a process (with) spaces) {}", parts.join(" "));
        assert_eq!(parse_proc_start_ticks(&stat).unwrap(), "987654");
        assert!(parse_proc_start_ticks("12 malformed").is_err());
    }

    // --- 3. tc command generation & output parsing ---

    #[test]
    fn test_tc_command_generation_and_listing_parsing() {
        let cmd = build_tc_filter_command(
            &["nsenter".into(), "--target".into(), "42".into(), "--net".into()],
            "eth0",
            Direction::Download,
            "add",
            49150,
            "0x6f3bc15e",
            80,
        );
        assert_eq!(
            cmd,
            vec![
                "nsenter", "--target", "42", "--net", "tc", "filter", "add", "dev", "eth0",
                "ingress", "protocol", "all", "pref", "49150", "handle", "0x6f3bc15e",
                "matchall", "action", "police", "rate", "80mbit", "burst", "256k",
                "conform-exceed", "drop"
            ]
        );

        let upload_del =
            build_tc_filter_del_command(&[], "ens3", Direction::Upload, 49151, "0x691d5461");
        assert_eq!(
            upload_del,
            vec![
                "tc", "filter", "del", "dev", "ens3", "egress", "protocol", "all", "pref",
                "49151", "handle", "0x691d5461"
            ]
        );

        // Multi-filter tc output with foreign filter + owned filter
        let listing = "\
filter protocol all pref 49150 matchall chain 0 \n\
filter protocol all pref 49150 matchall chain 0 handle 0xdeadbeef \n\
  police 0x1 rate 100Mbit burst 256Kb mtu 2Kb action drop/pipe\n\
filter protocol all pref 49152 matchall chain 0 \n\
filter protocol all pref 49152 matchall chain 0 handle 0x6f3bc15e \n\
  police 0x2 rate 80Mbit burst 256Kb mtu 2Kb action drop/pipe\n";

        assert!(filter_present(listing, "0x6f3bc15e", 49152));
        assert!(!filter_present(listing, "0x6f3bc15e", 49150));
        assert_eq!(filter_preference(listing, "0x6f3bc15e"), Some(49152));
        assert_eq!(filter_preference(listing, "0x60000000"), None);
        assert!(filter_has_police_action(listing, "0x6f3bc15e", 49152, Some(80)));
        assert!(!filter_has_police_action(listing, "0x6f3bc15e", 49152, Some(50)));
        assert!(!filter_has_police_action(listing, "0x6f3bc15e", 49150, Some(100)));

        let occ = occupied_preferences(listing);
        assert!(occ.contains(&49150));
        assert!(occ.contains(&49152));
        assert_eq!(next_free_preference(listing, Direction::Download, None), 49151);
        assert_eq!(next_free_preference(listing, Direction::Upload, None), 49151);
    }

    #[test]
    fn test_parse_police_rate_units_and_precision() {
        let gbit = "filter protocol all pref 49150 matchall handle 0x6f3bc15e\n  police 0x1 rate 1Gbit burst 256Kb";
        assert!(filter_has_police_action(gbit, "0x6f3bc15e", 49150, Some(1000)));

        let kbit = "filter protocol all pref 49150 matchall handle 0x6f3bc15e\n  police 0x1 rate 1500Kbit/s burst 256Kb";
        let parsed = parse_police_rate_mbps(kbit).expect("parsed rate");
        assert!((parsed - 1.5).abs() < 1e-6);

        let bps = "filter protocol all pref 49150 matchall handle 0x6f3bc15e\n  police 0x1 rate 80Mbps burst 256Kb";
        assert!(filter_has_police_action(bps, "0x6f3bc15e", 49150, Some(80)));
        assert!(!filter_has_police_action(bps, "0x6f3bc15e", 49150, Some(81)));
    }

    #[test]
    fn test_apply_filter_retries_eexist_collision_and_verifies_readback() {
        let mut runner = MockRunner::new(1000);
        let handle = filter_handle("node-a:host:eth0", Direction::Download);
        let mut add_attempts = 0usize;
        let expected_handle = handle.clone();

        runner.handler = Some(Box::new(move |args, _| {
            if args == ["tc", "qdisc", "show", "dev", "eth0"] {
                return (0, "qdisc clsact ffff: parent ffff:fff1".to_string());
            }
            if args == ["tc", "filter", "show", "dev", "eth0", "ingress"] {
                return match add_attempts {
                    0 => (0, String::new()),
                    1 => (
                        0,
                        "filter protocol all pref 49150 matchall handle 0xdeadbeef\n  police 0x1 rate 100Mbit burst 256Kb"
                            .to_string(),
                    ),
                    _ => (
                        0,
                        format!(
                            "filter protocol all pref 49151 matchall handle {expected_handle}\n  police 0x1 rate 80Mbit burst 256Kb"
                        ),
                    ),
                };
            }
            if args[0] == "tc" && args[1] == "filter" && args[2] == "add" {
                add_attempts += 1;
                if add_attempts == 1 {
                    return (2, "Error: NLM_F_EXCL: File exists".to_string());
                }
                return (0, String::new());
            }
            (1, "unexpected".to_string())
        }));

        let pref = apply_filter(
            &[],
            "eth0",
            "node-a:host:eth0",
            Direction::Download,
            80,
            false,
            None,
            &mut runner,
        )
        .expect("retried to 49151");
        assert_eq!(pref, 49151);
        let adds = runner
            .cmd_log
            .iter()
            .filter(|c| c.get(2).map(String::as_str) == Some("add"))
            .count();
        assert_eq!(adds, 2);
    }

    #[test]
    fn test_apply_filter_refuses_unowned_existing_handle_and_handles_change_eexist() {
        let handle = filter_handle("node-a:host:eth0", Direction::Download);

        // 1. Existing handle when previously_owned == false -> refused
        let mut runner = MockRunner::new(1000);
        let h1 = handle.clone();
        runner.handler = Some(Box::new(move |args, _| {
            if args == ["tc", "qdisc", "show", "dev", "eth0"] {
                return (0, "qdisc clsact ffff:".to_string());
            }
            if args == ["tc", "filter", "show", "dev", "eth0", "ingress"] {
                return (
                    0,
                    format!("filter protocol all pref 49150 matchall handle {h1}\n  police 0x1 rate 80Mbit"),
                );
            }
            (1, "unexpected".into())
        }));
        let err = apply_filter(
            &[],
            "eth0",
            "node-a:host:eth0",
            Direction::Download,
            80,
            false,
            None,
            &mut runner,
        )
        .unwrap_err();
        assert_eq!(
            err.message(),
            "reserved filter identity already exists; left unchanged"
        );

        // 2. Owned handle updated via `tc filter change` returning EEXIST -> verified via readback
        let mut runner2 = MockRunner::new(1000);
        let h2 = handle.clone();
        runner2.handler = Some(Box::new(move |args, _| {
            if args == ["tc", "qdisc", "show", "dev", "eth0"] {
                return (0, "qdisc clsact ffff:".to_string());
            }
            if args == ["tc", "filter", "show", "dev", "eth0", "ingress"] {
                return (
                    0,
                    format!("filter protocol all pref 49150 matchall handle {h2}\n  police 0x1 rate 60Mbit"),
                );
            }
            if args[0] == "tc" && args[1] == "filter" && args[2] == "change" {
                return (2, "RTNETLINK answers: File exists".to_string());
            }
            (1, "unexpected".into())
        }));
        let pref = apply_filter(
            &[],
            "eth0",
            "node-a:host:eth0",
            Direction::Download,
            60,
            true,
            Some(49150),
            &mut runner2,
        )
        .expect("verified change EEXIST via readback");
        assert_eq!(pref, 49150);
    }

    // --- 4. Auto-throttle tier state machine & recovery ---

    #[test]
    fn test_auto_tier_rates_and_advance_direction_escalation_and_recovery() {
        assert_eq!(auto_tier_rates(100), vec![50, 25, 5, 1]);
        assert_eq!(auto_tier_rates(20), vec![10, 5, 1]);
        assert_eq!(auto_tier_rates(10), vec![5, 2, 1]);
        assert_eq!(auto_tier_rates(2), vec![1]);
        assert_eq!(auto_tier_rates(1), Vec::<u32>::new());
        assert_eq!(auto_tier_rates(100_000), vec![50_000, 25_000, 5_000, 1]);

        let mut rec = DirectionThrottleState::default();
        // Below 80% threshold (79 Mbps < 80 Mbps): stays at stage 0
        advance_direction(&mut rec, 100, 79.9, 1000, 300);
        assert_eq!(rec.stage, 0);
        assert_eq!(rec.high_seconds, 0);

        // First 200s >= 80%: accumulates high_seconds without triggering yet
        advance_direction(&mut rec, 100, 80.0, 1200, 200);
        assert_eq!(rec.stage, 0);
        assert_eq!(rec.high_seconds, 200);

        // Next 100s >= 80% -> 300s total -> triggers Stage 1 (50 Mbps)
        advance_direction(&mut rec, 100, 85.0, 1300, 100);
        assert_eq!(rec.stage, 1);
        assert_eq!(rec.high_seconds, 0);
        assert_eq!(rec.low_seconds, 0);

        // Sustained >= 80% of 50 (40 Mbps) for 300s -> Stage 2 (25 Mbps)
        advance_direction(&mut rec, 100, 42.0, 1600, 300);
        assert_eq!(rec.stage, 2);

        // Sustained >= 80% of 25 (20 Mbps) for 300s -> Stage 3 (5 Mbps)
        advance_direction(&mut rec, 100, 21.0, 1900, 300);
        assert_eq!(rec.stage, 3);

        // Sustained >= 80% of 5 (4 Mbps) for 300s -> Stage 4 (1 Mbps min)
        advance_direction(&mut rec, 100, 4.0, 2200, 300);
        assert_eq!(rec.stage, 4);

        // Dip to 0.4 Mbps (< 50% of 1 = 0.5 Mbps): needs 600s to step down
        advance_direction(&mut rec, 100, 0.4, 2500, 300);
        assert_eq!(rec.stage, 4);
        assert_eq!(rec.low_seconds, 300);

        // Spike to 0.6 Mbps resets low_seconds
        advance_direction(&mut rec, 100, 0.6, 2600, 100);
        assert_eq!(rec.stage, 4);
        assert_eq!(rec.low_seconds, 0);

        // Sustained 600s below recovery threshold steps back down 4 -> 3 -> 2 -> 1 -> 0
        advance_direction(&mut rec, 100, 0.2, 2900, 300);
        advance_direction(&mut rec, 100, 0.2, 3200, 300);
        assert_eq!(rec.stage, 3);
        advance_direction(&mut rec, 100, 1.0, 3800, 600);
        assert_eq!(rec.stage, 2);
        advance_direction(&mut rec, 100, 10.0, 4400, 600);
        assert_eq!(rec.stage, 1);
        advance_direction(&mut rec, 100, 20.0, 5000, 600);
        assert_eq!(rec.stage, 0);

        // Changing base_mbps resets stage cleanly
        advance_direction(&mut rec, 100, 90.0, 5300, 300);
        assert_eq!(rec.stage, 1);
        advance_direction(&mut rec, 200, 10.0, 5600, 300);
        assert_eq!(rec.stage, 0);
        assert_eq!(rec.base_mbps, Some(200));
    }

    // --- 5. Atomic JSON state persistence & last_status_json ---

    #[test]
    fn test_atomic_state_persistence_and_last_status_json() {
        let dir = temp_dir("state");
        let path = dir.join("nested").join("manual-bandwidth-limits.json");

        // Missing file -> unconfigured default
        let initial_status = last_status_json(&path);
        let parsed = JsonValue::parse(&initial_status).expect("valid json");
        assert_eq!(parsed.get("state").and_then(JsonValue::as_str), Some("unconfigured"));
        assert_eq!(parsed.get("revision").and_then(JsonValue::as_strict_i64), Some(0));

        // Corrupt file -> falls back cleanly
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{not-valid-json").unwrap();
        assert_eq!(read_state(&path).entries.len(), 0);

        // Wrong schema -> falls back cleanly
        fs::write(&path, r#"{"schema":2,"entries":{"a":{}}}"#).unwrap();
        assert_eq!(read_state(&path).entries.len(), 0);

        // Persist valid state & read back
        let mut st = BandwidthState::default();
        st.host_id = HOST.to_string();
        st.expected_node_id = NODE.to_string();
        st.revision = 7;
        st.status = Some(
            ReconcileStatus {
                revision: 7,
                state: "applied".to_string(),
                ..Default::default()
            }
            .to_json_val(),
        );
        write_state_atomic(&path, &st).expect("atomic write");
        let loaded = read_state(&path);
        assert_eq!(loaded.revision, 7);
        let status_after = JsonValue::parse(&last_status_json(&path)).unwrap();
        assert_eq!(status_after.get("state").and_then(JsonValue::as_str), Some("applied"));
        assert_eq!(status_after.get("revision").and_then(JsonValue::as_strict_i64), Some(7));

        #[cfg(unix)]
        {
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    // --- 6. End-to-end reconcile_with_runner & reconcile_live tests ---

    #[test]
    fn test_reconcile_apply_update_remove_host_only_uses_owned_filters() {
        let dir = temp_dir("host_apply_remove");
        let state_path = dir.join("state.json");
        let mut runner = MockRunner::new(2000);
        runner.ifindices.insert("eth0".to_string(), Ok(2));

        let dl_handle = filter_handle("node-a:host:eth0", Direction::Download);
        let ul_handle = filter_handle("node-a:host:eth0", Direction::Upload);

        let mut ingress_listing = String::new();
        let mut egress_listing = String::new();
        let mut has_clsact = false;

        let dl_h = dl_handle.clone();
        let ul_h = ul_handle.clone();
        let state_ref = std::cell::RefCell::new((has_clsact, ingress_listing.clone(), egress_listing.clone()));

        runner.handler = Some(Box::new(move |args, _| {
            let mut s = state_ref.borrow_mut();
            if args == ["tc", "qdisc", "show", "dev", "eth0"] {
                return if s.0 {
                    (0, "qdisc clsact ffff:".to_string())
                } else {
                    (0, "qdisc noqueue 0: root".to_string())
                };
            }
            if args == ["tc", "qdisc", "add", "dev", "eth0", "clsact"] {
                s.0 = true;
                return (0, String::new());
            }
            if args == ["tc", "filter", "show", "dev", "eth0", "ingress"] {
                return (0, s.1.clone());
            }
            if args == ["tc", "filter", "show", "dev", "eth0", "egress"] {
                return (0, s.2.clone());
            }
            if args.len() >= 16 && args[0] == "tc" && args[1] == "filter" && (args[2] == "add" || args[2] == "change") {
                let dir = args[5];
                let pref = args[9];
                let handle = args[11];
                let rate = args[16];
                let block = format!("filter protocol all pref {pref} matchall handle {handle}\n  police 0x1 rate {rate} burst 256Kb\n");
                if dir == "ingress" {
                    assert_eq!(handle, dl_h);
                    s.1 = block;
                } else {
                    assert_eq!(handle, ul_h);
                    s.2 = block;
                }
                return (0, String::new());
            }
            if args.len() >= 12 && args[0] == "tc" && args[1] == "filter" && args[2] == "del" {
                let dir = args[5];
                if dir == "ingress" {
                    s.1.clear();
                } else {
                    s.2.clear();
                }
                return (0, String::new());
            }
            (1, format!("unexpected command: {args:?}"))
        }));
        let _ = (&mut has_clsact, &mut ingress_listing, &mut egress_listing);

        let policy_no_auto = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","revision":1,"limits":[{"scope":"host","interface":"eth0","upload_mbps":50,"download_mbps":80}],"auto_throttle":{"enabled":false}}"#;
        let res = reconcile_with_runner(
            &ReconcileRequest {
                policy_json: policy_no_auto,
                host_id: HOST,
                node_id: NODE,
                containers: &[],
                state_path: &state_path,
                traffic_samples: &[],
                sample_at: 0,
                sample_interval_seconds: 300,
                bridge_inventory: &[],
            },
            &mut runner,
        );
        assert_eq!(res.state, "applied");
        assert_eq!(res.items.len(), 2);
        let active = res.active_limits.as_ref().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].upload_mbps, 50);
        assert_eq!(active[0].download_mbps, 80);

        // Verify persisted JSON
        let saved = read_state(&state_path);
        assert_eq!(saved.entries["host:eth0"].directions, vec!["download", "upload"]);

        // Now clear limits -> removes only owned filters and becomes unconfigured
        let empty_policy = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","revision":2,"limits":[]}"#;
        let res2 = reconcile_with_runner(
            &ReconcileRequest {
                policy_json: empty_policy,
                host_id: HOST,
                node_id: NODE,
                containers: &[],
                state_path: &state_path,
                traffic_samples: &[],
                sample_at: 0,
                sample_interval_seconds: 300,
                bridge_inventory: &[],
            },
            &mut runner,
        );
        assert_eq!(res2.state, "unconfigured");
        assert!(read_state(&state_path).entries.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reconcile_container_rejects_shared_netns_and_applies_isolated_runman() {
        let dir = temp_dir("container_isolation");
        let state_path = dir.join("state.json");
        let vm_id = "11111111-2222-3333-4444-555555555555";
        let gen1 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let gen2 = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";

        let policy = format!(
            r#"{{"schema":1,"host_id":"{HOST}","expected_node_id":"{NODE}","revision":1,"limits":[{{"scope":"container","runtime":"runman","project":"default","container_name":"{vm_id}","container_id":"{gen1}","upload_mbps":5,"download_mbps":10}}],"auto_throttle":{{"enabled":false}}}}"#
        );

        let mut runner = MockRunner::new(3000);
        runner.netns.insert(1, Ok(1));
        runner.netns.insert(42, Ok(42));
        runner.netns.insert(43, Ok(42)); // shares netns 42!
        runner.proc_stats.insert(
            42,
            Ok(format!("42 (vm) S {} 987654", vec!["0"; 18].join(" "))),
        );

        let shared_containers = vec![
            ContainerInput {
                runtime: "runman".into(),
                runtime_bin: "runman".into(),
                project: "default".into(),
                name: vm_id.into(),
                id: vm_id.into(),
                instance_id: gen1.into(),
                status: "running".into(),
                pid: Some(42),
            },
            ContainerInput {
                runtime: "runman".into(),
                runtime_bin: "runman".into(),
                project: "default".into(),
                name: "other-vm".into(),
                id: "other-vm".into(),
                instance_id: gen2.into(),
                status: "running".into(),
                pid: Some(43),
            },
        ];

        let fail_res = reconcile_with_runner(
            &ReconcileRequest {
                policy_json: &policy,
                host_id: HOST,
                node_id: NODE,
                containers: &shared_containers,
                state_path: &state_path,
                traffic_samples: &[],
                sample_at: 0,
                sample_interval_seconds: 300,
                bridge_inventory: &[],
            },
            &mut runner,
        );
        assert_eq!(fail_res.state, "failed");
        assert!(fail_res.items[0]
            .message
            .as_deref()
            .unwrap()
            .contains("shared container network namespace"));
        assert!(runner.cmd_log.is_empty());

        // Now isolate peer 43 onto netns 43 and verify tc is applied inside container netns
        runner.netns.insert(43, Ok(43));
        let owner_key = format!("{HOST}:container:runman\0default\0{vm_id}\0{gen1}");
        let dl_h = filter_handle(&owner_key, Direction::Download);
        let ul_h = filter_handle(&owner_key, Direction::Upload);
        let tc_state = std::cell::RefCell::new((false, String::new(), String::new()));

        runner.handler = Some(Box::new(move |args, _| {
            let mut s = tc_state.borrow_mut();
            if args == ["nsenter", "--target", "42", "--net", "ip", "-j", "route", "show", "default"] {
                return (0, r#"[{"dev":"eth0"}]"#.to_string());
            }
            if args == ["nsenter", "--target", "42", "--net", "ip", "-j", "link", "show", "dev", "eth0"] {
                return (0, r#"[{"ifindex":2,"link_index":7}]"#.to_string());
            }
            if args == ["nsenter", "--target", "42", "--net", "tc", "qdisc", "show", "dev", "eth0"] {
                return (0, if s.0 { "qdisc clsact".into() } else { "qdisc noqueue".into() });
            }
            if args == ["nsenter", "--target", "42", "--net", "tc", "qdisc", "add", "dev", "eth0", "clsact"] {
                s.0 = true;
                return (0, String::new());
            }
            if args == ["nsenter", "--target", "42", "--net", "tc", "filter", "show", "dev", "eth0", "ingress"] {
                return (0, s.1.clone());
            }
            if args == ["nsenter", "--target", "42", "--net", "tc", "filter", "show", "dev", "eth0", "egress"] {
                return (0, s.2.clone());
            }
            if args.len() >= 20 && args[4] == "tc" && args[5] == "filter" && args[6] == "add" {
                let dir = args[9];
                let pref = args[13];
                let handle = args[15];
                let rate = args[20];
                let block = format!("filter protocol all pref {pref} matchall handle {handle}\n  police 0x1 rate {rate} burst 256Kb\n");
                if dir == "ingress" {
                    assert_eq!(handle, dl_h);
                    s.1 = block;
                } else {
                    assert_eq!(handle, ul_h);
                    s.2 = block;
                }
                return (0, String::new());
            }
            (1, format!("unexpected: {args:?}"))
        }));

        let ok_res = reconcile_with_runner(
            &ReconcileRequest {
                policy_json: &policy,
                host_id: HOST,
                node_id: NODE,
                containers: &shared_containers,
                state_path: &state_path,
                traffic_samples: &[],
                sample_at: 0,
                sample_interval_seconds: 300,
                bridge_inventory: &[],
            },
            &mut runner,
        );
        assert_eq!(ok_res.state, "applied");
        assert_eq!(ok_res.items.len(), 2);
        assert_eq!(ok_res.active_limits.as_ref().unwrap()[0].download_mbps, 10);
        assert_eq!(ok_res.active_limits.as_ref().unwrap()[0].upload_mbps, 5);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reconcile_auto_throttle_maps_runman_bridge_and_applies_tier1() {
        let dir = temp_dir("auto_bridge");
        let state_path = dir.join("state.json");
        let vm_id = "11111111-2222-3333-4444-555555555555";
        let gen1 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

        let policy = format!(
            r#"{{"schema":1,"host_id":"{HOST}","expected_node_id":"{NODE}","revision":1,"limits":[{{"scope":"host","interface":"eth0","upload_mbps":20,"download_mbps":20}}],"auto_throttle":{{"enabled":true}}}}"#
        );
        let containers = vec![ContainerInput {
            runtime: "runman".into(),
            runtime_bin: "runman".into(),
            project: "default".into(),
            name: vm_id.into(),
            id: vm_id.into(),
            instance_id: gen1.into(),
            status: "running".into(),
            pid: Some(42),
        }];
        let samples = vec![TrafficSampleInput {
            runtime: "runman".into(),
            project: "default".into(),
            container_name: vm_id.into(),
            container_id: gen1.into(),
            traffic_counters_available: true,
            net_tx_bps: Some(3_000_000.0), // 24 Mbps >= 80% of 20 Mbps
            net_rx_bps: Some(0.0),
        }];
        let bridges = vec![BridgeInterfaceInput {
            name: "rmbr0".into(),
            kind: "bridge".into(),
            runtimes: vec!["runman".into()],
        }];

        let mut runner = MockRunner::new(1000);
        runner.ifindices.insert("eth0".into(), Ok(2));
        runner.netns.insert(1, Ok(1));
        runner.netns.insert(42, Ok(42));
        runner.proc_stats.insert(
            42,
            Ok(format!("42 (vm) S {} 987654", vec!["0"; 18].join(" "))),
        );

        let tc_map = std::cell::RefCell::new(HashMap::<String, String>::new());
        runner.handler = Some(Box::new(move |args, _| {
            if args == ["ip", "-j", "link", "show"] {
                return (
                    0,
                    r#"[{"ifindex":2,"ifname":"eth0"},{"ifindex":7,"ifname":"rv1","master":"rmbr0"}]"#
                        .to_string(),
                );
            }
            if args == ["ip", "-j", "route", "show", "default"] {
                return (0, r#"[{"dev":"eth0"}]"#.to_string());
            }
            if args == ["nsenter", "--target", "42", "--net", "ip", "-j", "route", "show", "default"] {
                return (0, r#"[{"dev":"eth0"}]"#.to_string());
            }
            if args == ["nsenter", "--target", "42", "--net", "ip", "-j", "link", "show", "dev", "eth0"] {
                return (0, r#"[{"ifindex":3,"link_index":7}]"#.to_string());
            }
            if args.ends_with(&["tc", "qdisc", "show", "dev", "eth0"]) {
                return (0, "qdisc clsact ffff:".to_string());
            }
            if args.len() >= 6 && args.contains(&"filter") && args.contains(&"show") {
                let key = args.join(" ");
                return (0, tc_map.borrow().get(&key).cloned().unwrap_or_default());
            }
            if let Some(pos) = args.iter().position(|&x| x == "add") {
                if pos > 0 && args[pos - 1] == "filter" {
                    let dev = args[pos + 2];
                    let dir = args[pos + 3];
                    let pref = args[pos + 7];
                    let handle = args[pos + 9];
                    let rate = args[pos + 14];
                    let show_key = if args[0] == "nsenter" {
                        format!("nsenter --target 42 --net tc filter show dev {dev} {dir}")
                    } else {
                        format!("tc filter show dev {dev} {dir}")
                    };
                    tc_map.borrow_mut().insert(
                        show_key,
                        format!("filter protocol all pref {pref} matchall handle {handle}\n  police 0x1 rate {rate} burst 256Kb\n"),
                    );
                    return (0, String::new());
                }
            }
            (1, format!("unexpected: {args:?}"))
        }));

        let res = reconcile_with_runner(
            &ReconcileRequest {
                policy_json: &policy,
                host_id: HOST,
                node_id: NODE,
                containers: &containers,
                state_path: &state_path,
                traffic_samples: &samples,
                sample_at: 1000,
                sample_interval_seconds: 300,
                bridge_inventory: &bridges,
            },
            &mut runner,
        );
        assert_eq!(res.state, "applied");
        let auto = res.auto_throttle.as_ref().unwrap();
        assert_eq!(auto.state, "limited");
        assert_eq!(auto.mapped_containers, Some(1));
        assert_eq!(auto.items[0].container_id, gen1);
        assert_eq!(auto.items[0].upload_mbps, 10);

        let container_active = res
            .active_limits
            .as_ref()
            .unwrap()
            .iter()
            .find(|a| a.scope == "container")
            .expect("auto container limit applied");
        assert_eq!(container_active.upload_mbps, 10);
        assert_eq!(container_active.download_mbps, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reconcile_partial_cleanup_failure_rolls_back_and_blocks_replacement() {
        let dir = temp_dir("partial_cleanup");
        let state_path = dir.join("state.json");

        // Pre-populate state with an owned host:eth0 filter at interface_index 2
        let mut init_state = BandwidthState::default();
        init_state.host_id = HOST.to_string();
        init_state.expected_node_id = NODE.to_string();
        let mut rates = BTreeMap::new();
        rates.insert("download".into(), 80);
        rates.insert("upload".into(), 50);
        let mut prefs = BTreeMap::new();
        prefs.insert("download".into(), 49150);
        prefs.insert("upload".into(), 49151);
        let mut confirmed = BTreeMap::new();
        confirmed.insert("download".into(), 100);
        confirmed.insert("upload".into(), 100);
        init_state.entries.insert(
            "host:eth0".into(),
            StoredEntry {
                key: "host:eth0".into(),
                owner_key: "node-a:host:eth0".into(),
                expected_node_id: NODE.into(),
                scope: "host".into(),
                interface: "eth0".into(),
                interface_index: 2,
                namespace_inode: "host".into(),
                directions: vec!["download".into(), "upload".into()],
                rates_mbps: rates,
                filter_prefs: prefs,
                confirmed_at: confirmed,
                last_confirmed_at: 100,
                ..Default::default()
            },
        );
        write_state_atomic(&state_path, &init_state).unwrap();

        let dl_handle = filter_handle("node-a:host:eth0", Direction::Download);
        let ul_handle = filter_handle("node-a:host:eth0", Direction::Upload);

        let mut runner = MockRunner::new(2000);
        runner.ifindices.insert("eth0".into(), Ok(2));

        let mut script = VecDeque::from(vec![
            // remove download: show ingress (present), del ingress (ok), show ingress (gone)
            (0, format!("filter protocol all pref 49150 matchall handle {dl_handle}\n  police 0x1 rate 80Mbit")),
            (0, String::new()),
            (0, String::new()),
            // remove upload: show egress (present), del egress (fails!)
            (0, format!("filter protocol all pref 49151 matchall handle {ul_handle}\n  police 0x1 rate 50Mbit")),
            (1, "second direction failed".to_string()),
            // rollback download: qdisc show, filter show ingress (empty), filter add ingress (ok), filter show ingress (readback 80Mbit)
            (0, "qdisc clsact ffff:".to_string()),
            (0, String::new()),
            (0, String::new()),
            (0, format!("filter protocol all pref 49150 matchall handle {dl_handle}\n  police 0x1 rate 80Mbit")),
        ]);
        runner.handler = Some(Box::new(move |_, _| {
            script.pop_front().unwrap_or((1, "exhausted".into()))
        }));

        let empty_policy = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","revision":2,"limits":[]}"#;
        let res = reconcile_with_runner(
            &ReconcileRequest {
                policy_json: empty_policy,
                host_id: HOST,
                node_id: NODE,
                containers: &[],
                state_path: &state_path,
                traffic_samples: &[],
                sample_at: 0,
                sample_interval_seconds: 300,
                bridge_inventory: &[],
            },
            &mut runner,
        );
        assert_eq!(res.state, "failed");
        let rb = res.rollback.as_ref().unwrap();
        assert_eq!(rb.state, "verified");
        assert!(rb.attempted);
        assert_eq!(rb.results.as_ref().unwrap()[0].direction, "cleanup");
        assert!(read_state(&state_path).entries.contains_key("host:eth0"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reconcile_live_rejects_invalid_policy_without_touching_state() {
        let dir = temp_dir("live_reject");
        let state_path = dir.join("missing.json");
        let res = reconcile_live(&ReconcileRequest {
            policy_json: r#"{"schema":1,"host_id":"other","expected_node_id":"enrollment-a","limits":[]}"#,
            host_id: HOST,
            node_id: NODE,
            containers: &[],
            state_path: &state_path,
            traffic_samples: &[],
            sample_at: 0,
            sample_interval_seconds: 300,
            bridge_inventory: &[],
        });
        assert_eq!(res.state, "rejected");
        assert!(!state_path.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_merge_automatic_limits_respects_stricter_cap() {
        let manual = vec![NormalizedLimit {
            scope: Scope::Container,
            interface: String::new(),
            runtime: "podman".into(),
            project: "".into(),
            container_name: "c1".into(),
            container_id: "id1".into(),
            upload_mbps: 15,
            download_mbps: 40,
        }];
        let auto = vec![
            NormalizedLimit {
                scope: Scope::Container,
                interface: String::new(),
                runtime: "podman".into(),
                project: "".into(),
                container_name: "c1".into(),
                container_id: "id1".into(),
                upload_mbps: 20, // manual 15 is stricter
                download_mbps: 10, // auto 10 is stricter
            },
            NormalizedLimit {
                scope: Scope::Container,
                interface: String::new(),
                runtime: "incus".into(),
                project: "default".into(),
                container_name: "c2".into(),
                container_id: "c2".into(),
                upload_mbps: 5,
                download_mbps: 0,
            },
        ];
        let merged = merge_automatic_limits(&manual, &auto);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].upload_mbps, 15);
        assert_eq!(merged[0].download_mbps, 10);
        assert_eq!(merged[1].container_name, "c2");
        assert_eq!(merged[1].upload_mbps, 5);
    }

    #[test]
    fn test_sysfs_and_proc_route_fallbacks() {
        let mut runner = MockRunner::new(1000);
        runner.dirs.insert(
            PathBuf::from("/sys/class/net"),
            vec!["eth0".into(), "rv1".into(), "..".into()],
        );
        runner
            .texts
            .insert(PathBuf::from("/sys/class/net/eth0/ifindex"), "2\n".into());
        runner
            .texts
            .insert(PathBuf::from("/sys/class/net/rv1/ifindex"), "7\n".into());
        runner
            .links
            .insert(PathBuf::from("/sys/class/net/rv1/master"), "rmbr0".into());
        runner.texts.insert(
            PathBuf::from("/proc/net/route"),
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t01010101\t0003\t0\t0\t100\t00000000\n".into(),
        );
        runner.texts.insert(
            PathBuf::from("/proc/net/ipv6_route"),
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000064 00000000 00000000 00000003 eth1\n".into(),
        );

        let (links, defaults, err) = host_link_snapshot(&mut runner);
        assert!(err.is_empty());
        assert_eq!(links.get(&2).unwrap().ifname, "eth0");
        assert_eq!(links.get(&7).unwrap().master_name, "rmbr0");
        assert!(defaults.contains("eth0"));
        assert!(defaults.contains("eth1"));
    }

    #[test]
    fn test_runman_identity_and_container_sample_conversion() {
        let vm_id = "11111111-2222-3333-4444-555555555555";
        let gen1 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let sample = ContainerSample {
            id: vm_id.into(),
            stable_id: vm_id.into(),
            name: vm_id.into(),
            image: "ubuntu".into(),
            runtime: "runman".into(),
            runtime_bin: "runman".into(),
            project: "default".into(),
            pid: Some(42),
            status: "running".into(),
            instance_id: gen1.into(),
            network_addresses: vec![],
            pid_metrics_json: None,
            socket_tables_json: None,
            cgroup_metrics_json: None,
        };
        let converted = ContainerInput::from(&sample);
        assert_eq!(
            converted.identity(),
            (
                "runman".into(),
                "default".into(),
                vm_id.into(),
                gen1.into()
            )
        );
    }

    #[test]
    fn test_running_container_inventory_incus_podman_and_runman_strict() {
        let mut runner = MockRunner::new(1000);
        // Runman alone needs no external binary
        let runman_ok = vec![ContainerInput {
            runtime: "runman".into(),
            runtime_bin: "runman".into(),
            project: "default".into(),
            name: "vm".into(),
            id: "vm".into(),
            instance_id: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".into(),
            status: "running".into(),
            pid: Some(42),
        }];
        let peers = running_container_inventory(&runman_ok, &mut runner).expect("runman peer");
        assert_eq!(
            peers,
            vec![PeerEntry {
                runtime: "runman".into(),
                project: "default".into(),
                container_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                pid: 42,
            }]
        );

        let mut runman_bad = runman_ok.clone();
        runman_bad[0].pid = None;
        let err = running_container_inventory(&runman_bad, &mut runner).unwrap_err();
        assert!(err.message().contains("inventory is incomplete"));

        // Incus CSV + Podman ps/inspect
        let pod_id = "a".repeat(64);
        let pod_id_clone = pod_id.clone();
        let mut mixed_runner = MockRunner::new(1000);
        mixed_runner.bins.insert("incus".into(), "/usr/bin/incus".into());
        mixed_runner.bins.insert("podman".into(), "/usr/bin/podman".into());
        mixed_runner.handler = Some(Box::new(move |args, _| {
            if args == [
                "/usr/bin/incus",
                "list",
                "--all-projects",
                "type=container",
                "status=running",
                "--format=csv",
                "--columns=nepst",
            ] {
                return (0, "web,prod,55,RUNNING,CONTAINER\n".to_string());
            }
            if args == ["/usr/bin/podman", "ps", "--no-trunc", "--format", "{{.ID}}"] {
                return (0, pod_id_clone.clone());
            }
            if args[0] == "/usr/bin/podman" && args[1] == "inspect" {
                return (0, format!("{pod_id_clone}|66"));
            }
            (1, "unexpected".into())
        }));

        let mixed = running_container_inventory(&[], &mut mixed_runner).expect("mixed peers");
        assert_eq!(mixed.len(), 2);
        assert_eq!(mixed[0].runtime, "incus");
        assert_eq!(mixed[0].pid, 55);
        assert_eq!(mixed[1].runtime, "podman");
        assert_eq!(mixed[1].pid, 66);

        // Malformed Incus row rejected
        let mut bad_incus = MockRunner::new(1000);
        bad_incus.bins.insert("incus".into(), "/usr/bin/incus".into());
        bad_incus.handler = Some(Box::new(|_, _| {
            (0, "c1,other,43,STOPPED,CONTAINER\n".to_string())
        }));
        let err2 = running_container_inventory(&[], &mut bad_incus).unwrap_err();
        assert!(err2.message().contains("Incus inventory could not be verified"));
    }

    #[test]
    fn test_podman_pid_fallback_and_container_isolation_errors() {
        let mut runner = MockRunner::new(1000);
        let item = NormalizedLimit {
            scope: Scope::Container,
            interface: String::new(),
            runtime: "podman".into(),
            project: String::new(),
            container_name: "proxy".into(),
            container_id: "abc123".into(),
            upload_mbps: 5,
            download_mbps: 10,
        };
        let matched = ContainerInput {
            runtime: "podman".into(),
            runtime_bin: "podman".into(),
            project: String::new(),
            name: "proxy".into(),
            id: "abc123".into(),
            instance_id: String::new(),
            status: "running".into(),
            pid: None,
        };
        runner.handler = Some(Box::new(|_, _| (0, "abc123456789|42".to_string())));
        assert_eq!(container_process_pid(&item, &matched, &mut runner).unwrap(), 42);

        runner.handler = Some(Box::new(|_, _| (0, "def456789abc|42".to_string())));
        assert!(container_process_pid(&item, &matched, &mut runner).is_err());

        // Host network namespace rejected before running tc
        let dir = temp_dir("host_netns_reject");
        let state_path = dir.join("state.json");
        let pod_id = "a".repeat(64);
        let policy = format!(
            r#"{{"schema":1,"host_id":"{HOST}","expected_node_id":"{NODE}","revision":1,"limits":[{{"scope":"container","runtime":"podman","project":"","container_name":"proxy","container_id":"{pod_id}","upload_mbps":5,"download_mbps":10}}],"auto_throttle":{{"enabled":false}}}}"#
        );
        let containers = vec![ContainerInput {
            runtime: "podman".into(),
            runtime_bin: "podman".into(),
            project: String::new(),
            name: "proxy".into(),
            id: pod_id.clone(),
            instance_id: String::new(),
            status: "running".into(),
            pid: Some(42),
        }];

        let mut host_ns_runner = MockRunner::new(1000);
        host_ns_runner.bins.insert("podman".into(), "/usr/bin/podman".into());
        host_ns_runner.netns.insert(1, Ok(1));
        host_ns_runner.netns.insert(42, Ok(1)); // same as host!
        host_ns_runner.proc_stats.insert(
            42,
            Ok(format!("42 (pod) S {} 12345", vec!["0"; 18].join(" "))),
        );
        let pod_clone = pod_id.clone();
        host_ns_runner.handler = Some(Box::new(move |args, _| {
            if args[1] == "ps" {
                return (0, pod_clone.clone());
            }
            if args[1] == "inspect" {
                return (0, format!("{pod_clone}|42"));
            }
            (1, "unexpected".into())
        }));
        let res = reconcile_with_runner(
            &ReconcileRequest {
                policy_json: &policy,
                host_id: HOST,
                node_id: NODE,
                containers: &containers,
                state_path: &state_path,
                traffic_samples: &[],
                sample_at: 0,
                sample_interval_seconds: 300,
                bridge_inventory: &[],
            },
            &mut host_ns_runner,
        );
        assert_eq!(res.state, "failed");
        assert!(res.items[0]
            .message
            .as_deref()
            .unwrap()
            .contains("host network namespace"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reconcile_temporary_target_failure_preserves_existing_limit() {
        let dir = temp_dir("preserve_existing");
        let state_path = dir.join("state.json");
        let mut init_state = BandwidthState::default();
        init_state.host_id = HOST.into();
        init_state.expected_node_id = NODE.into();
        let mut rates = BTreeMap::new();
        rates.insert("download".into(), 80);
        init_state.entries.insert(
            "host:eth0".into(),
            StoredEntry {
                key: "host:eth0".into(),
                owner_key: "node-a:host:eth0".into(),
                expected_node_id: NODE.into(),
                scope: "host".into(),
                interface: "eth0".into(),
                interface_index: 2,
                namespace_inode: "host".into(),
                directions: vec!["download".into()],
                rates_mbps: rates,
                ..Default::default()
            },
        );
        write_state_atomic(&state_path, &init_state).unwrap();

        // eth0 temporarily unresolvable -> host_ifindex fails
        let mut runner = MockRunner::new(2000);
        let res = reconcile_with_runner(
            &ReconcileRequest {
                policy_json: base_policy_json(),
                host_id: HOST,
                node_id: NODE,
                containers: &[],
                state_path: &state_path,
                traffic_samples: &[],
                sample_at: 0,
                sample_interval_seconds: 300,
                bridge_inventory: &[],
            },
            &mut runner,
        );
        assert_eq!(res.state, "failed");
        assert!(runner.cmd_log.is_empty());
        assert!(read_state(&state_path).entries.contains_key("host:eth0"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reconcile_state_write_failure_rolls_back_new_filters() {
        let dir = temp_dir("write_fail_rb");
        // Using an existing directory as state_path forces write_state_atomic rename to fail cross-platform
        let state_path_dir = dir.join("state_is_dir");
        fs::create_dir_all(&state_path_dir).unwrap();

        let mut runner = MockRunner::new(2000);
        runner.ifindices.insert("eth0".into(), Ok(2));
        let dl_h = filter_handle("node-a:host:eth0", Direction::Download);
        let ul_h = filter_handle("node-a:host:eth0", Direction::Upload);
        let tc_state = std::cell::RefCell::new((false, String::new(), String::new()));

        runner.handler = Some(Box::new(move |args, _| {
            let mut s = tc_state.borrow_mut();
            if args == ["tc", "qdisc", "show", "dev", "eth0"] {
                return (0, if s.0 { "qdisc clsact".into() } else { "qdisc noqueue".into() });
            }
            if args == ["tc", "qdisc", "add", "dev", "eth0", "clsact"] {
                s.0 = true;
                return (0, String::new());
            }
            if args == ["tc", "filter", "show", "dev", "eth0", "ingress"] {
                return (0, s.1.clone());
            }
            if args == ["tc", "filter", "show", "dev", "eth0", "egress"] {
                return (0, s.2.clone());
            }
            if args.len() >= 16 && args[0] == "tc" && args[1] == "filter" && args[2] == "add" {
                let dir = args[5];
                let pref = args[9];
                let handle = args[11];
                let rate = args[16];
                let block = format!("filter protocol all pref {pref} matchall handle {handle}\n  police 0x1 rate {rate} burst 256Kb\n");
                if dir == "ingress" {
                    assert_eq!(handle, dl_h);
                    s.1 = block;
                } else {
                    assert_eq!(handle, ul_h);
                    s.2 = block;
                }
                return (0, String::new());
            }
            if args.len() >= 12 && args[0] == "tc" && args[1] == "filter" && args[2] == "del" {
                let dir = args[5];
                if dir == "ingress" {
                    s.1.clear();
                } else {
                    s.2.clear();
                }
                return (0, String::new());
            }
            (1, format!("unexpected: {args:?}"))
        }));

        let policy_no_auto = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","revision":1,"limits":[{"scope":"host","interface":"eth0","upload_mbps":50,"download_mbps":80}],"auto_throttle":{"enabled":false}}"#;
        let res = reconcile_with_runner(
            &ReconcileRequest {
                policy_json: policy_no_auto,
                host_id: HOST,
                node_id: NODE,
                containers: &[],
                state_path: &state_path_dir,
                traffic_samples: &[],
                sample_at: 0,
                sample_interval_seconds: 300,
                bridge_inventory: &[],
            },
            &mut runner,
        );
        assert_eq!(res.state, "failed");
        let rb = res.rollback.as_ref().unwrap();
        assert_eq!(rb.state, "verified");
        assert!(rb.attempted);
        assert_eq!(rb.restored, Some(2));
        assert!(res.message.as_deref().unwrap().contains("本地 tc 所有权状态保存失败"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reconcile_unverified_old_cleanup_blocks_replacing_same_target() {
        let dir = temp_dir("block_replace");
        let state_path = dir.join("state.json");
        let mut init_state = BandwidthState::default();
        init_state.host_id = HOST.into();
        init_state.expected_node_id = NODE.into();
        let mut rates = BTreeMap::new();
        rates.insert("download".into(), 80);
        let mut prefs = BTreeMap::new();
        prefs.insert("download".into(), 49150);
        let mut confirmed = BTreeMap::new();
        confirmed.insert("download".into(), 100);
        // Stored entry has invalid interface_index=0 so removal cannot verify disappeared interface
        init_state.entries.insert(
            "host:eth0".into(),
            StoredEntry {
                key: "host:eth0".into(),
                owner_key: "node-a:host:eth0".into(),
                expected_node_id: NODE.into(),
                scope: "host".into(),
                interface: "eth0".into(),
                interface_index: 0,
                namespace_inode: "host".into(),
                directions: vec!["download".into()],
                rates_mbps: rates,
                filter_prefs: prefs,
                confirmed_at: confirmed,
                last_confirmed_at: 100,
                ..Default::default()
            },
        );
        write_state_atomic(&state_path, &init_state).unwrap();

        // First call: ifindex fails -> preserve; instead make host_ifindex succeed with index 3,
        // wait: if host_ifindex succeeds with 3 != 0, remove_entry assumes old device disappeared!
        // Use a container entry whose netns_inode is Unavailable during cleanup to block replacement:
        let vm_id = "11111111-2222-3333-4444-555555555555";
        let gen1 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let key = format!("container:runman\0default\0{vm_id}\0{gen1}");
        init_state.entries.clear();
        init_state.entries.insert(
            key.clone(),
            StoredEntry {
                key: key.clone(),
                owner_key: format!("{HOST}:{key}"),
                expected_node_id: NODE.into(),
                scope: "container".into(),
                runtime: "runman".into(),
                project: "default".into(),
                container_name: vm_id.into(),
                container_id: gen1.into(),
                prefix: vec!["nsenter".into(), "--target".into(), "99".into(), "--net".into()],
                pid: 99, // old dead/unreadable pid with Unavailable error
                interface: "eth0".into(),
                interface_index: 2,
                namespace_inode: "99".into(),
                directions: vec!["download".into()],
                rates_mbps: BTreeMap::from([("download".into(), 80)]),
                filter_prefs: BTreeMap::from([("download".into(), 49150)]),
                confirmed_at: BTreeMap::from([("download".into(), 100)]),
                last_confirmed_at: 100,
                ..Default::default()
            },
        );
        write_state_atomic(&state_path, &init_state).unwrap();

        let policy = format!(
            r#"{{"schema":1,"host_id":"{HOST}","expected_node_id":"{NODE}","revision":2,"limits":[{{"scope":"container","runtime":"runman","project":"default","container_name":"{vm_id}","container_id":"{gen1}","upload_mbps":5,"download_mbps":10}}],"auto_throttle":{{"enabled":false}}}}"#
        );
        let containers = vec![ContainerInput {
            runtime: "runman".into(),
            runtime_bin: "runman".into(),
            project: "default".into(),
            name: vm_id.into(),
            id: vm_id.into(),
            instance_id: gen1.into(),
            status: "running".into(),
            pid: Some(42),
        }];
        let mut runner = MockRunner::new(2000);
        runner.netns.insert(1, Ok(1));
        runner.netns.insert(42, Ok(42));
        runner
            .netns
            .insert(99, Err(NetnsError::Unavailable("permission denied".into())));
        runner.proc_stats.insert(
            42,
            Ok(format!("42 (vm) S {} 987654", vec!["0"; 18].join(" "))),
        );
        runner.handler = Some(Box::new(|args, _| {
            if args == ["nsenter", "--target", "42", "--net", "ip", "-j", "route", "show", "default"] {
                return (0, r#"[{"dev":"eth0"}]"#.to_string());
            }
            if args == ["nsenter", "--target", "42", "--net", "ip", "-j", "link", "show", "dev", "eth0"] {
                return (0, r#"[{"ifindex":3,"link_index":7}]"#.to_string());
            }
            (1, "tc must not be called".into())
        }));

        let res = reconcile_with_runner(
            &ReconcileRequest {
                policy_json: &policy,
                host_id: HOST,
                node_id: NODE,
                containers: &containers,
                state_path: &state_path,
                traffic_samples: &[],
                sample_at: 0,
                sample_interval_seconds: 300,
                bridge_inventory: &[],
            },
            &mut runner,
        );
        assert_eq!(res.state, "failed");
        assert!(res.items.iter().any(|i| {
            i.message
                .as_deref()
                .unwrap_or("")
                .contains("旧的 tc 所有限额")
        }));
        assert_eq!(read_state(&state_path).entries[&key].interface_index, 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_active_limits_legacy_fallback_and_reconcile_live_samples() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "host:eth0".to_string(),
            StoredEntry {
                key: "host:eth0".into(),
                scope: "host".into(),
                interface: "eth0".into(),
                last_confirmed_at: 555,
                ..Default::default()
            },
        );
        let prev_status = JsonValue::parse(
            r#"{"items":[{"scope":"host","interface":"eth0","target":"eth0","direction":"upload","rate_mbps":25,"state":"applied"}]}"#,
        )
        .unwrap();
        let active = active_bandwidth_limits(&entries, Some(&prev_status));
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].upload_mbps, 25);
        assert_eq!(active[0].download_mbps, 0);

        let dir = temp_dir("live_samples");
        let state_path = dir.join("missing.json");
        let res = reconcile_live_samples(
            r#"{"schema":2,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[]}"#,
            HOST,
            NODE,
            &[],
            &state_path,
            &[],
            0,
            300,
            &[],
        );
        assert_eq!(res.state, "rejected");
        assert!(default_state_path().to_string_lossy().contains("manual-bandwidth-limits.json"));

        let _ = fs::remove_dir_all(&dir);
    }
}
