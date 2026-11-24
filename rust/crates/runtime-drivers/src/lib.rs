#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

pub const RUNMAN_SOCK_PATH: &str = "/run/narwhal-agent/connlimit.sock";
pub const INCUS_SOCK_PATH: &str = "/var/lib/incus/unix.socket";
pub const MAX_RUNMAN_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 128;
#[cfg(unix)]
const RUNMAN_IO_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// 1. Pure-std lightweight JSON parser (JsonVal)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum JsonVal {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<JsonVal>),
    Obj(BTreeMap<String, JsonVal>),
}

impl JsonVal {
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut parser = JsonParser::new(input);
        let val = parser.parse_value(0)?;
        parser.skip_ws();
        if !parser.is_eof() {
            return Err(format!(
                "trailing characters at byte offset {}",
                parser.pos
            ));
        }
        Ok(val)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonVal::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonVal::Num(n) if n.is_finite() => Some(*n),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonVal::Num(n) if n.is_finite() && n.fract() == 0.0 => {
                if *n >= (i64::MIN as f64) && *n <= (i64::MAX as f64) {
                    Some(*n as i64)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            JsonVal::Num(n) if n.is_finite() && n.fract() == 0.0 && *n >= 0.0 => {
                if *n <= (u64::MAX as f64) {
                    Some(*n as u64)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonVal::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[JsonVal]> {
        match self {
            JsonVal::Arr(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    pub fn as_obj(&self) -> Option<&BTreeMap<String, JsonVal>> {
        match self {
            JsonVal::Obj(m) => Some(m),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&JsonVal> {
        self.as_obj()?.get(key)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key)?.as_str()
    }

    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key)?.as_i64()
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key)?.as_u64()
    }

    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.get(key)?.as_f64()
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key)?.as_bool()
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    src: &'a str,
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            bytes: src.as_bytes(),
            src,
            pos: 0,
        }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn next_byte(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonVal, String> {
        if depth > MAX_JSON_DEPTH {
            return Err("json nesting depth exceeded".to_string());
        }
        self.skip_ws();
        let b = self
            .peek()
            .ok_or_else(|| "unexpected end of json input".to_string())?;
        match b {
            b'n' => self.parse_null(),
            b't' => self.parse_true(),
            b'f' => self.parse_false(),
            b'"' => self.parse_string().map(JsonVal::Str),
            b'[' => self.parse_array(depth),
            b'{' => self.parse_object(depth),
            b'-' | b'0'..=b'9' => self.parse_number(),
            other => Err(format!(
                "unexpected byte 0x{:02x} at offset {}",
                other, self.pos
            )),
        }
    }

    fn parse_null(&mut self) -> Result<JsonVal, String> {
        if self.bytes[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(JsonVal::Null)
        } else {
            Err(format!("invalid literal at offset {}", self.pos))
        }
    }

    fn parse_true(&mut self) -> Result<JsonVal, String> {
        if self.bytes[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(JsonVal::Bool(true))
        } else {
            Err(format!("invalid literal at offset {}", self.pos))
        }
    }

    fn parse_false(&mut self) -> Result<JsonVal, String> {
        if self.bytes[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(JsonVal::Bool(false))
        } else {
            Err(format!("invalid literal at offset {}", self.pos))
        }
    }

    fn parse_number(&mut self) -> Result<JsonVal, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(format!("invalid number at offset {}", start)),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(format!("invalid fraction in number at offset {}", start));
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
                return Err(format!("invalid exponent in number at offset {}", start));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let slice = &self.src[start..self.pos];
        let num = slice
            .parse::<f64>()
            .map_err(|_| format!("failed to parse number '{}'", slice))?;
        if !num.is_finite() {
            return Err(format!("non-finite number '{}'", slice));
        }
        Ok(JsonVal::Num(num))
    }

    fn parse_hex4(&mut self) -> Result<u16, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("truncated unicode escape".to_string());
        }
        let hex = &self.src[self.pos..self.pos + 4];
        self.pos += 4;
        u16::from_str_radix(hex, 16)
            .map_err(|_| format!("invalid unicode escape \\u{}", hex))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.next_byte() != Some(b'"') {
            return Err(format!("expected '\"' at offset {}", self.pos));
        }
        let mut out = String::new();
        while !self.is_eof() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                let esc = self
                    .next_byte()
                    .ok_or_else(|| "unterminated escape sequence".to_string())?;
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
                    other => {
                        return Err(format!("invalid escape '\\{}'", other as char));
                    }
                }
                continue;
            }
            if b < 0x20 {
                return Err(format!("unescaped control character 0x{:02x}", b));
            }
            // Fast path: scan UTF-8 char from self.src at self.pos
            let rest = &self.src[self.pos..];
            let ch = rest
                .chars()
                .next()
                .ok_or_else(|| "invalid utf-8 in string".to_string())?;
            out.push(ch);
            self.pos += ch.len_utf8();
        }
        Err("unterminated string".to_string())
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonVal, String> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonVal::Arr(items));
        }
        loop {
            let val = self.parse_value(depth + 1)?;
            items.push(val);
            self.skip_ws();
            match self.next_byte() {
                Some(b',') => continue,
                Some(b']') => return Ok(JsonVal::Arr(items)),
                _ => return Err(format!("expected ',' or ']' at offset {}", self.pos)),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonVal, String> {
        self.pos += 1; // '{'
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonVal::Obj(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(format!("expected object key string at offset {}", self.pos));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.next_byte() != Some(b':') {
                return Err(format!("expected ':' after key at offset {}", self.pos));
            }
            let val = self.parse_value(depth + 1)?;
            map.insert(key, val);
            self.skip_ws();
            match self.next_byte() {
                Some(b',') => continue,
                Some(b'}') => return Ok(JsonVal::Obj(map)),
                _ => return Err(format!("expected ',' or '}}' at offset {}", self.pos)),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Unix-domain-socket HTTP/1.1 client for Runman
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub fn runman_request(
    sock_path: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), String> {
    let mut stream = UnixStream::connect(sock_path)
        .map_err(|e| format!("failed to connect to {}: {}", sock_path, e))?;
    let _ = stream.set_read_timeout(Some(RUNMAN_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(RUNMAN_IO_TIMEOUT));

    let mut req = Vec::with_capacity(256 + body.map_or(0, |b| b.len()));
    req.extend_from_slice(method.as_bytes());
    req.push(b' ');
    req.extend_from_slice(path.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(b) = body {
        req.extend_from_slice(b"Content-Type: application/json\r\n");
        req.extend_from_slice(format!("Content-Length: {}\r\n", b.len()).as_bytes());
    }
    req.extend_from_slice(b"\r\n");
    if let Some(b) = body {
        req.extend_from_slice(b);
    }

    stream
        .write_all(&req)
        .map_err(|e| format!("failed to write request: {}", e))?;
    let _ = stream.flush();

    let mut raw = Vec::new();
    let mut limited = stream.take((MAX_RUNMAN_RESPONSE_BYTES + 1) as u64);
    limited
        .read_to_end(&mut raw)
        .map_err(|e| format!("failed to read response: {}", e))?;
    if raw.len() > MAX_RUNMAN_RESPONSE_BYTES {
        return Err("Runman HTTP response exceeded 4 MiB limit".to_string());
    }

    parse_http_response(&raw)
}

#[cfg(not(unix))]
pub fn runman_request(
    _sock_path: &str,
    _method: &str,
    _path: &str,
    _body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), String> {
    Err("Runman Unix socket client is only supported on Unix platforms".to_string())
}

#[cfg(any(unix, test))]
fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response: missing header terminator".to_string())?;
    let header_bytes = &raw[..header_end];
    let body_raw = &raw[header_end + 4..];

    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| "malformed HTTP response: non-UTF8 headers".to_string())?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "malformed HTTP response: empty status line".to_string())?;
    let mut status_parts = status_line.split_whitespace();
    let _http_ver = status_parts
        .next()
        .filter(|v| v.starts_with("HTTP/"))
        .ok_or_else(|| format!("malformed HTTP status line: {}", status_line))?;
    let status_code = status_parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("invalid HTTP status code in: {}", status_line))?;

    let mut is_chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_ascii_lowercase();
            if key == "transfer-encoding" && val.contains("chunked") {
                is_chunked = true;
            } else if key == "content-length" {
                content_length = val.parse::<usize>().ok();
            }
        }
    }

    let body = if is_chunked {
        decode_chunked_body(body_raw)?
    } else if let Some(len) = content_length {
        if body_raw.len() < len {
            return Err("truncated HTTP response body".to_string());
        }
        body_raw[..len].to_vec()
    } else {
        body_raw.to_vec()
    };

    Ok((status_code, body))
}

#[cfg(any(unix, test))]
fn decode_chunked_body(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let crlf = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "malformed chunked encoding: missing size CRLF".to_string())?;
        let size_line = std::str::from_utf8(&data[..crlf])
            .map_err(|_| "invalid chunk size line".to_string())?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("invalid chunk size '{}'", size_hex))?;
        data = &data[crlf + 2..];
        if chunk_len == 0 {
            break;
        }
        if data.len() < chunk_len + 2 {
            return Err("truncated chunked body".to_string());
        }
        if out.len().saturating_add(chunk_len) > MAX_RUNMAN_RESPONSE_BYTES {
            return Err("chunked HTTP response exceeded 4 MiB limit".to_string());
        }
        out.extend_from_slice(&data[..chunk_len]);
        data = &data[chunk_len + 2..];
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 3. Container Discovery & Probe Enrichment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct ContainerSample {
    pub id: String,
    pub stable_id: String,
    pub name: String,
    pub image: String,
    pub runtime: String,
    pub runtime_bin: String,
    pub project: String,
    pub pid: Option<u32>,
    pub status: String,
    pub instance_id: String,
    pub network_addresses: Vec<String>,
    pub pid_metrics_json: Option<String>,
    pub socket_tables_json: Option<String>,
    pub cgroup_metrics_json: Option<String>,
}

fn is_valid_uuid_lower(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
                    return false;
                }
            }
        }
    }
    true
}

fn find_binary_in_path(name: &str) -> Option<String> {
    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    for fallback_dir in ["/usr/bin", "/usr/local/bin", "/snap/bin"] {
        let candidate = Path::new(fallback_dir).join(name);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

fn run_command_stdout(bin: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(bin).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

/// Parse `podman ps --format json` (JSON array) or `docker ps --format json` (NDJSON or JSON array).
pub fn parse_oci_ps_json(runtime: &str, runtime_bin: &str, raw: &str) -> Vec<ContainerSample> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut objects: Vec<JsonVal> = Vec::new();
    if trimmed.starts_with('[') {
        if let Ok(JsonVal::Arr(arr)) = JsonVal::parse(trimmed) {
            objects = arr;
        }
    } else {
        for line in trimmed.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(val) = JsonVal::parse(line) {
                objects.push(val);
            }
        }
    }

    let mut items = Vec::new();
    for obj in objects {
        let id = obj
            .get_str("Id")
            .or_else(|| obj.get_str("ID"))
            .unwrap_or("")
            .trim()
            .to_string();
        if id.is_empty() {
            continue;
        }
        let name = match obj.get("Names") {
            Some(JsonVal::Arr(arr)) => arr
                .first()
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .trim_start_matches('/')
                .to_string(),
            Some(JsonVal::Str(s)) => s
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .trim_start_matches('/')
                .to_string(),
            _ => id.clone(),
        };
        let image = obj.get_str("Image").unwrap_or("").trim().to_string();
        let state = obj
            .get_str("State")
            .or_else(|| obj.get_str("Status"))
            .unwrap_or("running")
            .to_ascii_lowercase();
        if state != "running" && !state.starts_with("up") {
            continue;
        }
        let pid = obj
            .get_u64("Pid")
            .and_then(|p| u32::try_from(p).ok())
            .filter(|&p| p > 0);

        items.push(ContainerSample {
            id: id.clone(),
            stable_id: id,
            name: if name.is_empty() { "unknown".to_string() } else { name },
            image,
            runtime: runtime.to_string(),
            runtime_bin: runtime_bin.to_string(),
            project: "default".to_string(),
            pid,
            status: "running".to_string(),
            instance_id: String::new(),
            network_addresses: Vec::new(),
            pid_metrics_json: None,
            socket_tables_json: None,
            cgroup_metrics_json: None,
        });
    }
    items
}

/// Parse `incus list --format json` output or Incus REST API `{"metadata": [...]}` envelope.
pub fn parse_incus_list_json(runtime_bin: &str, raw: &str) -> Vec<ContainerSample> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let arr = match JsonVal::parse(trimmed) {
        Ok(JsonVal::Arr(arr)) => arr,
        Ok(JsonVal::Obj(map)) => match map.get("metadata") {
            Some(JsonVal::Arr(arr)) => arr.clone(),
            _ => return Vec::new(),
        },
        _ => return Vec::new(),
    };

    let mut items = Vec::new();
    for item in arr {
        let kind = item.get_str("type").unwrap_or("container").to_ascii_lowercase();
        if !kind.is_empty() && kind != "container" {
            continue;
        }
        let status = item.get_str("status").unwrap_or("running").to_ascii_lowercase();
        if status != "running" {
            continue;
        }
        let name = item.get_str("name").unwrap_or("").trim().to_string();
        if name.is_empty() {
            continue;
        }
        let config = item.get("config");
        let expanded = item.get("expanded_config");
        let image = config
            .and_then(|c| c.get_str("image.description"))
            .or_else(|| expanded.and_then(|c| c.get_str("image.description")))
            .or_else(|| config.and_then(|c| c.get_str("image.os")))
            .or_else(|| expanded.and_then(|c| c.get_str("image.os")))
            .or_else(|| config.and_then(|c| c.get_str("volatile.base_image")))
            .unwrap_or("incus-container")
            .to_string();
        let stable_id = config
            .and_then(|c| c.get_str("volatile.uuid"))
            .unwrap_or("")
            .to_string();
        let project = item.get_str("project").unwrap_or("default").to_string();
        let state = item.get("state");
        let pid = state
            .and_then(|s| s.get_u64("pid"))
            .and_then(|p| u32::try_from(p).ok())
            .filter(|&p| p > 0);

        let mut addrs = BTreeSet::new();
        if let Some(net_obj) = state.and_then(|s| s.get("network")).and_then(|n| n.as_obj()) {
            for iface in net_obj.values() {
                if let Some(addr_arr) = iface.get("addresses").and_then(|a| a.as_arr()) {
                    for addr in addr_arr {
                        let scope = addr.get_str("scope").unwrap_or("").to_ascii_lowercase();
                        if scope == "global" {
                            if let Some(ip) = addr.get_str("address") {
                                let ip = ip.trim();
                                if !ip.is_empty() {
                                    addrs.insert(ip.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        items.push(ContainerSample {
            id: name.clone(),
            stable_id,
            name,
            image,
            runtime: "incus".to_string(),
            runtime_bin: runtime_bin.to_string(),
            project,
            pid,
            status: "running".to_string(),
            instance_id: String::new(),
            network_addresses: addrs.into_iter().collect(),
            pid_metrics_json: None,
            socket_tables_json: None,
            cgroup_metrics_json: None,
        });
    }
    items
}

/// Parse Runman `GET /v1/inventory` JSON response.
pub fn parse_runman_inventory_json(raw: &str) -> Vec<ContainerSample> {
    let Ok(root) = JsonVal::parse(raw.trim()) else {
        return Vec::new();
    };
    if root.get_i64("schema") != Some(1) {
        return Vec::new();
    }
    let Some(raw_items) = root.get("items").and_then(|v| v.as_arr()) else {
        return Vec::new();
    };

    let mut items = Vec::new();
    for raw_item in raw_items.iter().take(4096) {
        if raw_item.get_bool("running") != Some(true) {
            continue;
        }
        let vm_id = raw_item
            .get_str("id")
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !is_valid_uuid_lower(&vm_id) {
            continue;
        }
        let generation = raw_item.get_str("instance_id").unwrap_or("");
        if generation.is_empty() || generation.len() > 200 {
            continue;
        }
        let pid = raw_item
            .get_u64("init_pid")
            .and_then(|p| u32::try_from(p).ok())
            .filter(|&p| p > 1);
        let image: String = raw_item
            .get_str("os_image")
            .unwrap_or("")
            .chars()
            .take(160)
            .collect();
        let mut addrs = Vec::new();
        if let Some(ip_arr) = raw_item.get("ips").and_then(|v| v.as_arr()) {
            for ip in ip_arr.iter().take(32) {
                if let Some(s) = ip.as_str() {
                    let s: String = s.trim().chars().take(64).collect();
                    if !s.is_empty() {
                        addrs.push(s);
                    }
                }
            }
        }

        items.push(ContainerSample {
            id: vm_id.clone(),
            stable_id: vm_id.clone(),
            name: vm_id,
            image,
            runtime: "runman".to_string(),
            runtime_bin: "runman".to_string(),
            project: "default".to_string(),
            pid,
            status: "running".to_string(),
            instance_id: generation.to_string(),
            network_addresses: addrs,
            pid_metrics_json: None,
            socket_tables_json: None,
            cgroup_metrics_json: None,
        });
    }
    items
}

/// Resolve a container PID's cgroup directory from `<proc_root>/<pid>/cgroup`.
pub fn resolve_cgroup_dir_from_proc(
    proc_root: &Path,
    cgroup_root: &Path,
    pid: u32,
) -> Option<PathBuf> {
    if pid == 0 {
        return None;
    }
    let raw = fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup")).ok()?;
    for line in raw.lines() {
        let mut parts = line.splitn(3, ':');
        let hierarchy = parts.next()?;
        let _controllers = parts.next()?;
        let rel = parts.next()?.trim();
        if hierarchy == "0" {
            let trimmed = rel.trim_start_matches('/');
            if trimmed.is_empty() {
                return Some(cgroup_root.to_path_buf());
            }
            return Some(cgroup_root.join(trimmed));
        }
    }
    None
}

fn enrich_sample(sample: &mut ContainerSample, include_sockets: bool) {
    let Some(pid) = sample.pid else {
        return;
    };
    if pid == 0 {
        return;
    }
    sample.pid_metrics_json = Some(proc_probe::collect_pid_metrics(pid));
    if include_sockets {
        sample.socket_tables_json = Some(socket_sec::collect_socket_tables(pid));
    }
    if let Some(cg_dir) =
        resolve_cgroup_dir_from_proc(Path::new("/proc"), Path::new("/sys/fs/cgroup"), pid)
    {
        sample.cgroup_metrics_json = Some(cgroup_probe::collect_cgroup_metrics(&cg_dir));
    }
}

fn inspect_oci_pid(bin: &str, id: &str) -> Option<u32> {
    let out = run_command_stdout(bin, &["inspect", "--format", "{{.State.Pid}}", id])?;
    out.trim().parse::<u32>().ok().filter(|&p| p > 0)
}

fn parse_enabled_runtimes(runtimes_cfg: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for token in runtimes_cfg.split(',') {
        let t = token.trim().to_ascii_lowercase();
        if !t.is_empty() {
            set.insert(t);
        }
    }
    if set.is_empty() || set.contains("auto") {
        set.insert("podman".to_string());
        set.insert("docker".to_string());
        set.insert("incus".to_string());
        set.insert("runman".to_string());
    }
    set
}

const MAX_ENRICH_THREADS: usize = 4;

fn enrich_sample_with_oci_fallback(sample: &mut ContainerSample, include_sockets: bool) {
    if sample.pid.is_none()
        && (sample.runtime == "podman" || sample.runtime == "docker")
        && !sample.runtime_bin.is_empty()
    {
        sample.pid = inspect_oci_pid(&sample.runtime_bin, &sample.id);
    }
    enrich_sample(sample, include_sockets);
}

fn enrich_samples_parallel(samples: &mut [ContainerSample], include_sockets: bool) {
    let n = samples.len();
    if n <= 1 {
        for item in samples {
            enrich_sample_with_oci_fallback(item, include_sockets);
        }
        return;
    }

    let workers = n.min(MAX_ENRICH_THREADS);
    let chunk_size = (n + workers - 1) / workers;
    std::thread::scope(|scope| {
        for chunk in samples.chunks_mut(chunk_size) {
            scope.spawn(move || {
                for item in chunk {
                    enrich_sample_with_oci_fallback(item, include_sockets);
                }
            });
        }
    });
}

pub fn discover_and_sample_containers(runtimes_cfg: &str) -> Vec<ContainerSample> {
    discover_and_sample_containers_inner(runtimes_cfg, true)
}

pub fn discover_and_sample_containers_lightweight(runtimes_cfg: &str) -> Vec<ContainerSample> {
    discover_and_sample_containers_inner(runtimes_cfg, false)
}

fn discover_and_sample_containers_inner(
    runtimes_cfg: &str,
    include_sockets: bool,
) -> Vec<ContainerSample> {
    let enabled = parse_enabled_runtimes(runtimes_cfg);
    let mut all = Vec::new();

    if enabled.contains("podman") {
        if let Some(bin) = find_binary_in_path("podman") {
            if let Some(out) = run_command_stdout(&bin, &["ps", "--format", "json"]) {
                all.extend(parse_oci_ps_json("podman", &bin, &out));
            }
        }
    }

    if enabled.contains("docker") {
        if let Some(bin) = find_binary_in_path("docker") {
            if let Some(out) = run_command_stdout(&bin, &["ps", "--format", "json"]) {
                all.extend(parse_oci_ps_json("docker", &bin, &out));
            }
        }
    }

    if enabled.contains("incus") {
        let bin = find_binary_in_path("incus").unwrap_or_else(|| "incus".to_string());
        let mut incus_loaded = false;
        if Path::new(INCUS_SOCK_PATH).exists() {
            if let Ok((200, body)) = runman_request(
                INCUS_SOCK_PATH,
                "GET",
                "/1.0/instances?recursion=2&all-projects=true",
                None,
            ) {
                if let Ok(text) = String::from_utf8(body) {
                    all.extend(parse_incus_list_json(&bin, &text));
                    incus_loaded = true;
                }
            }
        }
        if !incus_loaded {
            if let Some(real_bin) = find_binary_in_path("incus") {
                if let Some(out) = run_command_stdout(
                    &real_bin,
                    &[
                        "list",
                        "--all-projects",
                        "type=container",
                        "status=running",
                        "--format=json",
                    ],
                ) {
                    all.extend(parse_incus_list_json(&real_bin, &out));
                }
            }
        }
    }

    if enabled.contains("runman") {
        if let Ok((200, body)) = runman_request(RUNMAN_SOCK_PATH, "GET", "/v1/inventory", None) {
            if let Ok(text) = String::from_utf8(body) {
                all.extend(parse_runman_inventory_json(&text));
            }
        }
    }

    enrich_samples_parallel(&mut all, include_sockets);
    all
}

// ---------------------------------------------------------------------------
// 4. Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_parser_primitives_and_nested() {
        let raw = r#"
        {
            "null_v": null,
            "bool_t": true,
            "bool_f": false,
            "int_neg": -42,
            "float_exp": 1.25e2,
            "str": "hello\n\"world\"\u0041",
            "surrogate": "\uD83D\uDE80",
            "arr": [1, "two", {"nested": [true, false]}]
        }
        "#;
        let val = JsonVal::parse(raw).expect("valid json");
        assert_eq!(val.get("null_v"), Some(&JsonVal::Null));
        assert_eq!(val.get_bool("bool_t"), Some(true));
        assert_eq!(val.get_bool("bool_f"), Some(false));
        assert_eq!(val.get_i64("int_neg"), Some(-42));
        assert_eq!(val.get_f64("float_exp"), Some(125.0));
        assert_eq!(val.get_str("str"), Some("hello\n\"world\"A"));
        assert_eq!(val.get_str("surrogate"), Some("🚀"));
        let arr = val.get("arr").and_then(|v| v.as_arr()).expect("arr");
        assert_eq!(arr.len(), 3);
        assert_eq!(
            arr[2]
                .get("nested")
                .and_then(|v| v.as_arr())
                .map(|a| a.len()),
            Some(2)
        );
    }

    #[test]
    fn test_json_parser_rejects_invalid() {
        assert!(JsonVal::parse("").is_err());
        assert!(JsonVal::parse("{\"a\": 1} trailing").is_err());
        assert!(JsonVal::parse("[1, 2,]").is_err());
        assert!(JsonVal::parse("\"unterminated").is_err());
        assert!(JsonVal::parse("{\"k\": 01}").is_err());
    }

    #[test]
    fn test_parse_podman_and_docker_ps_json() {
        let podman_raw = r#"[
            {"Id": "abc123def456", "Names": ["/web-1"], "Image": "nginx:alpine", "State": "running", "Pid": 4242},
            {"Id": "dead999", "Names": ["stopped-1"], "Image": "busybox", "State": "exited", "Pid": 0}
        ]"#;
        let podman_items = parse_oci_ps_json("podman", "/usr/bin/podman", podman_raw);
        assert_eq!(podman_items.len(), 1);
        assert_eq!(podman_items[0].id, "abc123def456");
        assert_eq!(podman_items[0].name, "web-1");
        assert_eq!(podman_items[0].image, "nginx:alpine");
        assert_eq!(podman_items[0].pid, Some(4242));
        assert_eq!(podman_items[0].runtime, "podman");

        let docker_ndjson = concat!(
            "{\"ID\":\"d111\",\"Names\":\"app1,app1_alias\",\"Image\":\"node:20\",\"State\":\"running\",\"Status\":\"Up 3 hours\"}\n",
            "{\"ID\":\"d222\",\"Names\":\"app2\",\"Image\":\"redis:7\",\"State\":\"exited\",\"Status\":\"Exited (0)\"}\n"
        );
        let docker_items = parse_oci_ps_json("docker", "/usr/bin/docker", docker_ndjson);
        assert_eq!(docker_items.len(), 1);
        assert_eq!(docker_items[0].id, "d111");
        assert_eq!(docker_items[0].name, "app1");
        assert_eq!(docker_items[0].runtime, "docker");
    }

    #[test]
    fn test_parse_incus_list_json() {
        let raw = r#"[
            {
                "name": "ct-alpha",
                "type": "container",
                "status": "Running",
                "project": "prod",
                "config": {
                    "image.description": "Ubuntu 24.04",
                    "volatile.uuid": "11111111-2222-3333-4444-555555555555"
                },
                "state": {
                    "pid": 9001,
                    "network": {
                        "eth0": {
                            "addresses": [
                                {"address": "10.0.0.5", "scope": "global"},
                                {"address": "fe80::1", "scope": "link"}
                            ]
                        }
                    }
                }
            },
            {
                "name": "vm-beta",
                "type": "virtual-machine",
                "status": "Running"
            }
        ]"#;
        let items = parse_incus_list_json("/usr/bin/incus", raw);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "ct-alpha");
        assert_eq!(
            items[0].stable_id,
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(items[0].project, "prod");
        assert_eq!(items[0].image, "Ubuntu 24.04");
        assert_eq!(items[0].pid, Some(9001));
        assert_eq!(items[0].network_addresses, vec!["10.0.0.5".to_string()]);

        let rest_envelope = format!(
            "{{\"type\":\"sync\",\"status\":\"Success\",\"status_code\":200,\"metadata\":{raw}}}"
        );
        let rest_items = parse_incus_list_json("/usr/bin/incus", &rest_envelope);
        assert_eq!(rest_items, items);
    }

    #[test]
    fn test_parse_runman_inventory_json() {
        let raw = r#"{
            "schema": 1,
            "items": [
                {
                    "id": "ABCDEF01-2345-6789-ABCD-EF0123456789",
                    "instance_id": "gen-42",
                    "running": true,
                    "init_pid": 777,
                    "os_image": "debian-12",
                    "ips": ["192.0.2.10", "2001:db8::10"]
                },
                {
                    "id": "invalid-uuid",
                    "instance_id": "gen-1",
                    "running": true,
                    "init_pid": 888
                },
                {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "instance_id": "gen-2",
                    "running": false,
                    "init_pid": 0
                }
            ]
        }"#;
        let items = parse_runman_inventory_json(raw);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "abcdef01-2345-6789-abcd-ef0123456789");
        assert_eq!(items[0].instance_id, "gen-42");
        assert_eq!(items[0].pid, Some(777));
        assert_eq!(items[0].image, "debian-12");
        assert_eq!(items[0].runtime, "runman");
        assert_eq!(
            items[0].network_addresses,
            vec!["192.0.2.10".to_string(), "2001:db8::10".to_string()]
        );
    }

    #[test]
    fn test_parse_http_response_chunked_and_content_length() {
        let cl_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"ok\":true}\n!";
        let (status, body) = parse_http_response(cl_resp).expect("cl");
        assert_eq!(status, 200);
        assert_eq!(body, b"{\"ok\":true}\n!");

        let chunked_resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (status2, body2) = parse_http_response(chunked_resp).expect("chunked");
        assert_eq!(status2, 200);
        assert_eq!(body2, b"hello world");
    }

    #[test]
    fn test_resolve_cgroup_dir_from_proc() {
        let base = env::temp_dir().join(format!("rt_drv_cg_test_{}", std::process::id()));
        let pid_dir = base.join("proc").join("321");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&pid_dir).expect("mkdir");
        fs::write(pid_dir.join("cgroup"), "0::/system.slice/runman-1.scope\n").expect("write");

        let resolved = resolve_cgroup_dir_from_proc(
            &base.join("proc"),
            &base.join("sys/fs/cgroup"),
            321,
        );
        assert_eq!(
            resolved,
            Some(base.join("sys/fs/cgroup").join("system.slice/runman-1.scope"))
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn test_runman_request_unix_socket_mock() {
        use std::os::unix::net::UnixListener;
        use std::thread;

        let sock_path = env::temp_dir().join(format!(
            "narwhal_rt_drv_test_{}.sock",
            std::process::id()
        ));
        let _ = fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).expect("bind unix socket");

        let handle = thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 2048];
            let n = conn.read(&mut buf).expect("read request");
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.starts_with("POST /v1/exec HTTP/1.1\r\n"));
            assert!(req.contains("{\"ping\":1}"));

            let resp_body = b"{\"schema\":1,\"ok\":true}";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                resp_body.len()
            );
            conn.write_all(resp.as_bytes()).expect("write headers");
            conn.write_all(resp_body).expect("write body");
            let _ = conn.flush();
        });

        let sock_str = sock_path.to_str().expect("utf8 sock path");
        let (status, body) = runman_request(sock_str, "POST", "/v1/exec", Some(b"{\"ping\":1}"))
            .expect("runman_request");
        assert_eq!(status, 200);
        let parsed = JsonVal::parse(std::str::from_utf8(&body).expect("utf8")).expect("json");
        assert_eq!(parsed.get_i64("schema"), Some(1));
        assert_eq!(parsed.get_bool("ok"), Some(true));

        handle.join().expect("server thread");
        let _ = fs::remove_file(&sock_path);
    }

    #[test]
    fn test_enrich_samples_parallel_multi_container() {
        let self_pid = std::process::id();
        let mut samples: Vec<ContainerSample> = (0..6)
            .map(|i| ContainerSample {
                id: format!("c-{}", i),
                stable_id: format!("c-{}", i),
                name: format!("ctr-{}", i),
                image: "alpine:latest".to_string(),
                runtime: "incus".to_string(),
                runtime_bin: String::new(),
                project: "default".to_string(),
                pid: if i % 2 == 0 { Some(self_pid) } else { None },
                status: "running".to_string(),
                instance_id: String::new(),
                network_addresses: Vec::new(),
                pid_metrics_json: None,
                socket_tables_json: None,
                cgroup_metrics_json: None,
            })
            .collect();

        enrich_samples_parallel(&mut samples, true);

        assert_eq!(samples.len(), 6);
        for (i, s) in samples.iter().enumerate() {
            assert_eq!(s.id, format!("c-{}", i));
            if i % 2 == 0 {
                assert!(s.pid_metrics_json.is_some());
                assert!(s.socket_tables_json.is_some());
            } else {
                assert!(s.pid_metrics_json.is_none());
                assert!(s.socket_tables_json.is_none());
            }
        }
    }
}
