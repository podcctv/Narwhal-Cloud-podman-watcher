#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

use net_probe::{is_allowed_host, probe_tcp_target};
use transport::{SignedResponse, TransportClient, TransportError};

pub const MANAGED_UPDATE_SCRIPT: &str = "/opt/narwhal-monitor/managed-client-update.sh";
pub const MAX_TCP_PING_WORKERS: usize = 4;
pub const MAX_TCP_PING_TARGETS: usize = 400;
const MAX_JSON_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionParseError {
    UnexpectedEof,
    InvalidSyntax { pos: usize, msg: &'static str },
    InvalidEscape { pos: usize },
    InvalidUnicode { pos: usize },
    MaxDepthExceeded,
    TrailingData { pos: usize },
    MissingField(&'static str),
    InvalidFieldType(&'static str),
}

impl fmt::Display for ActionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of JSON input"),
            Self::InvalidSyntax { pos, msg } => write!(f, "JSON syntax error at {pos}: {msg}"),
            Self::InvalidEscape { pos } => write!(f, "invalid JSON escape at {pos}"),
            Self::InvalidUnicode { pos } => write!(f, "invalid JSON unicode escape at {pos}"),
            Self::MaxDepthExceeded => write!(f, "JSON nesting depth exceeded"),
            Self::TrailingData { pos } => write!(f, "unexpected trailing JSON data at {pos}"),
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::InvalidFieldType(field) => write!(f, "invalid type for field: {field}"),
        }
    }
}

impl std::error::Error for ActionParseError {}

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

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(s) => s.parse::<i64>().ok(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(s) => s.parse::<u64>().ok(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(s) => s.parse::<f64>().ok().filter(|v| v.is_finite()),
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
        self.as_object().and_then(|map| map.get(key))
    }
}

pub fn parse_json(input: &str) -> Result<JsonValue, ActionParseError> {
    let mut parser = JsonParser {
        src: input,
        bytes: input.as_bytes(),
        pos: 0,
    };
    let val = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.pos < parser.bytes.len() {
        return Err(ActionParseError::TrailingData { pos: parser.pos });
    }
    Ok(val)
}

struct JsonParser<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect_byte(&mut self, expected: u8, msg: &'static str) -> Result<(), ActionParseError> {
        match self.peek() {
            Some(b) if b == expected => {
                self.pos += 1;
                Ok(())
            }
            Some(_) => Err(ActionParseError::InvalidSyntax { pos: self.pos, msg }),
            None => Err(ActionParseError::UnexpectedEof),
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, ActionParseError> {
        if depth > MAX_JSON_DEPTH {
            return Err(ActionParseError::MaxDepthExceeded);
        }
        self.skip_ws();
        let b = self.peek().ok_or(ActionParseError::UnexpectedEof)?;
        match b {
            b'n' => self.parse_null(),
            b't' | b'f' => self.parse_bool(),
            b'"' => self.parse_string().map(JsonValue::String),
            b'[' => self.parse_array(depth + 1),
            b'{' => self.parse_object(depth + 1),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(ActionParseError::InvalidSyntax {
                pos: self.pos,
                msg: "unexpected token",
            }),
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue, ActionParseError> {
        if self.bytes[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(JsonValue::Null)
        } else {
            Err(ActionParseError::InvalidSyntax {
                pos: self.pos,
                msg: "expected null",
            })
        }
    }

    fn parse_bool(&mut self) -> Result<JsonValue, ActionParseError> {
        if self.bytes[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(JsonValue::Bool(true))
        } else if self.bytes[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(JsonValue::Bool(false))
        } else {
            Err(ActionParseError::InvalidSyntax {
                pos: self.pos,
                msg: "expected boolean",
            })
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, ActionParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => {
                return Err(ActionParseError::InvalidSyntax {
                    pos: self.pos,
                    msg: "invalid number",
                });
            }
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ActionParseError::InvalidSyntax {
                    pos: self.pos,
                    msg: "expected digit after decimal point",
                });
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
                return Err(ActionParseError::InvalidSyntax {
                    pos: self.pos,
                    msg: "expected exponent digit",
                });
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        Ok(JsonValue::Number(self.src[start..self.pos].to_string()))
    }

    fn parse_string(&mut self) -> Result<String, ActionParseError> {
        self.expect_byte(b'"', "expected '\"'")?;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let ch = self.src[self.pos..]
                .chars()
                .next()
                .ok_or(ActionParseError::UnexpectedEof)?;
            self.pos += ch.len_utf8();
            match ch {
                '"' => return Ok(out),
                '\\' => {
                    let esc = self.peek().ok_or(ActionParseError::UnexpectedEof)?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let code = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&code) {
                                if !self.bytes[self.pos..].starts_with(b"\\u") {
                                    return Err(ActionParseError::InvalidUnicode { pos: self.pos });
                                }
                                self.pos += 2;
                                let low = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err(ActionParseError::InvalidUnicode { pos: self.pos });
                                }
                                let combined = 0x10000
                                    + (((code as u32 - 0xD800) << 10) | (low as u32 - 0xDC00));
                                let c = char::from_u32(combined)
                                    .ok_or(ActionParseError::InvalidUnicode { pos: self.pos })?;
                                out.push(c);
                            } else if (0xDC00..=0xDFFF).contains(&code) {
                                return Err(ActionParseError::InvalidUnicode { pos: self.pos });
                            } else {
                                let c = char::from_u32(code as u32)
                                    .ok_or(ActionParseError::InvalidUnicode { pos: self.pos })?;
                                out.push(c);
                            }
                        }
                        _ => return Err(ActionParseError::InvalidEscape { pos: self.pos - 1 }),
                    }
                }
                c if (c as u32) < 0x20 => {
                    return Err(ActionParseError::InvalidSyntax {
                        pos: self.pos - 1,
                        msg: "unescaped control character in string",
                    });
                }
                c => out.push(c),
            }
        }
        Err(ActionParseError::UnexpectedEof)
    }

    fn parse_hex4(&mut self) -> Result<u16, ActionParseError> {
        if self.pos + 4 > self.bytes.len() {
            return Err(ActionParseError::UnexpectedEof);
        }
        let hex = &self.src[self.pos..self.pos + 4];
        let val = u16::from_str_radix(hex, 16)
            .map_err(|_| ActionParseError::InvalidUnicode { pos: self.pos })?;
        self.pos += 4;
        Ok(val)
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, ActionParseError> {
        self.expect_byte(b'[', "expected '['")?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.parse_value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                Some(_) => {
                    return Err(ActionParseError::InvalidSyntax {
                        pos: self.pos,
                        msg: "expected ',' or ']'",
                    });
                }
                None => return Err(ActionParseError::UnexpectedEof),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, ActionParseError> {
        self.expect_byte(b'{', "expected '{'")?;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(map));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect_byte(b':', "expected ':'")?;
            let val = self.parse_value(depth)?;
            map.insert(key, val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(map));
                }
                Some(_) => {
                    return Err(ActionParseError::InvalidSyntax {
                        pos: self.pos,
                        msg: "expected ',' or '}'",
                    });
                }
                None => return Err(ActionParseError::UnexpectedEof),
            }
        }
    }
}

pub fn json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRequest {
    pub id: i64,
    pub action_type: String,
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub params: BTreeMap<String, JsonValue>,
}

impl ActionRequest {
    pub fn from_json(raw: &str) -> Result<Self, ActionParseError> {
        let val = parse_json(raw)?;
        Self::from_json_value(&val)
    }

    pub fn from_json_value(val: &JsonValue) -> Result<Self, ActionParseError> {
        let obj = val
            .as_object()
            .ok_or(ActionParseError::InvalidFieldType("action"))?;
        let id = obj
            .get("id")
            .and_then(JsonValue::as_i64)
            .ok_or(ActionParseError::MissingField("id"))?;
        let action_type = obj
            .get("action_type")
            .and_then(JsonValue::as_str)
            .ok_or(ActionParseError::MissingField("action_type"))?
            .to_string();
        let runtime = obj
            .get("runtime")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string();
        let project = obj
            .get("project")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string();
        let container_name = obj
            .get("container_name")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string();
        let params = match obj.get("params") {
            None | Some(JsonValue::Null) => BTreeMap::new(),
            Some(JsonValue::Object(map)) => map.clone(),
            Some(_) => return Err(ActionParseError::InvalidFieldType("params")),
        };

        Ok(Self {
            id,
            action_type,
            runtime,
            project,
            container_name,
            params,
        })
    }
}

pub fn parse_poll_actions(body: &str) -> Result<Vec<ActionRequest>, ActionParseError> {
    let root = parse_json(body)?;
    let Some(actions_val) = root.get("actions") else {
        return Ok(Vec::new());
    };
    let arr = actions_val
        .as_array()
        .ok_or(ActionParseError::InvalidFieldType("actions"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        out.push(ActionRequest::from_json_value(item)?);
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionReceipt {
    pub action_id: i64,
    pub action_type: String,
    pub ok: bool,
    pub status: String,
    pub message: String,
    pub data_json: Option<String>,
}

impl ActionReceipt {
    pub fn succeeded(
        action_id: i64,
        action_type: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            action_id,
            action_type: action_type.into(),
            ok: true,
            status: "succeeded".to_string(),
            message: message.into(),
            data_json: None,
        }
    }

    pub fn succeeded_with_data(
        action_id: i64,
        action_type: impl Into<String>,
        message: impl Into<String>,
        data_json: impl Into<String>,
    ) -> Self {
        Self {
            action_id,
            action_type: action_type.into(),
            ok: true,
            status: "succeeded".to_string(),
            message: message.into(),
            data_json: Some(data_json.into()),
        }
    }

    pub fn failed(
        action_id: i64,
        action_type: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            action_id,
            action_type: action_type.into(),
            ok: false,
            status: "failed".to_string(),
            message: message.into(),
            data_json: None,
        }
    }

    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(160 + self.message.len());
        let _ = write!(
            out,
            "{{\"action_id\":{},\"action_type\":{},\"ok\":{},\"status\":{},\"message\":{}",
            self.action_id,
            json_quote(&self.action_type),
            self.ok,
            json_quote(&self.status),
            json_quote(&self.message),
        );
        if let Some(ref data) = self.data_json {
            let _ = write!(out, ",\"data\":{data}");
        }
        out.push('}');
        out
    }

    /// Serialize into `/api/v1/actions/result` payload.
    pub fn to_result_json(&self, host_id: &str, node_id: &str) -> String {
        let mut out = String::with_capacity(192 + self.message.len());
        let _ = write!(
            out,
            "{{\"action_id\":{},\"host_id\":{},\"node_id\":{},\"ok\":{},\"status\":{},\"message\":{}",
            self.action_id,
            json_quote(host_id),
            json_quote(node_id),
            self.ok,
            json_quote(&self.status),
            json_quote(&self.message),
        );
        if let Some(ref data) = self.data_json {
            let _ = write!(out, ",\"data\":{data}");
        }
        out.push('}');
        out
    }
}

pub fn submit_action_receipt(
    client: &TransportClient,
    host_id: &str,
    node_id: &str,
    receipt: &ActionReceipt,
) -> Result<SignedResponse, TransportError> {
    let payload = receipt.to_result_json(host_id, node_id);
    client.post_json_signed_verified("/api/v1/actions/result", payload.as_bytes())
}

pub fn is_valid_revision(revision: &str) -> bool {
    revision.len() == 40
        && revision
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn is_valid_semver(version: &str) -> bool {
    let mut parts = version.split('.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let Some(patch) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    [major, minor, patch]
        .iter()
        .all(|p| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Validate a systemd unit name matching `^[A-Za-z0-9_.@-]+\.(service|scope)$`,
/// additionally rejecting leading `-` (flag injection) and `..` (path traversal).
pub fn is_valid_systemd_unit(unit: &str) -> bool {
    if unit.is_empty() || unit.len() > 256 || unit.starts_with('-') || unit.contains("..") {
        return false;
    }
    let stem = if let Some(s) = unit.strip_suffix(".service") {
        s
    } else if let Some(s) = unit.strip_suffix(".scope") {
        s
    } else {
        return false;
    };
    !stem.is_empty()
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'@' | b'-'))
}

pub fn execute_action(req: &ActionRequest) -> ActionReceipt {
    match req.action_type.as_str() {
        "managed_upgrade" => execute_managed_upgrade(req, Path::new(MANAGED_UPDATE_SCRIPT)),
        "tcp_ping" => execute_tcp_ping(req),
        "cpu_limit" | "memory_limit" | "io_limit" => execute_systemd_limit(req),
        other => ActionReceipt::failed(
            req.id,
            other,
            format!("unsupported or unknown action_type: {other}"),
        ),
    }
}

fn execute_managed_upgrade(req: &ActionRequest, script_path: &Path) -> ActionReceipt {
    let revision = req
        .params
        .get("revision")
        .and_then(JsonValue::as_str)
        .unwrap_or("");
    let version = req
        .params
        .get("version")
        .and_then(JsonValue::as_str)
        .unwrap_or("");

    if !is_valid_revision(revision) {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            "invalid managed_upgrade revision: expected 40-char lowercase hex",
        );
    }
    if !is_valid_semver(version) {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            "invalid managed_upgrade version: expected MAJOR.MINOR.PATCH",
        );
    }
    if !script_path.is_file() {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("managed update script unavailable: {}", script_path.display()),
        );
    }

    match Command::new(script_path)
        .arg("upgrade")
        .arg(revision)
        .arg(version)
        .output()
    {
        Ok(output) if output.status.success() => ActionReceipt::succeeded(
            req.id,
            &req.action_type,
            format!("managed_upgrade {version} ({revision}) completed"),
        ),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = stderr.trim();
            let msg = if detail.is_empty() {
                format!(
                    "managed_upgrade exited with status {}",
                    output.status.code().unwrap_or(-1)
                )
            } else {
                format!("managed_upgrade failed: {detail}")
            };
            ActionReceipt::failed(req.id, &req.action_type, msg)
        }
        Err(err) => ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("failed to invoke managed_upgrade script: {err}"),
        ),
    }
}

#[derive(Debug, Clone)]
struct TcpTarget {
    id: String,
    host: String,
    port: u16,
}

fn execute_tcp_ping(req: &ActionRequest) -> ActionReceipt {
    let Some(targets_val) = req.params.get("targets").and_then(JsonValue::as_array) else {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            "tcp_ping requires non-empty targets array",
        );
    };
    if targets_val.is_empty() || targets_val.len() > MAX_TCP_PING_TARGETS {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("tcp_ping targets count must be between 1 and {MAX_TCP_PING_TARGETS}"),
        );
    }

    let samples = match req.params.get("samples") {
        None | Some(JsonValue::Null) => 1usize,
        Some(v) => match v.as_i64() {
            Some(n) if (1..=3).contains(&n) => n as usize,
            _ => {
                return ActionReceipt::failed(
                    req.id,
                    &req.action_type,
                    "tcp_ping samples must be an integer between 1 and 3",
                );
            }
        },
    };

    let mut targets = Vec::with_capacity(targets_val.len());
    for (idx, item) in targets_val.iter().enumerate() {
        let Some(host) = item.get("host").and_then(JsonValue::as_str) else {
            return ActionReceipt::failed(
                req.id,
                &req.action_type,
                format!("tcp_ping target[{idx}] missing host"),
            );
        };
        if !is_allowed_host(host) {
            return ActionReceipt::failed(
                req.id,
                &req.action_type,
                format!("tcp_ping target[{idx}] disallowed host: {host}"),
            );
        }
        let Some(port_i64) = item.get("port").and_then(JsonValue::as_i64) else {
            return ActionReceipt::failed(
                req.id,
                &req.action_type,
                format!("tcp_ping target[{idx}] missing integer port"),
            );
        };
        if !(1..=65535).contains(&port_i64) {
            return ActionReceipt::failed(
                req.id,
                &req.action_type,
                format!("tcp_ping target[{idx}] invalid port: {port_i64}"),
            );
        }
        let port = port_i64 as u16;
        let id = item
            .get("id")
            .or_else(|| item.get("target_id"))
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(|c| c.is_control()))
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("{host}:{port}"));
        targets.push(TcpTarget {
            id,
            host: host.to_string(),
            port,
        });
    }

    let worker_count = targets.len().min(MAX_TCP_PING_WORKERS);
    let queue: Arc<Mutex<Vec<(usize, TcpTarget)>>> =
        Arc::new(Mutex::new(targets.into_iter().enumerate().rev().collect()));
    let results: Arc<Mutex<Vec<(usize, String)>>> = Arc::new(Mutex::new(Vec::new()));

    let mut handles = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let queue_ref = Arc::clone(&queue);
        let results_ref = Arc::clone(&results);
        handles.push(thread::spawn(move || loop {
            let next_item = {
                let mut guard = match queue_ref.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                guard.pop()
            };
            let Some((idx, target)) = next_item else {
                break;
            };
            let row_json = probe_tcp_target(&target.id, &target.host, target.port, samples);
            let mut out_guard = match results_ref.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            out_guard.push((idx, row_json));
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    let mut collected = match results.lock() {
        Ok(g) => std::mem::take(&mut *g),
        Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
    };
    collected.sort_by_key(|(idx, _)| *idx);

    let mut data_json = String::from("{\"results\":[");
    for (i, (_, row)) in collected.iter().enumerate() {
        if i > 0 {
            data_json.push(',');
        }
        data_json.push_str(row);
    }
    data_json.push_str("]}");

    ActionReceipt::succeeded_with_data(
        req.id,
        &req.action_type,
        format!("probed {} target(s) with {} worker(s)", collected.len(), worker_count),
        data_json,
    )
}

fn is_restore_mode(params: &BTreeMap<String, JsonValue>) -> bool {
    if params.get("restore").and_then(JsonValue::as_bool) == Some(true) {
        return true;
    }
    for key in ["mode", "action", "op"] {
        if params
            .get(key)
            .and_then(JsonValue::as_str)
            .map(|s| s.eq_ignore_ascii_case("restore"))
            == Some(true)
        {
            return true;
        }
    }
    false
}

fn is_valid_systemd_size(s: &str) -> bool {
    if s.eq_ignore_ascii_case("infinity") {
        return true;
    }
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 24 {
        return false;
    }
    let (digits, suffix_ok) = if matches!(bytes[bytes.len() - 1], b'K' | b'M' | b'G' | b'T' | b'P') {
        (&bytes[..bytes.len() - 1], true)
    } else {
        (bytes, true)
    };
    suffix_ok && !digits.is_empty() && digits.iter().all(|b| b.is_ascii_digit())
}

fn is_valid_block_device(dev: &str) -> bool {
    if !dev.starts_with("/dev/") || dev.contains("..") || dev.len() > 128 {
        return false;
    }
    let rest = &dev["/dev/".len()..];
    !rest.is_empty()
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn build_systemd_limit_props(req: &ActionRequest) -> Result<(String, Vec<String>), String> {
    let unit = req
        .params
        .get("unit")
        .or_else(|| req.params.get("systemd_unit"))
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let trimmed = req.container_name.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .ok_or_else(|| "missing systemd unit name".to_string())?;

    if !is_valid_systemd_unit(unit) {
        return Err(format!("invalid systemd unit name: {unit}"));
    }

    let restore = is_restore_mode(&req.params);
    let mut props = Vec::new();

    match req.action_type.as_str() {
        "cpu_limit" => {
            if restore {
                props.push("CPUQuota=".to_string());
            } else if let Some(pct) = req.params.get("cpu_quota_percent").and_then(JsonValue::as_f64)
            {
                if !(0.1..=10000.0).contains(&pct) {
                    return Err("cpu_quota_percent out of range (0.1..=10000)".to_string());
                }
                props.push(format!("CPUQuota={:.0}%", pct.round().max(1.0)));
            } else if let Some(cpus) = req.params.get("cpus").and_then(JsonValue::as_f64) {
                if !(0.01..=1000.0).contains(&cpus) {
                    return Err("cpus out of range (0.01..=1000)".to_string());
                }
                let pct = (cpus * 100.0).round().max(1.0);
                props.push(format!("CPUQuota={pct:.0}%"));
            } else if let Some(raw) = req.params.get("cpu_quota").and_then(JsonValue::as_str) {
                let trimmed = raw.trim();
                if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("infinity") {
                    props.push("CPUQuota=".to_string());
                } else if let Some(num) = trimmed.strip_suffix('%') {
                    let parsed = num
                        .parse::<u64>()
                        .map_err(|_| "invalid cpu_quota percentage".to_string())?;
                    if !(1..=10000).contains(&parsed) {
                        return Err("cpu_quota percentage out of range (1..=10000)".to_string());
                    }
                    props.push(format!("CPUQuota={parsed}%"));
                } else {
                    return Err("invalid cpu_quota format; expected <N>%".to_string());
                }
            } else {
                return Err("cpu_limit requires cpu_quota_percent, cpus, cpu_quota, or restore=true".to_string());
            }
        }
        "memory_limit" => {
            if restore {
                props.push("MemoryMax=infinity".to_string());
                props.push("MemoryHigh=infinity".to_string());
            } else {
                if let Some(mem_max) = req.params.get("memory_max").and_then(JsonValue::as_str) {
                    let trimmed = mem_max.trim();
                    if !is_valid_systemd_size(trimmed) {
                        return Err("invalid memory_max value".to_string());
                    }
                    props.push(format!("MemoryMax={trimmed}"));
                } else if let Some(bytes) =
                    req.params.get("memory_max_bytes").and_then(JsonValue::as_u64)
                {
                    if bytes < 4096 {
                        return Err("memory_max_bytes must be >= 4096".to_string());
                    }
                    props.push(format!("MemoryMax={bytes}"));
                }
                if let Some(mem_high) = req.params.get("memory_high").and_then(JsonValue::as_str) {
                    let trimmed = mem_high.trim();
                    if !is_valid_systemd_size(trimmed) {
                        return Err("invalid memory_high value".to_string());
                    }
                    props.push(format!("MemoryHigh={trimmed}"));
                } else if let Some(bytes) =
                    req.params.get("memory_high_bytes").and_then(JsonValue::as_u64)
                {
                    if bytes < 4096 {
                        return Err("memory_high_bytes must be >= 4096".to_string());
                    }
                    props.push(format!("MemoryHigh={bytes}"));
                }
                if props.is_empty() {
                    return Err("memory_limit requires memory_max/memory_high or restore=true".to_string());
                }
            }
        }
        "io_limit" => {
            let device = req
                .params
                .get("device")
                .and_then(JsonValue::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty());
            if let Some(dev) = device {
                if !is_valid_block_device(dev) {
                    return Err(format!("invalid block device path: {dev}"));
                }
            }
            if restore {
                if let Some(dev) = device {
                    props.push(format!("IOReadBandwidthMax={dev}"));
                    props.push(format!("IOWriteBandwidthMax={dev}"));
                } else {
                    props.push("IOWeight=100".to_string());
                }
            } else {
                if let Some(weight) = req.params.get("io_weight").and_then(JsonValue::as_u64) {
                    if !(1..=10000).contains(&weight) {
                        return Err("io_weight out of range (1..=10000)".to_string());
                    }
                    props.push(format!("IOWeight={weight}"));
                }
                if let Some(read_bps) = req.params.get("read_bps") {
                    let dev = device.ok_or_else(|| {
                        "io_limit read_bps requires valid /dev/... device".to_string()
                    })?;
                    let val = extract_bandwidth_value(read_bps)
                        .ok_or_else(|| "invalid read_bps value".to_string())?;
                    props.push(format!("IOReadBandwidthMax={dev} {val}"));
                }
                if let Some(write_bps) = req.params.get("write_bps") {
                    let dev = device.ok_or_else(|| {
                        "io_limit write_bps requires valid /dev/... device".to_string()
                    })?;
                    let val = extract_bandwidth_value(write_bps)
                        .ok_or_else(|| "invalid write_bps value".to_string())?;
                    props.push(format!("IOWriteBandwidthMax={dev} {val}"));
                }
                if props.is_empty() {
                    return Err("io_limit requires io_weight, read_bps/write_bps, or restore=true".to_string());
                }
            }
        }
        other => return Err(format!("unsupported limit action: {other}")),
    }

    Ok((unit.to_string(), props))
}

fn extract_bandwidth_value(val: &JsonValue) -> Option<String> {
    if let Some(n) = val.as_u64() {
        return Some(n.to_string());
    }
    if let Some(s) = val.as_str() {
        let trimmed = s.trim();
        if is_valid_systemd_size(trimmed) {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn execute_systemd_limit(req: &ActionRequest) -> ActionReceipt {
    let (unit, props) = match build_systemd_limit_props(req) {
        Ok(parsed) => parsed,
        Err(msg) => return ActionReceipt::failed(req.id, &req.action_type, msg),
    };

    match Command::new("systemctl")
        .arg("set-property")
        .arg("--")
        .arg(&unit)
        .args(&props)
        .output()
    {
        Ok(output) if output.status.success() => ActionReceipt::succeeded(
            req.id,
            &req.action_type,
            format!("systemctl set-property {unit} {}", props.join(" ")),
        ),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = stderr.trim();
            let msg = if detail.is_empty() {
                format!(
                    "systemctl set-property failed with status {}",
                    output.status.code().unwrap_or(-1)
                )
            } else {
                format!("systemctl set-property failed: {detail}")
            };
            ActionReceipt::failed(req.id, &req.action_type, msg)
        }
        Err(err) => ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("failed to invoke systemctl: {err}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_poll_actions_and_receipt_serialization() {
        let poll_json = r#"{
            "ok": true,
            "actions": [
                {
                    "id": 42,
                    "action_type": "cpu_limit",
                    "runtime": "runman",
                    "project": "default",
                    "container_name": "runman-abc.service",
                    "params": {
                        "unit": "runman-abc.service",
                        "cpu_quota_percent": 50
                    }
                },
                {
                    "id": 43,
                    "action_type": "tcp_ping",
                    "params": {
                        "samples": 2,
                        "targets": [
                            {"id": "t1", "host": "example.com", "port": 443}
                        ]
                    }
                }
            ]
        }"#;

        let actions = parse_poll_actions(poll_json).expect("parse poll actions");
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].id, 42);
        assert_eq!(actions[0].action_type, "cpu_limit");
        assert_eq!(
            actions[0].params.get("cpu_quota_percent").and_then(JsonValue::as_i64),
            Some(50)
        );
        assert_eq!(actions[1].id, 43);
        assert_eq!(actions[1].action_type, "tcp_ping");

        let receipt = ActionReceipt::succeeded_with_data(
            43,
            "tcp_ping",
            "probed \"1\" target\nline2",
            "{\"results\":[]}",
        );
        let serialized = receipt.to_result_json("host-1", "node-9");
        let parsed = parse_json(&serialized).expect("valid receipt JSON");
        assert_eq!(parsed.get("action_id").and_then(JsonValue::as_i64), Some(43));
        assert_eq!(parsed.get("host_id").and_then(JsonValue::as_str), Some("host-1"));
        assert_eq!(parsed.get("node_id").and_then(JsonValue::as_str), Some("node-9"));
        assert_eq!(parsed.get("ok").and_then(JsonValue::as_bool), Some(true));
        assert_eq!(
            parsed.get("status").and_then(JsonValue::as_str),
            Some("succeeded")
        );
        assert_eq!(
            parsed.get("message").and_then(JsonValue::as_str),
            Some("probed \"1\" target\nline2")
        );
        assert!(parsed.get("data").and_then(|d| d.get("results")).is_some());
    }

    #[test]
    fn test_action_json_parse_rejects_malformed_input() {
        assert!(ActionRequest::from_json("{\"action_type\":\"tcp_ping\"}").is_err());
        assert!(ActionRequest::from_json("{\"id\":1}").is_err());
        assert!(ActionRequest::from_json("{\"id\":1,\"action_type\":\"tcp_ping\"} trailing").is_err());
        assert!(parse_json("{\"a\":\"\\uD800\"}").is_err());
    }

    #[test]
    fn test_managed_upgrade_validation_rejects_bad_revision_version_and_traversal() {
        let bad_rev = ActionRequest::from_json(
            r#"{"id":1,"action_type":"managed_upgrade","params":{"revision":"../etc/passwd","version":"1.8.44"}}"#,
        )
        .unwrap();
        let r1 = execute_action(&bad_rev);
        assert!(!r1.ok);
        assert_eq!(r1.status, "failed");

        let uppercase_rev = ActionRequest::from_json(
            r#"{"id":2,"action_type":"managed_upgrade","params":{"revision":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","version":"1.8.44"}}"#,
        )
        .unwrap();
        let r2 = execute_action(&uppercase_rev);
        assert!(!r2.ok);

        let bad_ver = ActionRequest::from_json(
            r#"{"id":3,"action_type":"managed_upgrade","params":{"revision":"0123456789abcdef0123456789abcdef01234567","version":"1.8.44;id"}}"#,
        )
        .unwrap();
        let r3 = execute_action(&bad_ver);
        assert!(!r3.ok);

        // Valid format but script does not exist in test environment -> safe ok: false
        let missing_script = ActionRequest::from_json(
            r#"{"id":4,"action_type":"managed_upgrade","params":{"revision":"0123456789abcdef0123456789abcdef01234567","version":"1.8.44"}}"#,
        )
        .unwrap();
        let r4 = execute_managed_upgrade(&missing_script, Path::new("/nonexistent/managed-client-update.sh"));
        assert!(!r4.ok);
    }

    #[test]
    fn test_systemd_unit_validation_and_limit_props() {
        assert!(is_valid_systemd_unit("narwhal-agent.service"));
        assert!(is_valid_systemd_unit("runman-123e4567.scope"));
        assert!(is_valid_systemd_unit("user@1000.service"));

        assert!(!is_valid_systemd_unit(""));
        assert!(!is_valid_systemd_unit(".service"));
        assert!(!is_valid_systemd_unit("-flag.service"));
        assert!(!is_valid_systemd_unit("../evil.service"));
        assert!(!is_valid_systemd_unit("foo/bar.service"));
        assert!(!is_valid_systemd_unit("foo.timer"));
        assert!(!is_valid_systemd_unit("foo.service;id"));
        assert!(!is_valid_systemd_unit("foo bar.service"));

        let cpu_req = ActionRequest::from_json(
            r#"{"id":10,"action_type":"cpu_limit","params":{"unit":"runman-1.service","cpu_quota_percent":75}}"#,
        )
        .unwrap();
        let (unit, props) = build_systemd_limit_props(&cpu_req).unwrap();
        assert_eq!(unit, "runman-1.service");
        assert_eq!(props, vec!["CPUQuota=75%"]);

        let cpu_restore = ActionRequest::from_json(
            r#"{"id":11,"action_type":"cpu_limit","params":{"unit":"runman-1.service","restore":true}}"#,
        )
        .unwrap();
        let (_, props_restore) = build_systemd_limit_props(&cpu_restore).unwrap();
        assert_eq!(props_restore, vec!["CPUQuota="]);

        let mem_req = ActionRequest::from_json(
            r#"{"id":12,"action_type":"memory_limit","params":{"unit":"ct-1.scope","memory_max":"512M","memory_high":"384M"}}"#,
        )
        .unwrap();
        let (_, mem_props) = build_systemd_limit_props(&mem_req).unwrap();
        assert_eq!(mem_props, vec!["MemoryMax=512M", "MemoryHigh=384M"]);

        let io_req = ActionRequest::from_json(
            r#"{"id":13,"action_type":"io_limit","params":{"unit":"ct-1.scope","io_weight":200,"device":"/dev/sda","read_bps":"10M"}}"#,
        )
        .unwrap();
        let (_, io_props) = build_systemd_limit_props(&io_req).unwrap();
        assert_eq!(
            io_props,
            vec!["IOWeight=200", "IOReadBandwidthMax=/dev/sda 10M"]
        );

        let bad_unit_req = ActionRequest::from_json(
            r#"{"id":14,"action_type":"cpu_limit","params":{"unit":"../etc/passwd","cpu_quota_percent":50}}"#,
        )
        .unwrap();
        let r_bad = execute_action(&bad_unit_req);
        assert!(!r_bad.ok);

        let bad_dev_req = ActionRequest::from_json(
            r#"{"id":15,"action_type":"io_limit","params":{"unit":"ct-1.scope","device":"/dev/../sda","read_bps":"10M"}}"#,
        )
        .unwrap();
        let r_bad_dev = execute_action(&bad_dev_req);
        assert!(!r_bad_dev.ok);
    }

    #[test]
    fn test_tcp_ping_validation_and_unknown_action_rejection() {
        let bad_host = ActionRequest::from_json(
            r#"{"id":20,"action_type":"tcp_ping","params":{"targets":[{"id":"local","host":"127.0.0.1","port":80}]}}"#,
        )
        .unwrap();
        let r_host = execute_action(&bad_host);
        assert!(!r_host.ok);

        let bad_port = ActionRequest::from_json(
            r#"{"id":21,"action_type":"tcp_ping","params":{"targets":[{"id":"p0","host":"example.com","port":0}]}}"#,
        )
        .unwrap();
        let r_port = execute_action(&bad_port);
        assert!(!r_port.ok);

        let bad_samples = ActionRequest::from_json(
            r#"{"id":22,"action_type":"tcp_ping","params":{"samples":99,"targets":[{"id":"t1","host":"example.com","port":443}]}}"#,
        )
        .unwrap();
        let r_samples = execute_action(&bad_samples);
        assert!(!r_samples.ok);

        let unknown = ActionRequest::from_json(
            r#"{"id":23,"action_type":"rm_rf_root","params":{}}"#,
        )
        .unwrap();
        let r_unknown = execute_action(&unknown);
        assert!(!r_unknown.ok);
        assert_eq!(r_unknown.status, "failed");
    }
}
