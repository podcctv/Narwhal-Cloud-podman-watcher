#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use net_probe::{is_allowed_host, probe_tcp_target};
use transport::{SignedResponse, TransportClient, TransportError};

pub const MANAGED_UPDATE_SCRIPT: &str = "/opt/narwhal-monitor/managed-client-update.sh";
pub const SELF_UNINSTALL_SCRIPT: &str = "/opt/narwhal-monitor/client-self-uninstall.sh";
pub const RUNMAN_FIREWALL_SOCK_PATH: &str = "/run/narwhal-agent/firewall.sock";
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

    pub fn to_json(&self) -> String {
        match self {
            Self::Null => "null".to_string(),
            Self::Bool(b) => if *b { "true" } else { "false" }.to_string(),
            Self::Number(n) => n.clone(),
            Self::String(s) => json_quote(s),
            Self::Array(arr) => {
                let items: Vec<String> = arr.iter().map(JsonValue::to_json).collect();
                format!("[{}]", items.join(","))
            }
            Self::Object(map) => {
                let fields: Vec<String> = map
                    .iter()
                    .map(|(k, v)| format!("{}:{}", json_quote(k), v.to_json()))
                    .collect();
                format!("{{{}}}", fields.join(","))
            }
        }
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
        let hex = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
            .map_err(|_| ActionParseError::InvalidUnicode { pos: self.pos })?;
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

    pub fn running(
        action_id: i64,
        action_type: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            action_id,
            action_type: action_type.into(),
            ok: true,
            status: "running".to_string(),
            message: message.into(),
            data_json: None,
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

#[derive(Debug, Clone)]
pub struct ActionContext {
    pub node_id: String,
    pub env_file: PathBuf,
    pub configured_access_logs: Vec<String>,
    pub rescan_requested: bool,
    pub restart_required: bool,
}

impl Default for ActionContext {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            env_file: PathBuf::from(crate::DEFAULT_ENV_FILE),
            configured_access_logs: Vec::new(),
            rescan_requested: false,
            restart_required: false,
        }
    }
}

pub fn execute_action(req: &ActionRequest) -> ActionReceipt {
    let mut ctx = ActionContext::default();
    execute_action_with_context(req, &mut ctx)
}

pub fn execute_action_with_context(
    req: &ActionRequest,
    ctx: &mut ActionContext,
) -> ActionReceipt {
    match req.action_type.as_str() {
        "managed_upgrade" | "managed_rollback" => {
            execute_managed_upgrade(req, Path::new(MANAGED_UPDATE_SCRIPT), ctx)
        }
        "tcp_ping" => execute_tcp_ping(req),
        "cpu_limit" | "memory_limit" | "io_limit" => execute_systemd_limit(req),
        "kill_pid" | "stop_socks_process" => execute_kill_pid(req),
        "runman_restart_overload" | "runman_stop_overload" => execute_runman_overload(req),
        "update_host_config" => execute_update_host_config(req, ctx),
        "self_uninstall" => execute_self_uninstall(req, Path::new(SELF_UNINSTALL_SCRIPT), ctx),
        "discover_access_logs" => execute_discover_access_logs(req, ctx),
        "host_security_rescan" => execute_host_security_rescan(req, ctx),
        "restart_container" => execute_restart_container(req, ctx),
        "freeze_container" | "unfreeze_container" => execute_freeze_container(req),
        "apply_host_firewall_policy" => execute_apply_host_firewall_policy(req, ctx),
        "delete_host_firewall_rule" => execute_delete_host_firewall_rule(req, ctx),
        other => ActionReceipt::failed(
            req.id,
            other,
            format!("unsupported or unknown action_type: {other}"),
        ),
    }
}

fn check_expected_node_id(req: &ActionRequest, ctx: &ActionContext) -> Result<(), String> {
    if ctx.node_id.is_empty() {
        return Ok(());
    }
    let expected = req
        .params
        .get("expected_node_id")
        .and_then(JsonValue::as_str)
        .unwrap_or("");
    if expected != ctx.node_id {
        return Err("host action node identity mismatch".to_string());
    }
    Ok(())
}

fn execute_managed_upgrade(
    req: &ActionRequest,
    script_path: &Path,
    ctx: &ActionContext,
) -> ActionReceipt {
    if let Err(msg) = check_expected_node_id(req, ctx) {
        return ActionReceipt::failed(req.id, &req.action_type, msg);
    }
    let rollback = req.action_type == "managed_rollback";
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

    if !rollback && !is_valid_revision(revision) {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            "invalid managed_upgrade revision: expected 40-char lowercase hex",
        );
    }
    if !rollback && !is_valid_semver(version) {
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
    if req.id <= 0 {
        return ActionReceipt::failed(req.id, &req.action_type, "invalid action id");
    }

    let unit = format!("narwhal-managed-{}", req.id);
    let action_id_str = req.id.to_string();
    let script_str = script_path.to_string_lossy().into_owned();
    let mut cmd = Command::new("systemd-run");
    cmd.arg("--no-block")
        .arg("--unit")
        .arg(&unit)
        .arg("--collect")
        .arg("--property=Type=oneshot")
        .arg("--property=TimeoutStartSec=15min")
        .arg("/bin/bash")
        .arg(&script_str);
    if rollback {
        cmd.arg("rollback").arg(&action_id_str);
    } else {
        cmd.arg("upgrade")
            .arg(revision)
            .arg(version)
            .arg(&action_id_str);
    }

    match cmd.output() {
        Ok(output) if output.status.success() => ActionReceipt::running(
            req.id,
            &req.action_type,
            if rollback {
                "scheduled managed rollback".to_string()
            } else {
                format!("scheduled immutable upgrade {version} ({revision})")
            },
        ),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = stderr.trim();
            let msg = if detail.is_empty() {
                format!(
                    "{} systemd-run exited with status {}",
                    req.action_type,
                    output.status.code().unwrap_or(-1)
                )
            } else {
                format!("{} failed: {detail}", req.action_type)
            };
            ActionReceipt::failed(req.id, &req.action_type, msg)
        }
        Err(err) => ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("unable to enqueue managed update; systemd-run failed: {err}"),
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
        Ok(mut g) => std::mem::take(&mut *g),
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

/// Validate a Runman container or instance identifier: non-empty ASCII `[A-Za-z0-9_.-]{1,128}`.
pub fn is_valid_runman_identifier(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn parse_valid_pid(val: Option<&JsonValue>) -> Result<u32, String> {
    let Some(v) = val else {
        return Err("missing required pid parameter".to_string());
    };
    if let Some(n) = v.as_u64() {
        if n > 1 && n <= u32::MAX as u64 {
            return Ok(n as u32);
        }
        return Err(format!("invalid pid {n}: must be > 1 and <= {}", u32::MAX));
    }
    if let Some(s) = v.as_str() {
        let trimmed = s.trim();
        if !trimmed.is_empty() && trimmed.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(n) = trimmed.parse::<u32>() {
                if n > 1 {
                    return Ok(n);
                }
            }
        }
        return Err(format!("invalid pid '{s}': expected integer > 1"));
    }
    Err("invalid pid: expected integer > 1".to_string())
}

fn execute_kill_pid(req: &ActionRequest) -> ActionReceipt {
    let pid = match parse_valid_pid(req.params.get("pid")) {
        Ok(p) => p,
        Err(msg) => return ActionReceipt::failed(req.id, &req.action_type, msg),
    };

    #[cfg(unix)]
    {
        let proc_stat = format!("/proc/{pid}/stat");
        if !Path::new(&proc_stat).is_file() {
            return ActionReceipt::failed(
                req.id,
                &req.action_type,
                format!("target process {pid} does not exist ({proc_stat} not found)"),
            );
        }

        match Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .output()
        {
            Ok(output) if output.status.success() => ActionReceipt::succeeded(
                req.id,
                &req.action_type,
                format!("sent SIGTERM to pid {pid}"),
            ),
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let detail = stderr.trim();
                let msg = if detail.is_empty() {
                    format!(
                        "kill -TERM {pid} failed with status {}",
                        output.status.code().unwrap_or(-1)
                    )
                } else {
                    format!("kill -TERM {pid} failed: {detail}")
                };
                ActionReceipt::failed(req.id, &req.action_type, msg)
            }
            Err(err) => ActionReceipt::failed(
                req.id,
                &req.action_type,
                format!("failed to invoke kill for pid {pid}: {err}"),
            ),
        }
    }

    #[cfg(not(unix))]
    {
        ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("{} is only supported on Unix platforms (validated pid {pid})", req.action_type),
        )
    }
}

fn validate_optional_runman_id<'a>(
    params: &'a BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<Option<&'a str>, String> {
    let Some(val) = params.get(key) else {
        return Ok(None);
    };
    if matches!(val, JsonValue::Null) {
        return Ok(None);
    }
    let Some(raw) = val.as_str() else {
        return Err(format!("invalid {key}: expected string"));
    };
    let trimmed = raw.trim();
    if !is_valid_runman_identifier(trimmed) {
        return Err(format!(
            "invalid {key}: must match [A-Za-z0-9_.-]{{1,128}}"
        ));
    }
    Ok(Some(trimmed))
}

fn execute_runman_overload(req: &ActionRequest) -> ActionReceipt {
    let container_param = match validate_optional_runman_id(&req.params, "container") {
        Ok(v) => v,
        Err(msg) => return ActionReceipt::failed(req.id, &req.action_type, msg),
    };
    let container_name_param = match validate_optional_runman_id(&req.params, "container_name") {
        Ok(v) => v,
        Err(msg) => return ActionReceipt::failed(req.id, &req.action_type, msg),
    };
    let instance_id = match validate_optional_runman_id(&req.params, "instance_id") {
        Ok(v) => v,
        Err(msg) => return ActionReceipt::failed(req.id, &req.action_type, msg),
    };

    let fallback_container = {
        let trimmed = req.container_name.trim();
        if trimmed.is_empty() {
            None
        } else if is_valid_runman_identifier(trimmed) {
            Some(trimmed)
        } else {
            return ActionReceipt::failed(
                req.id,
                &req.action_type,
                "invalid container_name: must match [A-Za-z0-9_.-]{1,128}",
            );
        }
    };

    let Some(target_container) = container_param
        .or(container_name_param)
        .or(fallback_container)
        .or(instance_id)
    else {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            "missing required container or instance_id",
        );
    };

    let generation = match req.params.get("generation") {
        None | Some(JsonValue::Null) => None,
        Some(val) => {
            let Some(s) = val.as_str() else {
                return ActionReceipt::failed(
                    req.id,
                    &req.action_type,
                    "invalid generation: expected string",
                );
            };
            let trimmed = s.trim();
            if trimmed.chars().count() > 128 || trimmed.chars().any(|c| c.is_control()) {
                return ActionReceipt::failed(
                    req.id,
                    &req.action_type,
                    "invalid generation: must be <= 128 non-control characters",
                );
            }
            Some(trimmed)
        }
    };

    let endpoint = match req.action_type.as_str() {
        "runman_restart_overload" => "/v1/restart-overload",
        "runman_stop_overload" => "/v1/stop-overload",
        other => {
            return ActionReceipt::failed(
                req.id,
                &req.action_type,
                format!("unsupported runman overload action: {other}"),
            );
        }
    };

    let mut body = String::from("{");
    let _ = write!(body, "\"container_name\":{}", json_quote(target_container));
    if let Some(inst) = instance_id {
        let _ = write!(body, ",\"instance_id\":{}", json_quote(inst));
    }
    if let Some(gen) = generation {
        let _ = write!(body, ",\"generation\":{}", json_quote(gen));
    }
    if !req.project.is_empty() {
        let _ = write!(body, ",\"project\":{}", json_quote(&req.project));
    }
    body.push('}');

    #[cfg(unix)]
    if !Path::new(runtime_drivers::RUNMAN_SOCK_PATH).exists() {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("runman socket unavailable: {}", runtime_drivers::RUNMAN_SOCK_PATH),
        );
    }

    match runtime_drivers::runman_request(
        runtime_drivers::RUNMAN_SOCK_PATH,
        "POST",
        endpoint,
        Some(body.as_bytes()),
    ) {
        Ok((status, resp_body)) if (200..300).contains(&status) => {
            let detail = String::from_utf8_lossy(&resp_body);
            let msg = if detail.trim().is_empty() {
                format!("runman {endpoint} succeeded for {target_container} (HTTP {status})")
            } else {
                format!("runman {endpoint} succeeded for {target_container} (HTTP {status}): {}", detail.trim())
            };
            ActionReceipt::succeeded(req.id, &req.action_type, msg)
        }
        Ok((status, resp_body)) => {
            let detail = String::from_utf8_lossy(&resp_body);
            ActionReceipt::failed(
                req.id,
                &req.action_type,
                format!("runman {endpoint} returned HTTP {status}: {}", detail.trim()),
            )
        }
        Err(err) => ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("runman {endpoint} request failed: {err}"),
        ),
    }
}

fn is_valid_access_log_path(path: &str) -> bool {
    if !path.starts_with("/var/log/") || path.len() > 200 || path.contains("..") {
        return false;
    }
    let rest = &path["/var/log/".len()..];
    !rest.is_empty()
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-'))
}

fn execute_update_host_config(req: &ActionRequest, ctx: &mut ActionContext) -> ActionReceipt {
    if let Err(msg) = check_expected_node_id(req, ctx) {
        return ActionReceipt::failed(req.id, &req.action_type, msg);
    }
    let Some(cfg_obj) = req.params.get("config").and_then(JsonValue::as_object) else {
        return ActionReceipt::failed(req.id, &req.action_type, "no valid host configuration");
    };
    if !ctx.env_file.is_file() {
        return ActionReceipt::failed(req.id, &req.action_type, "client environment file not found");
    }

    let mut updates: BTreeMap<&'static str, String> = BTreeMap::new();
    for (key, val) in cfg_obj {
        let env_key = match key.as_str() {
            "host_id" => "HOST_ID",
            "report_interval" => "REPORT_INTERVAL",
            "action_poll_interval" => "ACTION_POLL_INTERVAL",
            "container_runtimes" => "CONTAINER_RUNTIMES",
            "docker_monitor_mode" => "DOCKER_MONITOR_MODE",
            "incus_project" => "INCUS_PROJECT",
            "security_monitor_enabled" => "SECURITY_MONITOR_ENABLED",
            "security_access_log_paths" => "SECURITY_ACCESS_LOG_PATHS",
            _ => continue,
        };
        if key == "security_access_log_paths" {
            let Some(arr) = val.as_array() else {
                return ActionReceipt::failed(req.id, &req.action_type, "unsafe access log paths");
            };
            if !(1..=20).contains(&arr.len()) {
                return ActionReceipt::failed(req.id, &req.action_type, "unsafe access log paths");
            }
            let mut joined = Vec::with_capacity(arr.len());
            for item in arr {
                let Some(s) = item.as_str() else {
                    return ActionReceipt::failed(req.id, &req.action_type, "unsafe access log paths");
                };
                if !is_valid_access_log_path(s) {
                    return ActionReceipt::failed(req.id, &req.action_type, "unsafe access log paths");
                }
                joined.push(s);
            }
            updates.insert(env_key, joined.join(","));
        } else if key == "security_monitor_enabled" {
            let b = val.as_bool().unwrap_or(false);
            updates.insert(env_key, if b { "true" } else { "false" }.to_string());
        } else {
            let raw = match val {
                JsonValue::String(s) => s.trim().to_string(),
                JsonValue::Number(n) => n.clone(),
                JsonValue::Bool(b) => b.to_string(),
                _ => return ActionReceipt::failed(req.id, &req.action_type, format!("invalid config value: {key}")),
            };
            if raw.chars().any(|c| matches!(c, '\r' | '\n' | '=' | '\\' | '"' | '\'')) {
                return ActionReceipt::failed(req.id, &req.action_type, format!("invalid config value: {key}"));
            }
            updates.insert(env_key, raw);
        }
    }

    if updates.is_empty() {
        return ActionReceipt::failed(req.id, &req.action_type, "no valid host configuration");
    }

    let Ok(existing) = fs::read_to_string(&ctx.env_file) else {
        return ActionReceipt::failed(req.id, &req.action_type, "unable to read client configuration");
    };

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut output: Vec<String> = Vec::new();
    for line in existing.lines() {
        let key = line.split('=').next().unwrap_or("");
        if let Some(new_val) = updates.get(key) {
            output.push(format!("{key}={new_val}"));
            seen.insert(key.to_string());
        } else {
            output.push(line.to_string());
        }
    }
    for (k, v) in &updates {
        if !seen.contains(*k) {
            output.push(format!("{k}={v}"));
        }
    }

    let tmp_path = ctx.env_file.with_extension(format!("env.tmp-{}", std::process::id()));
    let content = format!("{}\n", output.join("\n"));
    if let Err(err) = fs::write(&tmp_path, content.as_bytes()) {
        return ActionReceipt::failed(req.id, &req.action_type, format!("unable to write host config: {err}"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    }
    if let Err(err) = fs::rename(&tmp_path, &ctx.env_file) {
        let _ = fs::remove_file(&tmp_path);
        return ActionReceipt::failed(req.id, &req.action_type, format!("unable to replace host config: {err}"));
    }
    ctx.restart_required = true;
    ActionReceipt::succeeded(req.id, &req.action_type, "configuration saved; agent will restart")
}

fn execute_self_uninstall(
    req: &ActionRequest,
    script_path: &Path,
    ctx: &ActionContext,
) -> ActionReceipt {
    if req.id <= 0 {
        return ActionReceipt::failed(req.id, &req.action_type, "invalid uninstall action id");
    }
    if let Err(msg) = check_expected_node_id(req, ctx) {
        return ActionReceipt::failed(req.id, &req.action_type, msg);
    }
    let journal_path = Path::new("/var/lib/narwhal-monitor/quarantine-journal.json");
    if journal_path.exists() {
        match fs::read_to_string(journal_path) {
            Ok(raw) => {
                let trimmed = raw.trim();
                if !trimmed.is_empty() && trimmed != "{}" && trimmed != "[]" {
                    return ActionReceipt::failed(
                        req.id,
                        &req.action_type,
                        "pending network quarantine review; preserve recovery tooling and release/review first",
                    );
                }
            }
            Err(_) => {
                return ActionReceipt::failed(
                    req.id,
                    &req.action_type,
                    "quarantine recovery journal unavailable; refusing unattended uninstall",
                );
            }
        }
    }
    if !script_path.is_file() {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            "self-uninstall helper is unavailable; update Client first",
        );
    }
    match Command::new(script_path)
        .arg(req.id.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(_) => ActionReceipt::running(req.id, &req.action_type, "self-uninstall scheduled"),
        Err(err) => ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("unable to schedule self-uninstall: {err}"),
        ),
    }
}

fn execute_discover_access_logs(req: &ActionRequest, ctx: &ActionContext) -> ActionReceipt {
    if let Err(msg) = check_expected_node_id(req, ctx) {
        return ActionReceipt::failed(req.id, &req.action_type, msg);
    }
    let mut patterns: Vec<String> = vec![
        "/var/log/nginx/*access*.log".to_string(),
        "/var/log/caddy/*access*.log".to_string(),
        "/var/log/apache2/*access*.log".to_string(),
    ];
    for p in &ctx.configured_access_logs {
        if !p.contains('*') && !p.contains('?') {
            patterns.push(p.clone());
        }
    }
    let (mut candidates, _) = crate::expand_access_log_globs(&patterns);
    candidates.sort();
    candidates.dedup();

    let mut results = Vec::new();
    for path_str in candidates.into_iter().take(30) {
        let status;
        let mut samples = 0usize;
        let mut parsed_count = 0usize;
        let mut parse_errors = 0usize;
        let mut formats: BTreeSet<&'static str> = BTreeSet::new();
        let mut methods: BTreeSet<String> = BTreeSet::new();
        let mut statuses: BTreeSet<u16> = BTreeSet::new();
        let mut modified_at = 0u64;

        match fs::metadata(&path_str) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => status = "missing",
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => status = "permission_denied",
            Err(_) => status = "read_error",
            Ok(meta) => {
                modified_at = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                match fs::read(&path_str) {
                    Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => status = "permission_denied",
                    Err(_) => status = "read_error",
                    Ok(bytes) => {
                        let tail = if bytes.len() > 16384 {
                            &bytes[bytes.len() - 16384..]
                        } else {
                            &bytes[..]
                        };
                        let text = String::from_utf8_lossy(tail);
                        let lines: Vec<&str> = text.lines().collect();
                        let start_idx = lines.len().saturating_sub(20);
                        for line in &lines[start_idx..] {
                            samples += 1;
                            if let Some(ev) = crate::parse_access_log_line(line) {
                                parsed_count += 1;
                                if !ev.method.is_empty() {
                                    methods.insert(ev.method);
                                }
                                statuses.insert(ev.status);
                                formats.insert(if line.trim_start().starts_with('{') { "json" } else { "combined" });
                            } else {
                                parse_errors += 1;
                            }
                        }
                        status = if parsed_count > 0 {
                            "healthy"
                        } else if samples == 0 {
                            "idle"
                        } else {
                            "parse_error"
                        };
                    }
                }
            }
        }

        let fmt_json: Vec<String> = formats.iter().map(|s| json_quote(s)).collect();
        let method_json: Vec<String> = methods.iter().map(|s| json_quote(s)).collect();
        let status_json: Vec<String> = statuses.iter().map(|s| s.to_string()).collect();
        results.push(format!(
            "{{\"path\":{},\"status\":{},\"samples\":{},\"parsed\":{},\"parse_errors\":{},\"formats\":[{}],\"methods\":[{}],\"statuses\":[{}],\"modified_at\":{}}}",
            json_quote(&path_str),
            json_quote(status),
            samples,
            parsed_count,
            parse_errors,
            fmt_json.join(","),
            method_json.join(","),
            status_json.join(","),
            modified_at,
        ));
    }

    ActionReceipt::succeeded(req.id, &req.action_type, format!("[{}]", results.join(",")))
}

fn execute_host_security_rescan(req: &ActionRequest, ctx: &mut ActionContext) -> ActionReceipt {
    if let Err(msg) = check_expected_node_id(req, ctx) {
        return ActionReceipt::failed(req.id, &req.action_type, msg);
    }
    ctx.rescan_requested = true;
    ActionReceipt::succeeded(
        req.id,
        &req.action_type,
        "read-only host security rescan scheduled for next report",
    )
}

fn is_safe_container_target(name: &str) -> bool {
    (1..=200).contains(&name.len())
        && !name.starts_with('-')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'+' | b'-'))
}

fn execute_restart_container(req: &ActionRequest, ctx: &ActionContext) -> ActionReceipt {
    if let Err(msg) = check_expected_node_id(req, ctx) {
        return ActionReceipt::failed(req.id, &req.action_type, msg);
    }
    let runtime = req.runtime.trim().to_ascii_lowercase();
    if runtime == "runman" {
        return execute_runman_overload(req);
    }
    if !matches!(runtime.as_str(), "podman" | "docker" | "incus") {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("unsupported runtime for restart_container: {runtime}"),
        );
    }
    let target = req.container_name.trim();
    if !is_safe_container_target(target) {
        return ActionReceipt::failed(req.id, &req.action_type, "invalid container target");
    }
    let mut cmd = Command::new(&runtime);
    if runtime == "incus" && !req.project.is_empty() && is_safe_container_target(&req.project) {
        cmd.arg("--project").arg(&req.project);
    }
    cmd.arg("restart").arg(target);
    match cmd.output() {
        Ok(out) if out.status.success() => ActionReceipt::succeeded(
            req.id,
            &req.action_type,
            format!("{runtime} restarted {target}"),
        ),
        Ok(out) => ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("{runtime} restart failed: {}", String::from_utf8_lossy(&out.stderr).trim()),
        ),
        Err(err) => ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("unable to invoke {runtime} restart: {err}"),
        ),
    }
}

fn execute_freeze_container(req: &ActionRequest) -> ActionReceipt {
    let freeze = req.action_type == "freeze_container";
    let runtime = req.runtime.trim().to_ascii_lowercase();
    let target = req.container_name.trim();
    if !is_safe_container_target(target) {
        return ActionReceipt::failed(req.id, &req.action_type, "invalid container target");
    }

    // Direct pure-std cgroup v2 freeze when PID is supplied
    if let Some(pid) = req.params.get("pid").and_then(JsonValue::as_i64).filter(|&p| p > 1) {
        if let Some(cg_dir) = runtime_drivers::resolve_cgroup_dir_from_proc(
            Path::new("/proc"),
            Path::new("/sys/fs/cgroup"),
            pid as u32,
        ) {
            let freeze_path = cg_dir.join("cgroup.freeze");
            if freeze_path.is_file() {
                if fs::write(&freeze_path, if freeze { b"1" } else { b"0" }).is_ok() {
                    return ActionReceipt::succeeded(
                        req.id,
                        &req.action_type,
                        format!(
                            "cgroup {} succeeded for {target}",
                            if freeze { "freeze" } else { "unfreeze" }
                        ),
                    );
                }
            }
        }
    }

    if !matches!(runtime.as_str(), "podman" | "docker") {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("unable to freeze/unfreeze {runtime} container without valid cgroup pid"),
        );
    }
    let subcmd = if freeze { "pause" } else { "unpause" };
    match Command::new(&runtime).arg(subcmd).arg(target).output() {
        Ok(out) if out.status.success() => ActionReceipt::succeeded(
            req.id,
            &req.action_type,
            format!("{runtime} {subcmd} succeeded for {target}"),
        ),
        Ok(out) => ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("{runtime} {subcmd} failed: {}", String::from_utf8_lossy(&out.stderr).trim()),
        ),
        Err(err) => ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("unable to execute {runtime} {subcmd}: {err}"),
        ),
    }
}

fn execute_apply_host_firewall_policy(
    req: &ActionRequest,
    ctx: &ActionContext,
) -> ActionReceipt {
    if req.runtime != "host" || req.container_name != "__host__" {
        return ActionReceipt::failed(req.id, &req.action_type, "host firewall policy action has an invalid scope");
    }
    if check_expected_node_id(req, ctx).is_err() {
        return ActionReceipt::failed(req.id, &req.action_type, "host firewall policy belongs to another Watcher node");
    }
    let Some(policy_val) = req.params.get("policy") else {
        return ActionReceipt::failed(req.id, &req.action_type, "host firewall policy data is invalid");
    };
    let Some(revision) = policy_val.get("revision").and_then(JsonValue::as_i64).filter(|&r| r >= 1) else {
        return ActionReceipt::failed(req.id, &req.action_type, "host firewall policy revision is missing or invalid");
    };
    if policy_val.get("rules").and_then(JsonValue::as_array).is_none()
        || policy_val.get("abuse").and_then(JsonValue::as_object).is_none()
    {
        return ActionReceipt::failed(req.id, &req.action_type, "host firewall policy data is invalid");
    }

    if !Path::new(RUNMAN_FIREWALL_SOCK_PATH).exists() {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            "Runman firewall socket unavailable; no host firewall change was confirmed",
        );
    }

    let body = policy_val.to_json();
    match runtime_drivers::runman_request(
        RUNMAN_FIREWALL_SOCK_PATH,
        "POST",
        "/v1/firewall/policy",
        Some(body.as_bytes()),
    ) {
        Ok((200, resp_body)) => {
            let text = String::from_utf8_lossy(&resp_body);
            let msg = parse_json(&text)
                .ok()
                .and_then(|v| v.get("message").and_then(JsonValue::as_str).map(|s| s.to_string()))
                .unwrap_or_else(|| "Runman host firewall policy updated".to_string());
            // Read back revision to verify persistence.
            match runtime_drivers::runman_request(RUNMAN_FIREWALL_SOCK_PATH, "GET", "/v1/firewall/policy", None) {
                Ok((200, rb_body)) => {
                    let rb_text = String::from_utf8_lossy(&rb_body);
                    let rb_rev = parse_json(&rb_text)
                        .ok()
                        .and_then(|v| v.get("revision").and_then(JsonValue::as_i64));
                    if rb_rev == Some(revision) {
                        ActionReceipt::succeeded(
                            req.id,
                            &req.action_type,
                            format!("{msg}; readback verified revision {revision}"),
                        )
                    } else {
                        ActionReceipt::failed(
                            req.id,
                            &req.action_type,
                            format!("host firewall readback mismatch: expected revision {revision}"),
                        )
                    }
                }
                _ => ActionReceipt::failed(
                    req.id,
                    &req.action_type,
                    "host firewall applied but readback verification failed",
                ),
            }
        }
        Ok((status, resp_body)) => ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("Runman rejected host firewall policy (HTTP {status}): {}", String::from_utf8_lossy(&resp_body).trim()),
        ),
        Err(err) => ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("Runman firewall socket error: {err}"),
        ),
    }
}

fn execute_delete_host_firewall_rule(
    req: &ActionRequest,
    ctx: &ActionContext,
) -> ActionReceipt {
    if req.runtime != "host" || req.container_name != "__host__" {
        return ActionReceipt::failed(req.id, &req.action_type, "host firewall rule deletion action has an invalid scope");
    }
    if let Err(_) = check_expected_node_id(req, ctx) {
        return ActionReceipt::failed(req.id, &req.action_type, "host firewall rule deletion belongs to another Watcher node");
    }
    let Some(rule_val) = req.params.get("rule") else {
        return ActionReceipt::failed(req.id, &req.action_type, "manual RFW rule identity is missing or invalid");
    };
    let Some(rule_id) = rule_val.get("id").and_then(JsonValue::as_i64).filter(|&id| id >= 1) else {
        return ActionReceipt::failed(req.id, &req.action_type, "manual RFW rule identity is missing or invalid");
    };
    if rule_val.get("origin").and_then(JsonValue::as_str) != Some("manual")
        || rule_val.get("sync_state").and_then(JsonValue::as_str) != Some("manual")
        || rule_val
            .get("managed_key")
            .and_then(JsonValue::as_str)
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            "only a confirmed manual RFW rule can be deleted directly",
        );
    }
    if !Path::new(RUNMAN_FIREWALL_SOCK_PATH).exists() {
        return ActionReceipt::failed(
            req.id,
            &req.action_type,
            "Runman firewall socket unavailable; no RFW rule deletion was confirmed",
        );
    }
    let body = rule_val.to_json();
    let endpoint = format!("/v1/firewall/rules/{rule_id}");
    match runtime_drivers::runman_request(
        RUNMAN_FIREWALL_SOCK_PATH,
        "DELETE",
        &endpoint,
        Some(body.as_bytes()),
    ) {
        Ok((200, resp_body)) => {
            let text = String::from_utf8_lossy(&resp_body);
            let msg = parse_json(&text)
                .ok()
                .and_then(|v| v.get("message").and_then(JsonValue::as_str).map(|s| s.to_string()))
                .unwrap_or_else(|| "RFW manual rule deleted".to_string());
            ActionReceipt::succeeded(req.id, &req.action_type, msg)
        }
        Ok((status, resp_body)) => ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("Runman rejected RFW rule deletion (HTTP {status}): {}", String::from_utf8_lossy(&resp_body).trim()),
        ),
        Err(err) => ActionReceipt::failed(
            req.id,
            &req.action_type,
            format!("Runman firewall socket error: {err}"),
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
        let r4 = execute_managed_upgrade(
            &missing_script,
            Path::new("/nonexistent/managed-client-update.sh"),
            &ActionContext::default(),
        );
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

    #[test]
    fn test_kill_pid_validation_rejects_pid_le_one_and_invalid_values() {
        for (idx, payload) in [
            r#"{"id":30,"action_type":"kill_pid","params":{}}"#,
            r#"{"id":31,"action_type":"kill_pid","params":{"pid":0}}"#,
            r#"{"id":32,"action_type":"kill_pid","params":{"pid":1}}"#,
            r#"{"id":33,"action_type":"stop_socks_process","params":{"pid":1}}"#,
            r#"{"id":34,"action_type":"kill_pid","params":{"pid":-5}}"#,
            r#"{"id":35,"action_type":"kill_pid","params":{"pid":"1"}}"#,
            r#"{"id":36,"action_type":"kill_pid","params":{"pid":"123;id"}}"#,
            r#"{"id":37,"action_type":"kill_pid","params":{"pid":4294967296}}"#,
        ]
        .iter()
        .enumerate()
        {
            let req = ActionRequest::from_json(payload).unwrap();
            let receipt = execute_action(&req);
            assert!(!receipt.ok, "case {idx} should fail: {payload}");
            assert_eq!(receipt.status, "failed");
            assert!(
                receipt.message.contains("pid"),
                "case {idx} should mention pid validation error, got: {}",
                receipt.message
            );
        }

        // Valid pid > 1 passes validation (fails gracefully on non-Unix or missing /proc/<pid>/stat)
        let valid_req = ActionRequest::from_json(
            r#"{"id":38,"action_type":"stop_socks_process","params":{"pid":99999999}}"#,
        )
        .unwrap();
        let valid_receipt = execute_action(&valid_req);
        assert!(!valid_receipt.ok);
        assert!(
            valid_receipt.message.contains("does not exist")
                || valid_receipt.message.contains("only supported on Unix"),
            "unexpected message for valid pid: {}",
            valid_receipt.message
        );
    }

    #[test]
    fn test_runman_overload_validation_rejects_empty_and_unsafe_container_id() {
        let too_long_id = "a".repeat(129);
        let too_long_gen = "g".repeat(129);
        let long_id_json = format!(
            r#"{{"id":40,"action_type":"runman_restart_overload","params":{{"container":"{too_long_id}"}}}}"#
        );
        let long_gen_json = format!(
            r#"{{"id":41,"action_type":"runman_stop_overload","params":{{"container":"ct-1","generation":"{too_long_gen}"}}}}"#
        );

        let invalid_cases = [
            r#"{"id":42,"action_type":"runman_restart_overload","params":{}}"#,
            r#"{"id":43,"action_type":"runman_stop_overload","params":{"container":""}}"#,
            r#"{"id":44,"action_type":"runman_restart_overload","params":{"container":"../evil"}}"#,
            r#"{"id":45,"action_type":"runman_stop_overload","params":{"container":"ct;rm -rf /"}}"#,
            r#"{"id":46,"action_type":"runman_restart_overload","params":{"instance_id":"bad/id"}}"#,
            r#"{"id":47,"action_type":"runman_stop_overload","params":{"container":"ct-1","generation":"bad\nline"}}"#,
            long_id_json.as_str(),
            long_gen_json.as_str(),
        ];

        for (idx, payload) in invalid_cases.iter().enumerate() {
            let req = ActionRequest::from_json(payload).unwrap();
            let receipt = execute_action(&req);
            assert!(!receipt.ok, "case {idx} should fail: {payload}");
            assert_eq!(receipt.status, "failed");
        }

        // Valid container + generation passes validation and fails gracefully when socket is absent / non-Unix
        for action_type in ["runman_restart_overload", "runman_stop_overload"] {
            let valid_json = format!(
                r#"{{"id":50,"action_type":"{action_type}","params":{{"container":"ct_1.prod-01","instance_id":"inst-123","generation":"gen-42"}}}}"#
            );
            let req = ActionRequest::from_json(&valid_json).unwrap();
            let receipt = execute_action(&req);
            assert!(!receipt.ok);
            assert!(
                receipt.message.contains("socket")
                    || receipt.message.contains("Unix")
                    || receipt.message.contains("request failed"),
                "expected graceful socket/platform failure, got: {}",
                receipt.message
            );
        }
    }

    #[test]
    fn test_mainline_host_config_rescan_discover_and_firewall_validation() {
        let dir = std::env::temp_dir().join("narwhal-actions-mainline-test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let env_file = dir.join("client.env");
        fs::write(&env_file, "HOST_ID=old-host\nREPORT_INTERVAL=300\nSECURITY_MONITOR_ENABLED=true\n").unwrap();

        let log_file = dir.join("access.log");
        fs::write(&log_file, "203.0.113.1 - - [16/Nov/2026:12:00:00 +0800] \"GET /health HTTP/1.1\" 200 2\n").unwrap();

        let mut ctx = ActionContext {
            node_id: "node-xyz".to_string(),
            env_file: env_file.clone(),
            configured_access_logs: vec![log_file.to_string_lossy().into_owned()],
            rescan_requested: false,
            restart_required: false,
        };

        // Mismatched node_id must be rejected
        let bad_cfg = ActionRequest::from_json(
            r#"{"id":60,"action_type":"update_host_config","params":{"expected_node_id":"wrong","config":{"host_id":"new"}}}"#,
        )
        .unwrap();
        let r_bad_cfg = execute_action_with_context(&bad_cfg, &mut ctx);
        assert!(!r_bad_cfg.ok);
        assert!(!ctx.restart_required);

        // Unsafe access log path must be rejected
        let bad_paths = ActionRequest::from_json(
            r#"{"id":61,"action_type":"update_host_config","params":{"expected_node_id":"node-xyz","config":{"security_access_log_paths":["/etc/passwd"]}}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&bad_paths, &mut ctx).ok);

        // Valid host config update mutates client.env and requests restart
        let ok_cfg = ActionRequest::from_json(
            r#"{"id":62,"action_type":"update_host_config","params":{"expected_node_id":"node-xyz","config":{"host_id":"new-host","report_interval":120,"security_monitor_enabled":false,"security_access_log_paths":["/var/log/nginx/access.log"]}}}"#,
        )
        .unwrap();
        let r_ok_cfg = execute_action_with_context(&ok_cfg, &mut ctx);
        assert!(r_ok_cfg.ok);
        assert!(ctx.restart_required);
        let written = fs::read_to_string(&env_file).unwrap();
        assert!(written.contains("HOST_ID=new-host"));
        assert!(written.contains("REPORT_INTERVAL=120"));
        assert!(written.contains("SECURITY_MONITOR_ENABLED=false"));
        assert!(written.contains("SECURITY_ACCESS_LOG_PATHS=/var/log/nginx/access.log"));

        // host_security_rescan sets rescan flag
        let rescan_req = ActionRequest::from_json(
            r#"{"id":63,"action_type":"host_security_rescan","params":{"expected_node_id":"node-xyz"}}"#,
        )
        .unwrap();
        let r_rescan = execute_action_with_context(&rescan_req, &mut ctx);
        assert!(r_rescan.ok);
        assert!(ctx.rescan_requested);

        // discover_access_logs finds & parses configured log
        let disc_req = ActionRequest::from_json(
            r#"{"id":64,"action_type":"discover_access_logs","params":{"expected_node_id":"node-xyz"}}"#,
        )
        .unwrap();
        let r_disc = execute_action_with_context(&disc_req, &mut ctx);
        assert!(r_disc.ok);
        assert!(r_disc.message.contains("access.log"));
        assert!(r_disc.message.contains("\"status\":\"healthy\""));

        // Host firewall policy rejects wrong scope and non-manual delete
        let bad_fw = ActionRequest::from_json(
            r#"{"id":65,"action_type":"apply_host_firewall_policy","runtime":"podman","container_name":"c1","params":{"expected_node_id":"node-xyz","policy":{"revision":1,"rules":[],"abuse":{}}}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&bad_fw, &mut ctx).ok);

        let bad_del = ActionRequest::from_json(
            r#"{"id":66,"action_type":"delete_host_firewall_rule","runtime":"host","container_name":"__host__","params":{"expected_node_id":"node-xyz","rule":{"id":1,"origin":"auto","sync_state":"manual"}}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&bad_del, &mut ctx).ok);

        let _ = fs::remove_dir_all(&dir);
    }
}
