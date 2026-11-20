use std::collections::BTreeMap;
use std::fmt::Write as _;

use proc_probe::json_escape;

const MAX_JSON_DEPTH: usize = 64;

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

pub(crate) fn format_f64_json(val: f64) -> String {
    let clean = if val == 0.0 { 0.0 } else { val };
    if clean.fract() == 0.0 {
        format!("{clean:.1}")
    } else {
        format!("{clean}")
    }
}

pub(crate) fn round3(val: f64) -> f64 {
    let r = (val * 1000.0).round() / 1000.0;
    if r == 0.0 {
        0.0
    } else {
        r
    }
}

pub(crate) fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}
