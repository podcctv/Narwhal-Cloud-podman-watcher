use std::collections::{BTreeMap, HashSet};

use crate::*;

// ---------------------------------------------------------------------------
// 3. Regex-equivalent character validators
// ---------------------------------------------------------------------------

fn is_iface_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'+' | b'-')
}

pub fn is_valid_iface_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 15 && s.bytes().all(is_iface_char)
}

pub(crate) fn is_safe_sysfs_iface(s: &str) -> bool {
    is_valid_iface_name(s) && s != "." && s != ".."
}

pub(crate) fn is_valid_container_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 200 && s.bytes().all(is_iface_char)
}

pub(crate) fn is_valid_container_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(is_iface_char)
}

pub(crate) fn is_valid_incus_project(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

pub(crate) fn is_valid_runtime_bin(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 240
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'+' | b'-'))
}

pub(crate) fn is_valid_hex64_lower(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn is_valid_uuid(s: &str) -> bool {
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
