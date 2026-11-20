use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::*;

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
