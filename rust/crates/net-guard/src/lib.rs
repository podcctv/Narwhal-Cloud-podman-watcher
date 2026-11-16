#![forbid(unsafe_code)]

//! Pure-`std`, `#![forbid(unsafe_code)]` network guard and quarantine migration crate.
//!
//! Mirrors the validation, nftables/iptables command construction, Unix-socket /
//! runtime driver protocols, atomic `0o600` journal persistence, and release /
//! replacement-verification contracts of:
//! - `client/udp_guard.py`
//! - `client/anti_spoof_guard.py`
//! - `client/network_quarantine.py`
//! - `client/agent.py` (lines 8455-8685)

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixStream;

use proc_probe::json_escape;
use runtime_drivers::{runman_request, JsonVal, RUNMAN_SOCK_PATH};

pub const DEFAULT_UDP_BLACKHOLE_JOURNAL: &str = "/var/lib/narwhal-agent/udp-blackhole.json";
pub const UDP_BLACKHOLE_JOURNAL_ENV: &str = "NARWHAL_UDP_BLACKHOLE_JOURNAL";
pub const UDP_NFT_TABLE: &str = "narwhal_udp_guard";

pub const DEFAULT_ANTI_SPOOF_JOURNAL: &str = "/var/lib/narwhal-agent/anti-spoof.json";
pub const ANTI_SPOOF_JOURNAL_ENV: &str = "NARWHAL_ANTI_SPOOF_JOURNAL";
pub const ANTI_SPOOF_NFT_TABLE: &str = "narwhal_antispoof";

pub const DEFAULT_QUARANTINE_JOURNAL: &str = "/opt/narwhal-monitor/abuse-quarantine.json";
pub const QUARANTINE_JOURNAL_ENV: &str = "SECURITY_ABUSE_QUARANTINE_FILE";

pub const DEFAULT_INCUS_SOCKET: &str = "/var/lib/incus/unix.socket";
pub const DEFAULT_RUNMAN_SOCKET: &str = RUNMAN_SOCK_PATH;

pub const MAX_JOURNAL_ENTRIES: usize = 1000;
pub const MAX_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;
#[cfg(unix)]
const MAX_INCUS_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RUNMAN_QUARANTINE_BYTES: usize = 16 * 1024;
const MAX_RUNMAN_INVENTORY_BYTES: usize = 2 * 1024 * 1024;

const CMD_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(unix)]
const INCUS_IO_TIMEOUT: Duration = Duration::from_secs(35);

pub const PROTECTED_CONTAINERS: &[&str] = &[
    "narwhal-monitor-client",
    "narwhal-monitor-server",
    "narwhal-monitor-caddy",
];

pub const PODMAN_INSPECT_FORMAT: &str = concat!(
    r#"[{"Id":{{json .ID}},"Pod":{{json .Pod}},"HostConfig":{"#,
    r#""NetworkMode":{{json .HostConfig.NetworkMode}},"PidMode":{{json .HostConfig.PidMode}},"#,
    r#""Privileged":{{json .HostConfig.Privileged}},"Devices":{{if .HostConfig.Devices}}[{}]{{else}}[]{{end}}},"#,
    r#""NetworkSettings":{"Networks":{{json .NetworkSettings.Networks}}},"State":{"Pid":{{json .State.Pid}}}}]"#,
);

static UDP_JOURNAL_LOCK: Mutex<()> = Mutex::new(());
static SPOOF_JOURNAL_LOCK: Mutex<()> = Mutex::new(());
static QUARANTINE_LOCK: Mutex<()> = Mutex::new(());
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------
// 1. Common Types, Validation, Time, Binary Discovery & Command Runner
// ---------------------------------------------------------------------------

/// Standardized action result matching `(ok: bool, message: str)` in `client/agent.py`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionOutcome {
    pub ok: bool,
    pub message: String,
}

impl ActionOutcome {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
        }
    }

    pub fn into_result(self) -> Result<String, String> {
        if self.ok {
            Ok(self.message)
        } else {
            Err(self.message)
        }
    }
}

impl From<Result<String, String>> for ActionOutcome {
    fn from(res: Result<String, String>) -> Self {
        match res {
            Ok(msg) => Self::ok(msg),
            Err(msg) => Self::err(msg),
        }
    }
}

impl From<ActionOutcome> for Result<String, String> {
    fn from(outcome: ActionOutcome) -> Self {
        outcome.into_result()
    }
}

pub fn current_unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn lock_guard(mutex: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Validates `_SAFE_KEY`: `^[A-Za-z0-9_.:@+-]{1,256}$`.
pub fn is_safe_key(s: &str) -> bool {
    let bytes = s.as_bytes();
    (1..=256).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'+' | b'-'))
}

/// Validates `_SAFE_VETH`: `^[A-Za-z0-9_.-]{1,16}$` (rejecting `.` and `..`).
pub fn is_safe_veth(s: &str) -> bool {
    let bytes = s.as_bytes();
    (1..=16).contains(&bytes.len())
        && s != "."
        && !s.contains("..")
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Validates quarantine container names: `^[A-Za-z0-9_.:@+-]{1,200}$` and not protected.
pub fn is_safe_quarantine_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    (1..=200).contains(&bytes.len())
        && !PROTECTED_CONTAINERS.contains(&s)
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'+' | b'-'))
}

/// Validates quarantine project names: `^[A-Za-z0-9_.-]{1,100}$`.
pub fn is_safe_project(s: &str) -> bool {
    let bytes = s.as_bytes();
    (1..=100).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Validates instance identity: `^[A-Za-z0-9-]{12,100}$`.
pub fn is_safe_instance_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    (12..=100).contains(&bytes.len())
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// Validates canonical lowercase UUID `[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}`.
pub fn is_uuid_lower(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(i, &b)| match i {
        8 | 13 | 18 | 23 => b == b'-',
        _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
    })
}

/// Validates canonical lowercase UUID v4 `[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`.
pub fn is_uuid_v4_lower(s: &str) -> bool {
    if !is_uuid_lower(s) {
        return false;
    }
    let bytes = s.as_bytes();
    bytes[14] == b'4' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

/// Validates Podman replacement identity `^[0-9a-fA-F]{12,64}$`.
pub fn is_hex_12_64(s: &str) -> bool {
    let bytes = s.as_bytes();
    (12..=64).contains(&bytes.len()) && bytes.iter().all(|b| b.is_ascii_hexdigit())
}

/// Validates Incus async operation path `^/1\.0/operations/[a-fA-F0-9-]{36}$`.
pub fn is_valid_incus_operation(op: &str) -> bool {
    let Some(rest) = op.strip_prefix("/1.0/operations/") else {
        return false;
    };
    rest.len() == 36
        && rest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-')
}

fn is_safe_evidence_token(s: &str) -> bool {
    let bytes = s.as_bytes();
    (1..=100).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

pub trait CommandRunner {
    fn run(&mut self, args: &[String], stdin: Option<&str>) -> (bool, String);
}

pub struct LiveCommandRunner;

impl CommandRunner for LiveCommandRunner {
    fn run(&mut self, args: &[String], stdin: Option<&str>) -> (bool, String) {
        if args.is_empty() {
            return (false, "empty command".to_string());
        }
        let mut cmd = Command::new(&args[0]);
        cmd.args(&args[1..])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) => return (false, err.to_string()),
        };

        if let Some(input) = stdin {
            if let Some(mut child_stdin) = child.stdin.take() {
                let _ = child_stdin.write_all(input.as_bytes());
            }
        }

        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let stdout_handle = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(out) = stdout_pipe {
                let _ = out.take(1024 * 1024).read_to_end(&mut buf);
            }
            buf
        });
        let stderr_handle = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(err) = stderr_pipe {
                let _ = err.take(1024 * 1024).read_to_end(&mut buf);
            }
            buf
        });

        let deadline = Instant::now() + CMD_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Ok(st),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break Err("command timed out".to_string());
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(err) => break Err(err.to_string()),
            }
        };

        let stdout_bytes = stdout_handle.join().unwrap_or_default();
        let stderr_bytes = stderr_handle.join().unwrap_or_default();
        match status {
            Ok(st) => {
                let mut combined = String::from_utf8_lossy(&stdout_bytes).into_owned();
                combined.push_str(&String::from_utf8_lossy(&stderr_bytes));
                (st.success(), combined)
            }
            Err(msg) => (false, msg),
        }
    }
}

pub struct ClosureCommandRunner<F>(pub F);

impl<F> CommandRunner for ClosureCommandRunner<F>
where
    F: FnMut(&[String], Option<&str>) -> (bool, String),
{
    fn run(&mut self, args: &[String], stdin: Option<&str>) -> (bool, String) {
        (self.0)(args, stdin)
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetToolPaths {
    pub nsenter_bin: Option<String>,
    pub nft_bin: Option<String>,
    pub iptables_bin: Option<String>,
    pub podman_bin: Option<String>,
    pub sysctl_bin: Option<String>,
}

impl NetToolPaths {
    pub fn discover() -> Self {
        Self {
            nsenter_bin: find_binary("nsenter"),
            nft_bin: find_binary("nft"),
            iptables_bin: find_binary("iptables"),
            podman_bin: find_binary("podman"),
            sysctl_bin: find_binary("sysctl"),
        }
    }
}

fn find_binary(name: &str) -> Option<String> {
    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    for fallback_dir in ["/usr/sbin", "/sbin", "/usr/bin", "/usr/local/bin", "/bin"] {
        let candidate = Path::new(fallback_dir).join(name);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 2. JSON Serialization & Atomic 0600 Journal Persistence
// ---------------------------------------------------------------------------

/// Serialize a `JsonVal` cleanly to JSON (compact or 2-space indented).
pub fn json_val_to_string(val: &JsonVal, pretty: bool) -> String {
    let mut out = String::new();
    write_json_val(val, &mut out, pretty, 0);
    out
}

fn write_json_val(val: &JsonVal, out: &mut String, pretty: bool, depth: usize) {
    match val {
        JsonVal::Null => out.push_str("null"),
        JsonVal::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JsonVal::Num(n) => {
            if !n.is_finite() {
                out.push_str("null");
            } else if n.fract() == 0.0 && *n >= (i64::MIN as f64) && *n <= (i64::MAX as f64) {
                let i = *n as i64;
                let _ = write!(out, "{i}");
            } else {
                let _ = write!(out, "{n}");
            }
        }
        JsonVal::Str(s) => {
            out.push('"');
            out.push_str(&json_escape(s));
            out.push('"');
        }
        JsonVal::Arr(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    push_indent(out, depth + 1);
                }
                write_json_val(item, out, pretty, depth + 1);
            }
            if pretty {
                out.push('\n');
                push_indent(out, depth);
            }
            out.push(']');
        }
        JsonVal::Obj(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (idx, (k, v)) in map.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    push_indent(out, depth + 1);
                }
                out.push('"');
                out.push_str(&json_escape(k));
                out.push_str(if pretty { "\": " } else { "\":" });
                write_json_val(v, out, pretty, depth + 1);
            }
            if pretty {
                out.push('\n');
                push_indent(out, depth);
            }
            out.push('}');
        }
    }
}

fn push_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn env_path_or(env_key: &str, default_path: &str) -> PathBuf {
    if let Ok(raw) = env::var(env_key) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    PathBuf::from(default_path)
}

pub fn resolve_udp_blackhole_journal_path() -> PathBuf {
    env_path_or(UDP_BLACKHOLE_JOURNAL_ENV, DEFAULT_UDP_BLACKHOLE_JOURNAL)
}

pub fn resolve_anti_spoof_journal_path() -> PathBuf {
    env_path_or(ANTI_SPOOF_JOURNAL_ENV, DEFAULT_ANTI_SPOOF_JOURNAL)
}

pub fn resolve_quarantine_journal_path() -> Result<PathBuf, String> {
    let path = env_path_or(QUARANTINE_JOURNAL_ENV, DEFAULT_QUARANTINE_JOURNAL);
    if !path.is_absolute() {
        return Err("journal path must be absolute".to_string());
    }
    Ok(path)
}

/// Read a JSON object journal safely (rejecting symlinks, oversized files, and >1000 entries).
pub fn read_json_journal(path: &Path) -> Result<BTreeMap<String, JsonVal>, String> {
    let lmeta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(err) => return Err(format!("unable to read journal metadata: {err}")),
    };
    if lmeta.file_type().is_symlink() || !lmeta.is_file() || lmeta.len() > MAX_JOURNAL_BYTES {
        return Err("invalid journal file or symlink rejected".to_string());
    }

    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(err) => return Err(format!("unable to open journal: {err}")),
    };
    let meta = file
        .metadata()
        .map_err(|err| format!("unable to stat journal: {err}"))?;
    if !meta.is_file() || meta.len() > MAX_JOURNAL_BYTES {
        return Err("invalid journal format or size limit exceeded".to_string());
    }

    let mut buf = Vec::with_capacity((meta.len() as usize).min(65536));
    std::io::Read::take(file, MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|err| format!("unable to read journal: {err}"))?;
    if (buf.len() as u64) > MAX_JOURNAL_BYTES {
        return Err("journal exceeds 8 MiB limit".to_string());
    }

    let text = String::from_utf8(buf).map_err(|_| "journal contains invalid UTF-8".to_string())?;
    let parsed = JsonVal::parse(&text).map_err(|err| format!("corrupted journal JSON: {err}"))?;
    let JsonVal::Obj(map) = parsed else {
        return Err("invalid journal schema: expected JSON object".to_string());
    };
    if map.len() > MAX_JOURNAL_ENTRIES {
        return Err("journal exceeds entry capacity limit".to_string());
    }
    Ok(map)
}

/// Atomically persist a JSON object journal with `0o600` permissions and symlink protection.
pub fn write_json_journal(
    path: &Path,
    data: &BTreeMap<String, JsonVal>,
    temp_prefix: &str,
    pretty: bool,
) -> Result<(), String> {
    if data.len() > MAX_JOURNAL_ENTRIES {
        return Err("journal exceeds capacity limit".to_string());
    }

    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|err| format!("cannot resolve working directory: {err}"))?
            .join(path)
    };
    let directory = abs_path
        .parent()
        .ok_or_else(|| "journal path has no parent directory".to_string())?;

    create_secure_dir(directory)?;

    if let Ok(meta) = fs::symlink_metadata(&abs_path) {
        if meta.file_type().is_symlink() {
            return Err("拒绝向符号链接写入日志".to_string());
        }
    }

    let payload = json_val_to_string(&JsonVal::Obj(data.clone()), pretty);
    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let temp_path = directory.join(format!("{temp_prefix}{pid}-{seq}.tmp"));

    let write_res = (|| -> Result<(), String> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = opts
            .open(&temp_path)
            .map_err(|err| format!("failed to create temp journal: {err}"))?;

        #[cfg(unix)]
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("failed to set 0600 permissions: {err}"))?;

        file.write_all(payload.as_bytes())
            .map_err(|err| format!("failed to write journal payload: {err}"))?;
        file.flush()
            .map_err(|err| format!("failed to flush journal: {err}"))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync journal: {err}"))?;
        drop(file);

        fs::rename(&temp_path, &abs_path)
            .map_err(|err| format!("failed to replace journal atomically: {err}"))?;
        sync_directory(directory);
        Ok(())
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_res
}

#[cfg(unix)]
fn create_secure_dir(dir: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(dir)
        .map_err(|err| format!("failed to create journal directory: {err}"))
}

#[cfg(not(unix))]
fn create_secure_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|err| format!("failed to create journal directory: {err}"))
}

#[cfg(unix)]
fn sync_directory(dir: &Path) {
    if let Ok(dir_file) = fs::File::open(dir) {
        let _ = dir_file.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_directory(_dir: &Path) {}

// ---------------------------------------------------------------------------
// 3. UDP Egress Blackhole Guard (`client/udp_guard.py`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpBlackholeApply {
    pub runtime: String,
    pub name: String,
    pub pid: u32,
    pub instance_id: String,
    pub allow_dns: bool,
    pub project: String,
    pub auto_triggered: bool,
    pub duration: u64,
    pub reason: String,
}

impl UdpBlackholeApply {
    pub fn new(runtime: impl Into<String>, name: impl Into<String>, pid: u32) -> Self {
        Self {
            runtime: runtime.into(),
            name: name.into(),
            pid,
            instance_id: String::new(),
            allow_dns: true,
            project: "default".to_string(),
            auto_triggered: false,
            duration: 1800,
            reason: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpBlackholeStatus {
    pub active: bool,
    pub allow_dns: bool,
    pub applied_at: Option<u64>,
    pub auto_triggered: bool,
    pub expires_at: Option<u64>,
    pub remaining_seconds: Option<u64>,
    pub reason: String,
}

impl UdpBlackholeStatus {
    pub fn to_json(&self) -> String {
        let applied = self
            .applied_at
            .map_or_else(|| "null".to_string(), |v| v.to_string());
        let expires = self
            .expires_at
            .map_or_else(|| "null".to_string(), |v| v.to_string());
        let remaining = self
            .remaining_seconds
            .map_or_else(|| "null".to_string(), |v| v.to_string());
        format!(
            "{{\"active\":{},\"allow_dns\":{},\"applied_at\":{applied},\"auto_triggered\":{},\"expires_at\":{expires},\"remaining_seconds\":{remaining},\"reason\":\"{}\"}}",
            self.active,
            self.allow_dns,
            self.auto_triggered,
            json_escape(&self.reason),
        )
    }
}

/// Build the nftables ruleset injected inside the container network namespace.
pub fn build_udp_nft_rules(allow_dns: bool) -> String {
    let dns_rule = if allow_dns {
        "        udp dport 53 accept\n"
    } else {
        ""
    };
    format!(
        "table inet {UDP_NFT_TABLE} {{\n    chain output {{\n        type filter hook output priority 0; policy accept;\n        oif \"lo\" accept\n        ct state established,related accept\n{dns_rule}        ip protocol udp drop\n        ip6 nexthdr udp drop\n    }}\n}}\n"
    )
}

/// Build the fallback iptables/ip6tables apply shell script for container netns.
pub fn build_udp_iptables_apply_script(allow_dns: bool) -> String {
    let dns_part = if allow_dns {
        "iptables -C OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -p udp --dport 53 -j ACCEPT; \
         ip6tables -C OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 1 -p udp --dport 53 -j ACCEPT; "
    } else {
        ""
    };
    format!(
        "iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -o lo -j ACCEPT; \
         iptables -C OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I OUTPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT; \
         {dns_part}\
         iptables -C OUTPUT -p udp -j DROP 2>/dev/null || iptables -A OUTPUT -p udp -j DROP; \
         ip6tables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 1 -o lo -j ACCEPT; \
         ip6tables -C OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT; \
         ip6tables -C OUTPUT -p udp -j DROP 2>/dev/null || ip6tables -A OUTPUT -p udp -j DROP"
    )
}

/// Build the fallback iptables/ip6tables release shell script for container netns.
pub fn build_udp_iptables_release_script() -> &'static str {
    "iptables -D OUTPUT -p udp -j DROP 2>/dev/null || true; \
     iptables -D OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true; \
     ip6tables -D OUTPUT -p udp -j DROP 2>/dev/null || true; \
     ip6tables -D OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true"
}

pub fn apply_udp_blackhole(req: &UdpBlackholeApply) -> ActionOutcome {
    let journal_path = resolve_udp_blackhole_journal_path();
    let tools = NetToolPaths::discover();
    let mut runner = LiveCommandRunner;
    apply_udp_blackhole_with(req, &journal_path, &tools, &mut runner, current_unix_ts())
}

pub fn apply_udp_blackhole_with(
    req: &UdpBlackholeApply,
    journal_path: &Path,
    tools: &NetToolPaths,
    runner: &mut dyn CommandRunner,
    now_unix: u64,
) -> ActionOutcome {
    let runtime_name = req.runtime.trim().to_ascii_lowercase();
    let container_name = req.name.trim();
    if !matches!(runtime_name.as_str(), "incus" | "podman" | "runman") {
        return ActionOutcome::err(format!("不支持的运行时: {runtime_name}"));
    }
    if !is_safe_key(container_name) {
        return ActionOutcome::err(format!("容器名称格式无效: {container_name}"));
    }
    if req.pid <= 1 {
        return ActionOutcome::err("容器 PID 无效，无法进入 network namespace");
    }

    let Some(ref nsenter) = tools.nsenter_bin else {
        return ActionOutcome::err("宿主机缺少 nsenter 命令");
    };

    let pid_str = req.pid.to_string();
    let mut rules_applied = false;

    if let Some(ref nft) = tools.nft_bin {
        let nft_content = build_udp_nft_rules(req.allow_dns);
        let cmd = vec![
            nsenter.clone(),
            "-t".to_string(),
            pid_str.clone(),
            "-n".to_string(),
            "--".to_string(),
            nft.clone(),
            "-f".to_string(),
            "-".to_string(),
        ];
        let (ok, _) = runner.run(&cmd, Some(&nft_content));
        rules_applied = ok;
    }

    if !rules_applied && tools.iptables_bin.is_some() {
        let script = build_udp_iptables_apply_script(req.allow_dns);
        let cmd = vec![
            nsenter.clone(),
            "-t".to_string(),
            pid_str,
            "-n".to_string(),
            "sh".to_string(),
            "-c".to_string(),
            script,
        ];
        let (ok, _) = runner.run(&cmd, None);
        rules_applied = ok;
    }

    if !rules_applied {
        return ActionOutcome::err("应用出站 UDP 黑洞规则失败 (nftables 和 iptables 均无法执行)");
    }

    let journal_key = format!("{runtime_name}:{container_name}");
    let _guard = lock_guard(&UDP_JOURNAL_LOCK);
    let mut journal = match read_json_journal(journal_path) {
        Ok(j) => j,
        Err(err) => return ActionOutcome::err(format!("无法读取 UDP 阻断日志: {err}")),
    };

    let expires_at = if req.duration > 0 {
        now_unix.saturating_add(req.duration)
    } else {
        0
    };
    let mut entry = BTreeMap::new();
    entry.insert("status".to_string(), JsonVal::Str("blackholed".to_string()));
    entry.insert("runtime".to_string(), JsonVal::Str(runtime_name));
    entry.insert(
        "name".to_string(),
        JsonVal::Str(container_name.to_string()),
    );
    entry.insert(
        "instance_id".to_string(),
        JsonVal::Str(req.instance_id.clone()),
    );
    entry.insert("pid".to_string(), JsonVal::Num(req.pid as f64));
    entry.insert("allow_dns".to_string(), JsonVal::Bool(req.allow_dns));
    entry.insert("applied_at".to_string(), JsonVal::Num(now_unix as f64));
    entry.insert(
        "auto_triggered".to_string(),
        JsonVal::Bool(req.auto_triggered),
    );
    entry.insert("expires_at".to_string(), JsonVal::Num(expires_at as f64));
    entry.insert("reason".to_string(), JsonVal::Str(req.reason.clone()));

    journal.insert(journal_key, JsonVal::Obj(entry));
    if let Err(err) = write_json_journal(journal_path, &journal, ".udp-blackhole-", true) {
        return ActionOutcome::err(format!("持久化日志失败: {err}"));
    }

    let dns_note = if req.allow_dns {
        " (放行 53 端口 DNS 解析)"
    } else {
        " (完全阻断全部 UDP)"
    };
    ActionOutcome::ok(format!("已对容器 {container_name} 实施出站 UDP 专项阻断{dns_note}"))
}

pub fn release_udp_blackhole(
    runtime: &str,
    name: &str,
    pid: u32,
    instance_id: &str,
    project: &str,
) -> ActionOutcome {
    let journal_path = resolve_udp_blackhole_journal_path();
    let tools = NetToolPaths::discover();
    let mut runner = LiveCommandRunner;
    release_udp_blackhole_with(
        runtime,
        name,
        pid,
        instance_id,
        project,
        &journal_path,
        &tools,
        &mut runner,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn release_udp_blackhole_with(
    runtime: &str,
    name: &str,
    pid: u32,
    _instance_id: &str,
    _project: &str,
    journal_path: &Path,
    tools: &NetToolPaths,
    runner: &mut dyn CommandRunner,
) -> ActionOutcome {
    let runtime_name = runtime.trim().to_ascii_lowercase();
    let container_name = name.trim();
    if !matches!(runtime_name.as_str(), "incus" | "podman" | "runman")
        || !is_safe_key(container_name)
    {
        return ActionOutcome::err("无效的运行时或容器名称");
    }

    let journal_key = format!("{runtime_name}:{container_name}");
    let _guard = lock_guard(&UDP_JOURNAL_LOCK);
    let mut journal = match read_json_journal(journal_path) {
        Ok(j) => j,
        Err(err) => return ActionOutcome::err(format!("无法读取 UDP 阻断日志: {err}")),
    };

    if pid > 1 {
        if let Some(ref nsenter) = tools.nsenter_bin {
            let pid_str = pid.to_string();
            if let Some(ref nft) = tools.nft_bin {
                let cmd = vec![
                    nsenter.clone(),
                    "-t".to_string(),
                    pid_str.clone(),
                    "-n".to_string(),
                    "--".to_string(),
                    nft.clone(),
                    "delete".to_string(),
                    "table".to_string(),
                    "inet".to_string(),
                    UDP_NFT_TABLE.to_string(),
                ];
                let _ = runner.run(&cmd, None);
            }
            if tools.iptables_bin.is_some() {
                let cmd = vec![
                    nsenter.clone(),
                    "-t".to_string(),
                    pid_str,
                    "-n".to_string(),
                    "sh".to_string(),
                    "-c".to_string(),
                    build_udp_iptables_release_script().to_string(),
                ];
                let _ = runner.run(&cmd, None);
            }
        }
    }

    journal.remove(&journal_key);
    if let Err(err) = write_json_journal(journal_path, &journal, ".udp-blackhole-", true) {
        return ActionOutcome::err(format!("持久化日志失败: {err}"));
    }
    ActionOutcome::ok(format!("已解除容器 {container_name} 的出站 UDP 阻断"))
}

pub fn get_udp_blackhole_status(
    runtime: &str,
    name: &str,
    pid: u32,
) -> Result<UdpBlackholeStatus, String> {
    let journal_path = resolve_udp_blackhole_journal_path();
    let tools = NetToolPaths::discover();
    let mut runner = LiveCommandRunner;
    get_udp_blackhole_status_with(
        runtime,
        name,
        pid,
        &journal_path,
        &tools,
        Some(&mut runner),
        current_unix_ts(),
    )
}

pub fn get_udp_blackhole_status_with(
    runtime: &str,
    name: &str,
    pid: u32,
    journal_path: &Path,
    tools: &NetToolPaths,
    runner: Option<&mut dyn CommandRunner>,
    now_unix: u64,
) -> Result<UdpBlackholeStatus, String> {
    let runtime_name = runtime.trim().to_ascii_lowercase();
    let container_name = name.trim();
    let _guard = lock_guard(&UDP_JOURNAL_LOCK);
    let journal = read_json_journal(journal_path)?;
    let entry = journal.get(&format!("{runtime_name}:{container_name}"));

    let mut is_active = entry
        .and_then(|e| e.get_str("status"))
        .map(|s| s == "blackholed")
        .unwrap_or(false);

    if pid > 1 && is_active {
        if let (Some(nsenter), Some(nft), Some(run)) = (&tools.nsenter_bin, &tools.nft_bin, runner)
        {
            let cmd = vec![
                nsenter.clone(),
                "-t".to_string(),
                pid.to_string(),
                "-n".to_string(),
                "--".to_string(),
                nft.clone(),
                "list".to_string(),
                "table".to_string(),
                "inet".to_string(),
                UDP_NFT_TABLE.to_string(),
            ];
            let (ok, out) = run.run(&cmd, None);
            if ok && out.contains(&format!("table inet {UDP_NFT_TABLE}")) {
                is_active = true;
            }
        }
    }

    let applied_at = entry.and_then(|e| e.get_u64("applied_at"));
    let expires_at = entry.and_then(|e| e.get_u64("expires_at"));
    let auto_triggered = entry
        .and_then(|e| e.get_bool("auto_triggered"))
        .unwrap_or(false);
    let allow_dns = entry.and_then(|e| e.get_bool("allow_dns")).unwrap_or(true);
    let reason = entry
        .and_then(|e| e.get_str("reason"))
        .unwrap_or("")
        .to_string();
    let remaining_seconds = match (is_active, expires_at) {
        (true, Some(exp)) if exp > 0 => Some(exp.saturating_sub(now_unix)),
        _ => None,
    };

    Ok(UdpBlackholeStatus {
        active: is_active,
        allow_dns,
        applied_at,
        auto_triggered,
        expires_at,
        remaining_seconds,
        reason,
    })
}

// ---------------------------------------------------------------------------
// 4. Veth Anti-IP Spoofing Guard (`client/anti_spoof_guard.py`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiSpoofStatus {
    pub active: bool,
    pub veth: String,
    pub v4_ips: Vec<String>,
    pub v6_ips: Vec<String>,
    pub applied_at: Option<u64>,
}

impl AntiSpoofStatus {
    pub fn to_json(&self) -> String {
        let v4_json: Vec<String> = self
            .v4_ips
            .iter()
            .map(|ip| format!("\"{}\"", json_escape(ip)))
            .collect();
        let v6_json: Vec<String> = self
            .v6_ips
            .iter()
            .map(|ip| format!("\"{}\"", json_escape(ip)))
            .collect();
        let applied = self
            .applied_at
            .map_or_else(|| "null".to_string(), |v| v.to_string());
        format!(
            "{{\"active\":{},\"veth\":\"{}\",\"v4_ips\":[{}],\"v6_ips\":[{}],\"applied_at\":{applied}}}",
            self.active,
            json_escape(&self.veth),
            v4_json.join(","),
            v6_json.join(","),
        )
    }
}

/// Parse, validate, deduplicate, and sort non-loopback IPv4/IPv6 addresses.
pub fn parse_valid_ips<S: AsRef<str>>(raw_ips: &[S]) -> (Vec<String>, Vec<String>) {
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    for raw in raw_ips {
        let trimmed = raw.as_ref().trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(addr) = trimmed.parse::<IpAddr>() else {
            continue;
        };
        if addr.is_loopback() {
            continue;
        }
        match addr {
            IpAddr::V4(ip4) => {
                v4.insert(ip4.to_string());
            }
            IpAddr::V6(ip6) => {
                v6.insert(ip6.to_string());
            }
        }
    }
    (v4.into_iter().collect(), v6.into_iter().collect())
}

pub fn build_anti_spoof_nft_init() -> String {
    format!(
        "table inet {ANTI_SPOOF_NFT_TABLE} {{\n    chain forward {{\n        type filter hook forward priority -10; policy accept;\n    }}\n}}\n"
    )
}

pub fn build_anti_spoof_nft_rules(
    veth: &str,
    v4_ips: &[String],
    v6_ips: &[String],
) -> Vec<String> {
    let mut rules = Vec::new();
    if !v4_ips.is_empty() {
        let v4_set = v4_ips.join(", ");
        rules.push(format!(
            "add rule inet {ANTI_SPOOF_NFT_TABLE} forward iifname \"{veth}\" ip saddr != {{ {v4_set} }} drop"
        ));
    }
    if !v6_ips.is_empty() {
        let v6_set = v6_ips.join(", ");
        rules.push(format!(
            "add rule inet {ANTI_SPOOF_NFT_TABLE} forward iifname \"{veth}\" ip6 saddr != {{ {v6_set} }} drop"
        ));
    } else {
        rules.push(format!(
            "add rule inet {ANTI_SPOOF_NFT_TABLE} forward iifname \"{veth}\" ip6 drop"
        ));
    }
    rules
}

pub fn apply_anti_spoof<S: AsRef<str>>(
    veth_name: &str,
    allocated_ips: &[S],
    runtime: &str,
    name: &str,
) -> ActionOutcome {
    let journal_path = resolve_anti_spoof_journal_path();
    let tools = NetToolPaths::discover();
    let mut runner = LiveCommandRunner;
    apply_anti_spoof_with(
        veth_name,
        allocated_ips,
        runtime,
        name,
        &journal_path,
        &tools,
        &mut runner,
        current_unix_ts(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn apply_anti_spoof_with<S: AsRef<str>>(
    veth_name: &str,
    allocated_ips: &[S],
    runtime: &str,
    name: &str,
    journal_path: &Path,
    tools: &NetToolPaths,
    runner: &mut dyn CommandRunner,
    now_unix: u64,
) -> ActionOutcome {
    let veth = veth_name.trim();
    if !is_safe_veth(veth) {
        return ActionOutcome::err(format!("无效的网卡接口名: {veth}"));
    }

    let (v4_ips, v6_ips) = parse_valid_ips(allocated_ips);
    if v4_ips.is_empty() && v6_ips.is_empty() {
        return ActionOutcome::err("未提供已分配的有效 IPv4 / IPv6 列表，无法构建白名单");
    }

    let sysctl_bin = tools
        .sysctl_bin
        .clone()
        .unwrap_or_else(|| "sysctl".to_string());
    let _ = runner.run(
        &[
            sysctl_bin,
            "-w".to_string(),
            format!("net.ipv4.conf.{veth}.rp_filter=1"),
        ],
        None,
    );

    if let Some(ref nft) = tools.nft_bin {
        let init_table = build_anti_spoof_nft_init();
        let init_cmd = vec![nft.clone(), "-f".to_string(), "-".to_string()];
        let _ = runner.run(&init_cmd, Some(&init_table));

        for rule in build_anti_spoof_nft_rules(veth, &v4_ips, &v6_ips) {
            let mut cmd = Vec::with_capacity(16);
            cmd.push(nft.clone());
            for tok in rule.split_whitespace() {
                cmd.push(tok.to_string());
            }
            let _ = runner.run(&cmd, None);
        }
    }

    let runtime_norm = runtime.trim().to_ascii_lowercase();
    let container_name = name.trim().to_string();

    let _guard = lock_guard(&SPOOF_JOURNAL_LOCK);
    let mut journal = match read_json_journal(journal_path) {
        Ok(j) => j,
        Err(err) => return ActionOutcome::err(format!("无法读取反欺骗日志: {err}")),
    };

    let mut entry = BTreeMap::new();
    entry.insert("status".to_string(), JsonVal::Str("active".to_string()));
    entry.insert("runtime".to_string(), JsonVal::Str(runtime_norm));
    entry.insert("name".to_string(), JsonVal::Str(container_name));
    entry.insert("veth".to_string(), JsonVal::Str(veth.to_string()));
    entry.insert(
        "v4_ips".to_string(),
        JsonVal::Arr(v4_ips.iter().cloned().map(JsonVal::Str).collect()),
    );
    entry.insert(
        "v6_ips".to_string(),
        JsonVal::Arr(v6_ips.iter().cloned().map(JsonVal::Str).collect()),
    );
    entry.insert("applied_at".to_string(), JsonVal::Num(now_unix as f64));

    journal.insert(veth.to_string(), JsonVal::Obj(entry));
    if let Err(err) = write_json_journal(journal_path, &journal, ".anti-spoof-", true) {
        return ActionOutcome::err(format!("持久化日志失败: {err}"));
    }

    ActionOutcome::ok(format!(
        "已在接口 {veth} 启用源地址防伪造保护 (允许 v4: {}个, v6: {}个)",
        v4_ips.len(),
        v6_ips.len()
    ))
}

pub fn release_anti_spoof(veth_name: &str, runtime: &str, name: &str) -> ActionOutcome {
    let journal_path = resolve_anti_spoof_journal_path();
    let tools = NetToolPaths::discover();
    let mut runner = LiveCommandRunner;
    release_anti_spoof_with(
        veth_name,
        runtime,
        name,
        &journal_path,
        &tools,
        &mut runner,
    )
}

pub fn release_anti_spoof_with(
    veth_name: &str,
    _runtime: &str,
    _name: &str,
    journal_path: &Path,
    tools: &NetToolPaths,
    runner: &mut dyn CommandRunner,
) -> ActionOutcome {
    let veth = veth_name.trim();
    if !is_safe_veth(veth) {
        return ActionOutcome::err(format!("无效的网卡接口名: {veth}"));
    }

    let sysctl_bin = tools
        .sysctl_bin
        .clone()
        .unwrap_or_else(|| "sysctl".to_string());
    let _ = runner.run(
        &[
            sysctl_bin,
            "-w".to_string(),
            format!("net.ipv4.conf.{veth}.rp_filter=2"),
        ],
        None,
    );

    if let Some(ref nft) = tools.nft_bin {
        let cmd = vec![
            nft.clone(),
            "delete".to_string(),
            "table".to_string(),
            "inet".to_string(),
            ANTI_SPOOF_NFT_TABLE.to_string(),
        ];
        let _ = runner.run(&cmd, None);
    }

    let _guard = lock_guard(&SPOOF_JOURNAL_LOCK);
    let mut journal = match read_json_journal(journal_path) {
        Ok(j) => j,
        Err(err) => return ActionOutcome::err(format!("无法读取反欺骗日志: {err}")),
    };
    journal.remove(veth);
    if let Err(err) = write_json_journal(journal_path, &journal, ".anti-spoof-", true) {
        return ActionOutcome::err(format!("持久化日志失败: {err}"));
    }

    ActionOutcome::ok(format!("已在接口 {veth} 解除源地址防伪造过滤"))
}

fn extract_str_list(val: Option<&JsonVal>) -> Vec<String> {
    val.and_then(JsonVal::as_arr)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default()
}

pub fn get_anti_spoof_status(veth_name: &str) -> Result<AntiSpoofStatus, String> {
    get_anti_spoof_status_with(veth_name, &resolve_anti_spoof_journal_path())
}

pub fn get_anti_spoof_status_with(
    veth_name: &str,
    journal_path: &Path,
) -> Result<AntiSpoofStatus, String> {
    let veth = veth_name.trim();
    let _guard = lock_guard(&SPOOF_JOURNAL_LOCK);
    let journal = read_json_journal(journal_path)?;
    let entry = journal.get(veth);
    Ok(AntiSpoofStatus {
        active: entry
            .and_then(|e| e.get_str("status"))
            .map(|s| s == "active")
            .unwrap_or(false),
        veth: veth.to_string(),
        v4_ips: extract_str_list(entry.and_then(|e| e.get("v4_ips"))),
        v6_ips: extract_str_list(entry.and_then(|e| e.get("v6_ips"))),
        applied_at: entry.and_then(|e| e.get_u64("applied_at")),
    })
}

pub fn get_anti_spoof_status_for_container(
    runtime: &str,
    name: &str,
    veth_name: &str,
) -> Result<AntiSpoofStatus, String> {
    get_anti_spoof_status_for_container_with(
        runtime,
        name,
        veth_name,
        &resolve_anti_spoof_journal_path(),
    )
}

pub fn get_anti_spoof_status_for_container_with(
    runtime: &str,
    name: &str,
    veth_name: &str,
    journal_path: &Path,
) -> Result<AntiSpoofStatus, String> {
    let runtime_name = runtime.trim().to_ascii_lowercase();
    let container_name = name.trim();
    let veth = veth_name.trim();
    let _guard = lock_guard(&SPOOF_JOURNAL_LOCK);
    let journal = read_json_journal(journal_path)?;

    if !veth.is_empty() {
        if let Some(entry) = journal.get(veth) {
            return Ok(AntiSpoofStatus {
                active: entry.get_str("status") == Some("active"),
                veth: veth.to_string(),
                v4_ips: extract_str_list(entry.get("v4_ips")),
                v6_ips: extract_str_list(entry.get("v6_ips")),
                applied_at: entry.get_u64("applied_at"),
            });
        }
    }

    for (entry_veth, entry) in &journal {
        if entry.get_str("runtime") == Some(runtime_name.as_str())
            && entry.get_str("name") == Some(container_name)
        {
            return Ok(AntiSpoofStatus {
                active: entry.get_str("status") == Some("active"),
                veth: entry_veth.clone(),
                v4_ips: extract_str_list(entry.get("v4_ips")),
                v6_ips: extract_str_list(entry.get("v6_ips")),
                applied_at: entry.get_u64("applied_at"),
            });
        }
    }

    Ok(AntiSpoofStatus {
        active: false,
        veth: String::new(),
        v4_ips: Vec::new(),
        v6_ips: Vec::new(),
        applied_at: None,
    })
}

// ---------------------------------------------------------------------------
// 5. Quarantine Journal, Drivers & Release / Replacement Helpers
// ---------------------------------------------------------------------------

/// Validate target tuple and format canonical compact JSON key matching `network_quarantine.target`.
pub fn quarantine_target(
    runtime: &str,
    project: &str,
    name: &str,
    instance_id: &str,
) -> Result<String, String> {
    if !matches!(runtime, "incus" | "podman" | "runman") {
        return Err("unsupported runtime; no network change performed".to_string());
    }
    if !is_safe_quarantine_name(name) {
        return Err("invalid or protected instance".to_string());
    }
    if !project.is_empty() && !is_safe_project(project) {
        return Err("invalid project".to_string());
    }
    if runtime == "runman" {
        if project != "default" || !is_uuid_lower(name) || !is_uuid_v4_lower(instance_id) {
            return Err("Runman requires a canonical VM UUID and current UUID generation".to_string());
        }
    }
    if !is_safe_instance_id(instance_id) {
        return Err("stable instance identity required".to_string());
    }
    Ok(format!(
        "[\"{}\",\"{}\",\"{}\",\"{}\"]",
        json_escape(runtime),
        json_escape(project),
        json_escape(name),
        json_escape(instance_id),
    ))
}

pub fn podman_inspect_args(name: &str) -> Vec<String> {
    vec![
        "inspect".to_string(),
        "--format".to_string(),
        PODMAN_INSPECT_FORMAT.to_string(),
        name.to_string(),
    ]
}

/// Whitelist only typed feature metadata; never persist argv, code, or raw records.
pub fn safe_evidence(evidence: &[JsonVal]) -> Result<Vec<JsonVal>, String> {
    const STR_KEYS: &[&str] = &[
        "kind",
        "confidence",
        "basis",
        "tool",
        "start_ticks",
        "source_sha256",
    ];
    const NUM_KEYS: &[&str] = &[
        "pid",
        "target_count",
        "public_target_count",
        "private_target_count",
        "owned_http_connections",
        "pending_attempts",
        "vertical_ports",
        "horizontal_targets",
        "failed_ratio",
        "pending_ratio",
    ];
    const FEATURE_KEYS: &[&str] = &[
        "http_calls",
        "enumeration",
        "dictionary_inputs",
        "identity_generator",
        "concurrency",
        "corroborating_samples",
    ];

    let mut result = Vec::new();
    for item in evidence.iter().take(20) {
        let Some(obj) = item.as_obj() else {
            continue;
        };
        let mut clean = BTreeMap::new();
        for &k in STR_KEYS {
            if let Some(s) = obj.get(k).and_then(JsonVal::as_str) {
                if is_safe_evidence_token(s) {
                    clean.insert(k.to_string(), JsonVal::Str(s.to_string()));
                }
            }
        }
        for &k in NUM_KEYS {
            if let Some(n) = obj.get(k).and_then(JsonVal::as_f64) {
                if (0.0..=1_000_000_000.0).contains(&n) {
                    clean.insert(k.to_string(), JsonVal::Num(n));
                }
            }
        }
        if let Some(features_obj) = obj.get("features").and_then(JsonVal::as_obj) {
            let mut clean_features = BTreeMap::new();
            for &fk in FEATURE_KEYS {
                if let Some(fv) = features_obj.get(fk) {
                    match fv {
                        JsonVal::Bool(_) => {
                            clean_features.insert(fk.to_string(), fv.clone());
                        }
                        JsonVal::Num(_) if fv.as_i64().is_some() => {
                            clean_features.insert(fk.to_string(), fv.clone());
                        }
                        _ => {}
                    }
                }
            }
            clean.insert("features".to_string(), JsonVal::Obj(clean_features));
        }
        if clean
            .get("kind")
            .and_then(JsonVal::as_str)
            .is_some_and(|s| !s.is_empty())
        {
            result.push(JsonVal::Obj(clean));
        }
    }
    if result.is_empty() {
        return Err("no safe abuse evidence".to_string());
    }
    Ok(result)
}

#[derive(Debug, Clone)]
pub struct QuarantineJournal {
    path: PathBuf,
}

impl QuarantineJournal {
    pub fn new(path: Option<&Path>) -> Result<Self, String> {
        let resolved = match path {
            Some(p) => {
                if !p.is_absolute() {
                    return Err("journal path must be absolute".to_string());
                }
                p.to_path_buf()
            }
            None => resolve_quarantine_journal_path()?,
        };
        Ok(Self { path: resolved })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read(&self) -> Result<BTreeMap<String, JsonVal>, String> {
        read_json_journal(&self.path)
    }

    pub fn write(&self, data: &BTreeMap<String, JsonVal>) -> Result<(), String> {
        write_json_journal(&self.path, data, ".abuse-quarantine-", false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverReleaseOutcome {
    pub container_deleted: bool,
}

pub trait IsolationDriver {
    fn snapshot(&mut self) -> Result<JsonVal, String>;
    fn refresh_backup(&mut self, _backup: &mut JsonVal) -> Result<(), String> {
        Ok(())
    }
    fn isolate(&mut self, backup: &JsonVal) -> Result<(), String>;
    fn verify(&mut self, backup: &JsonVal) -> Result<(), String>;
    fn release(&mut self, backup: &JsonVal) -> Result<DriverReleaseOutcome, String>;
    fn prove_replaced(&mut self) -> Result<String, String>;
}

fn url_encode_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

pub trait IncusTransport {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&JsonVal>,
        etag: Option<&str>,
    ) -> Result<(JsonVal, Option<String>), String>;
}

pub struct UnixIncusApi {
    pub project: String,
    pub socket_path: String,
}

impl UnixIncusApi {
    pub fn new(project: &str, socket_path: impl Into<String>) -> Self {
        Self {
            project: if project.is_empty() {
                "default".to_string()
            } else {
                project.to_string()
            },
            socket_path: socket_path.into(),
        }
    }
}

#[cfg(unix)]
impl UnixIncusApi {
    fn raw_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&JsonVal>,
        etag: Option<&str>,
    ) -> Result<(u16, BTreeMap<String, String>, Vec<u8>), String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|_| "Incus local API unavailable".to_string())?;
        let _ = stream.set_read_timeout(Some(INCUS_IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(INCUS_IO_TIMEOUT));

        let sep = if path.contains('?') { '&' } else { '?' };
        let full_path = format!("{path}{sep}project={}", url_encode_component(&self.project));
        let body_bytes = body.map(|val| json_val_to_string(val, false).into_bytes());

        let mut req = Vec::with_capacity(256 + body_bytes.as_ref().map_or(0, Vec::len));
        req.extend_from_slice(method.as_bytes());
        req.push(b' ');
        req.extend_from_slice(full_path.as_bytes());
        req.extend_from_slice(
            b" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\n",
        );
        if let Some(tag) = etag {
            if !tag.is_empty() && !tag.contains('\r') && !tag.contains('\n') {
                req.extend_from_slice(format!("If-Match: {tag}\r\n").as_bytes());
            }
        }
        if let Some(ref b) = body_bytes {
            req.extend_from_slice(format!("Content-Length: {}\r\n", b.len()).as_bytes());
        }
        req.extend_from_slice(b"\r\n");
        if let Some(ref b) = body_bytes {
            req.extend_from_slice(b);
        }

        stream
            .write_all(&req)
            .map_err(|_| "Incus local API unavailable".to_string())?;
        let _ = stream.flush();

        let mut raw = Vec::new();
        stream
            .take((MAX_INCUS_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut raw)
            .map_err(|_| "Incus local API unavailable".to_string())?;
        if raw.len() > MAX_INCUS_RESPONSE_BYTES {
            return Err("Incus API request failed: status 413".to_string());
        }

        parse_http_response_with_headers(&raw)
            .map_err(|_| "Incus local API unavailable".to_string())
    }
}

#[cfg(unix)]
impl IncusTransport for UnixIncusApi {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&JsonVal>,
        etag: Option<&str>,
    ) -> Result<(JsonVal, Option<String>), String> {
        let (status, headers, raw_body) = self.raw_request(method, path, body, etag)?;
        if status >= 400 || raw_body.len() > MAX_INCUS_RESPONSE_BYTES {
            return Err(format!("Incus API request failed: status {status}"));
        }
        let text = std::str::from_utf8(&raw_body)
            .map_err(|_| "Incus local API unavailable".to_string())?;
        let parsed = JsonVal::parse(text)
            .map_err(|_| "Incus local API unavailable".to_string())?;
        let response_etag = headers.get("etag").cloned();

        if parsed.get_str("type") == Some("async") {
            let op = parsed
                .get_str("operation")
                .unwrap_or("")
                .split('?')
                .next()
                .unwrap_or("");
            if !is_valid_incus_operation(op) {
                return Err("invalid Incus operation identity".to_string());
            }
            let wait_path = format!("{op}/wait?timeout=30");
            let (wait_meta, _) = self.request("GET", &wait_path, None, None)?;
            if wait_meta.get_i64("status_code") != Some(200) {
                return Err("Incus network update was not confirmed".to_string());
            }
        }

        let metadata = parsed
            .get("metadata")
            .cloned()
            .unwrap_or_else(|| JsonVal::Obj(BTreeMap::new()));
        Ok((metadata, response_etag))
    }
}

#[cfg(not(unix))]
impl IncusTransport for UnixIncusApi {
    fn request(
        &mut self,
        _method: &str,
        _path: &str,
        _body: Option<&JsonVal>,
        _etag: Option<&str>,
    ) -> Result<(JsonVal, Option<String>), String> {
        Err("Incus Unix socket client is only supported on Unix platforms".to_string())
    }
}

#[cfg(any(unix, test))]
fn parse_http_response_with_headers(
    raw: &[u8],
) -> Result<(u16, BTreeMap<String, String>, Vec<u8>), String> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "missing HTTP header terminator".to_string())?;
    let header_str = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "non-UTF8 HTTP headers".to_string())?;
    let body_raw = &raw[header_end + 4..];

    let mut lines = header_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "empty HTTP status line".to_string())?;
    let mut parts = status_line.split_whitespace();
    let _ver = parts
        .next()
        .filter(|v| v.starts_with("HTTP/"))
        .ok_or_else(|| "invalid HTTP status line".to_string())?;
    let status_code = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| "invalid HTTP status code".to_string())?;

    let mut headers = BTreeMap::new();
    let mut is_chunked = false;
    let mut content_length: Option<usize> = None;

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "transfer-encoding" && val.to_ascii_lowercase().contains("chunked") {
                is_chunked = true;
            } else if key == "content-length" {
                content_length = val.parse::<usize>().ok();
            }
            headers.insert(key, val);
        }
    }

    let body = if is_chunked {
        decode_http_chunked_body(body_raw)?
    } else if let Some(len) = content_length {
        if body_raw.len() < len {
            return Err("truncated HTTP body".to_string());
        }
        body_raw[..len].to_vec()
    } else {
        body_raw.to_vec()
    };
    Ok((status_code, headers, body))
}

#[cfg(any(unix, test))]
fn decode_http_chunked_body(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let crlf = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "malformed chunked size".to_string())?;
        let size_line =
            std::str::from_utf8(&data[..crlf]).map_err(|_| "invalid chunk size".to_string())?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let len = usize::from_str_radix(size_hex, 16)
            .map_err(|_| "invalid hex chunk size".to_string())?;
        data = &data[crlf + 2..];
        if len == 0 {
            break;
        }
        if data.len() < len + 2 {
            return Err("truncated chunk body".to_string());
        }
        out.extend_from_slice(&data[..len]);
        data = &data[len + 2..];
    }
    Ok(out)
}

fn is_incus_network_device(dev: &JsonVal) -> bool {
    matches!(
        dev.get_str("type"),
        Some("nic" | "proxy" | "infiniband")
    )
}

fn is_incus_passthrough_device(dev: &JsonVal) -> bool {
    matches!(
        dev.get_str("type"),
        Some("pci" | "usb" | "unix-hotplug")
    )
}

fn has_raw_lxc_network(raw_lxc: &str) -> bool {
    raw_lxc.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("lxc.net.") || trimmed.starts_with("lxc.network.")
    })
}

pub struct IncusIsolation<T: IncusTransport> {
    pub api: T,
    pub name: String,
    pub instance_id: String,
    path: String,
}

impl<T: IncusTransport> IncusIsolation<T> {
    pub fn new(api: T, name: impl Into<String>, instance_id: impl Into<String>) -> Self {
        let name = name.into();
        let path = format!("/1.0/instances/{}", url_encode_component(&name));
        Self {
            api,
            name,
            instance_id: instance_id.into(),
            path,
        }
    }

    pub fn inspect(&mut self) -> Result<(JsonVal, String), String> {
        let (item, etag_opt) = self.api.request("GET", &self.path, None, None)?;
        let identity = item
            .get("config")
            .and_then(|c| c.get_str("volatile.uuid"))
            .unwrap_or("");
        if identity != self.instance_id {
            return Err("Incus instance identity changed; refused".to_string());
        }
        let Some(etag) = etag_opt.filter(|s| !s.is_empty()) else {
            return Err("Incus conditional-update support required".to_string());
        };
        let effective = item
            .get("expanded_config")
            .or_else(|| item.get("config"));
        if let Some(raw_lxc) = effective.and_then(|c| c.get_str("raw.lxc")) {
            if has_raw_lxc_network(raw_lxc) {
                return Err("unmanaged Incus network requires manual isolation".to_string());
            }
        }
        if let Some(expanded) = item.get("expanded_devices").and_then(JsonVal::as_obj) {
            if expanded.values().any(is_incus_passthrough_device) {
                return Err("passthrough devices require manual isolation".to_string());
            }
        }
        Ok((item, etag))
    }

    fn volatile_identity(&self, item: &JsonVal, devices: &BTreeMap<String, JsonVal>) -> BTreeMap<String, JsonVal> {
        let mut out = BTreeMap::new();
        let Some(cfg) = item.get("config").and_then(JsonVal::as_obj) else {
            return out;
        };
        for key in devices.keys() {
            for field in ["hwaddr", "name"] {
                let full_key = format!("volatile.{key}.{field}");
                if let Some(val) = cfg.get(&full_key) {
                    out.insert(full_key, val.clone());
                }
            }
        }
        out
    }

    fn guest_names(
        &mut self,
        item: &JsonVal,
        devices: &BTreeMap<String, JsonVal>,
    ) -> Result<BTreeMap<String, JsonVal>, String> {
        let mut result = BTreeMap::new();
        let mut state: Option<JsonVal> = None;

        for (key, device) in devices {
            if !matches!(device.get_str("type"), Some("nic" | "infiniband")) {
                continue;
            }
            let vol_name_key = format!("volatile.{key}.name");
            let mut iface_name = device
                .get_str("name")
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    item.get("config")
                        .and_then(|c| c.get_str(&vol_name_key))
                        .filter(|s| !s.is_empty())
                })
                .map(ToString::to_string);

            if iface_name.is_none() {
                if state.is_none() {
                    let state_path = format!("{}/state", self.path);
                    let (st, _) = self.api.request("GET", &state_path, None, None)?;
                    state = Some(st);
                }
                let vol_hw_key = format!("volatile.{key}.hwaddr");
                let mac = device
                    .get_str("hwaddr")
                    .filter(|s| !s.is_empty())
                    .or_else(|| {
                        item.get("config")
                            .and_then(|c| c.get_str(&vol_hw_key))
                            .filter(|s| !s.is_empty())
                    });
                if let (Some(mac_str), Some(net_map)) = (
                    mac,
                    state
                        .as_ref()
                        .and_then(|s| s.get("network"))
                        .and_then(JsonVal::as_obj),
                ) {
                    let matches: Vec<&String> = net_map
                        .iter()
                        .filter(|(_, iface)| {
                            iface
                                .get_str("hwaddr")
                                .is_some_and(|h| h.eq_ignore_ascii_case(mac_str))
                        })
                        .map(|(n, _)| n)
                        .collect();
                    if matches.len() == 1 {
                        iface_name = Some(matches[0].clone());
                    }
                }
            }

            let Some(resolved) = iface_name else {
                return Err(
                    "original guest interface identity unavailable; no new device mutation"
                        .to_string(),
                );
            };
            result.insert(key.clone(), JsonVal::Str(resolved));
        }

        Ok(result)
    }

    fn set_devices(
        &mut self,
        item: &JsonVal,
        etag: &str,
        devices: BTreeMap<String, JsonVal>,
        restore_identity: Option<&BTreeMap<String, JsonVal>>,
    ) -> Result<(), String> {
        let mut data = BTreeMap::new();
        if let Some(obj) = item.as_obj() {
            for key in [
                "architecture",
                "config",
                "profiles",
                "ephemeral",
                "description",
            ] {
                if let Some(val) = obj.get(key) {
                    data.insert(key.to_string(), val.clone());
                }
            }
        }
        data.insert("devices".to_string(), JsonVal::Obj(devices));
        if let Some(identity) = restore_identity {
            let mut cfg = data
                .get("config")
                .and_then(JsonVal::as_obj)
                .cloned()
                .unwrap_or_default();
            for (k, v) in identity {
                cfg.insert(k.clone(), v.clone());
            }
            data.insert("config".to_string(), JsonVal::Obj(cfg));
        }
        self.api
            .request("PUT", &self.path, Some(&JsonVal::Obj(data)), Some(etag))?;
        Ok(())
    }
}

impl<T: IncusTransport> IsolationDriver for IncusIsolation<T> {
    fn snapshot(&mut self) -> Result<JsonVal, String> {
        let (item, _) = self.inspect()?;
        let expanded_map = item
            .get("expanded_devices")
            .and_then(JsonVal::as_obj)
            .cloned()
            .unwrap_or_default();
        let devices: BTreeMap<String, JsonVal> = expanded_map
            .into_iter()
            .filter(|(_, v)| is_incus_network_device(v))
            .collect();
        if devices.is_empty() {
            return Err("no managed network devices; cannot prove isolation".to_string());
        }

        let item_devices = item
            .get("devices")
            .and_then(JsonVal::as_obj)
            .cloned()
            .unwrap_or_default();
        let mut original = BTreeMap::new();
        for k in devices.keys() {
            original.insert(
                k.clone(),
                item_devices.get(k).cloned().unwrap_or(JsonVal::Null),
            );
        }
        let guest_names = self.guest_names(&item, &devices)?;
        let volatile_id = self.volatile_identity(&item, &devices);

        let mut backup = BTreeMap::new();
        backup.insert("original".to_string(), JsonVal::Obj(original));
        backup.insert("expanded".to_string(), JsonVal::Obj(devices));
        backup.insert("guest_names".to_string(), JsonVal::Obj(guest_names));
        backup.insert("volatile_identity".to_string(), JsonVal::Obj(volatile_id));
        Ok(JsonVal::Obj(backup))
    }

    fn refresh_backup(&mut self, backup: &mut JsonVal) -> Result<(), String> {
        let (item, _) = self.inspect()?;
        let existing_orig_keys: BTreeSet<String> = backup
            .get("original")
            .and_then(JsonVal::as_obj)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        let mut added = BTreeMap::new();
        if let Some(expanded) = item.get("expanded_devices").and_then(JsonVal::as_obj) {
            for (k, v) in expanded {
                if is_incus_network_device(v) && !existing_orig_keys.contains(k) {
                    added.insert(k.clone(), v.clone());
                }
            }
        }
        if added.is_empty() {
            return Ok(());
        }
        let names = self.guest_names(&item, &added)?;
        let vol = self.volatile_identity(&item, &added);
        let item_devices = item
            .get("devices")
            .and_then(JsonVal::as_obj)
            .cloned()
            .unwrap_or_default();

        let JsonVal::Obj(ref mut root) = backup else {
            return Err("invalid Incus backup".to_string());
        };
        if let Some(JsonVal::Obj(orig_map)) = root.get_mut("original") {
            for k in added.keys() {
                orig_map.insert(
                    k.clone(),
                    item_devices.get(k).cloned().unwrap_or(JsonVal::Null),
                );
            }
        }
        if let Some(JsonVal::Obj(exp_map)) = root.get_mut("expanded") {
            for (k, v) in added {
                exp_map.insert(k, v);
            }
        }
        match root.get_mut("guest_names") {
            Some(JsonVal::Obj(gn)) => gn.extend(names),
            _ => {
                root.insert("guest_names".to_string(), JsonVal::Obj(names));
            }
        }
        match root.get_mut("volatile_identity") {
            Some(JsonVal::Obj(vi)) => vi.extend(vol),
            _ => {
                root.insert("volatile_identity".to_string(), JsonVal::Obj(vol));
            }
        }
        Ok(())
    }

    fn isolate(&mut self, backup: &JsonVal) -> Result<(), String> {
        let (item, etag) = self.inspect()?;
        let original_map = backup
            .get("original")
            .and_then(JsonVal::as_obj)
            .ok_or_else(|| "invalid Incus backup".to_string())?;
        let item_devices = item
            .get("devices")
            .and_then(JsonVal::as_obj)
            .cloned()
            .unwrap_or_default();
        let mut current = item_devices.clone();

        let mut network_keys: BTreeSet<String> = original_map.keys().cloned().collect();
        if let Some(expanded) = item.get("expanded_devices").and_then(JsonVal::as_obj) {
            for (k, v) in expanded {
                if is_incus_network_device(v) {
                    network_keys.insert(k.clone());
                }
            }
        }

        let none_dev = JsonVal::Obj(BTreeMap::from([(
            "type".to_string(),
            JsonVal::Str("none".to_string()),
        )]));

        for key in network_keys {
            if !original_map.contains_key(&key) {
                return Err("network topology changed; manual review required".to_string());
            }
            if let Some(local_type) = current.get(&key).and_then(|d| d.get_str("type")) {
                if !matches!(local_type, "nic" | "proxy" | "infiniband" | "none") {
                    return Err("device is no longer a network device; manual review required".to_string());
                }
            }
            current.insert(key, none_dev.clone());
        }

        if current != item_devices {
            self.set_devices(&item, &etag, current, None)?;
        }
        self.verify(backup)
    }

    fn verify(&mut self, backup: &JsonVal) -> Result<(), String> {
        let (item, _) = self.inspect()?;
        if let Some(expanded) = item.get("expanded_devices").and_then(JsonVal::as_obj) {
            if expanded.values().any(is_incus_network_device) {
                return Err("Incus network devices remain connected".to_string());
            }
        }
        let original_map = backup
            .get("original")
            .and_then(JsonVal::as_obj)
            .ok_or_else(|| "invalid Incus backup".to_string())?;
        let item_devices = item
            .get("devices")
            .and_then(JsonVal::as_obj)
            .cloned()
            .unwrap_or_default();
        let none_dev = JsonVal::Obj(BTreeMap::from([(
            "type".to_string(),
            JsonVal::Str("none".to_string()),
        )]));
        for key in original_map.keys() {
            if item_devices.get(key) != Some(&none_dev) {
                return Err("Incus quarantine masks not confirmed".to_string());
            }
        }

        let state_path = format!("{}/state", self.path);
        let (state, _) = self.api.request("GET", &state_path, None, None)?;
        let interfaces = state.get("network").and_then(JsonVal::as_obj);
        if let Some(exp_map) = backup.get("expanded").and_then(JsonVal::as_obj) {
            let guest_names = backup.get("guest_names").and_then(JsonVal::as_obj);
            for (key, device) in exp_map {
                if matches!(device.get_str("type"), Some("nic" | "infiniband")) {
                    let iface_name = guest_names
                        .and_then(|g| g.get(key))
                        .and_then(JsonVal::as_str)
                        .filter(|s| !s.is_empty())
                        .or_else(|| device.get_str("name").filter(|s| !s.is_empty()))
                        .ok_or_else(|| "original guest interface identity unavailable".to_string())?;
                    let is_up = interfaces
                        .and_then(|nets| nets.get(iface_name))
                        .and_then(|iface| iface.get_str("state"))
                        .is_some_and(|st| st.eq_ignore_ascii_case("up"));
                    if is_up {
                        return Err("original guest interface is still up".to_string());
                    }
                }
            }
        }
        Ok(())
    }

    fn release(&mut self, backup: &JsonVal) -> Result<DriverReleaseOutcome, String> {
        let (mut item, mut etag) = match self.inspect() {
            Ok(pair) => pair,
            Err(err) if err.contains("status 404") => {
                let (instances_val, _) =
                    self.api.request("GET", "/1.0/instances?recursion=2", None, None)?;
                if let Some(instances) = instances_val.as_arr() {
                    let any_present = instances.iter().any(|inst| {
                        let uuid_match = inst
                            .get("config")
                            .and_then(|c| c.get_str("volatile.uuid"))
                            == Some(self.instance_id.as_str());
                        let name_match = inst.get_str("name") == Some(self.name.as_str());
                        uuid_match || name_match
                    });
                    if !any_present {
                        return Ok(DriverReleaseOutcome {
                            container_deleted: true,
                        });
                    }
                }
                return Err(err);
            }
            Err(err) => return Err(err),
        };

        let original_map = backup
            .get("original")
            .and_then(JsonVal::as_obj)
            .ok_or_else(|| "invalid Incus backup".to_string())?;
        let expanded_map = backup
            .get("expanded")
            .and_then(JsonVal::as_obj)
            .ok_or_else(|| "invalid Incus backup".to_string())?;

        let none_dev = JsonVal::Obj(BTreeMap::from([(
            "type".to_string(),
            JsonVal::Str("none".to_string()),
        )]));

        let mut devices = item
            .get("devices")
            .and_then(JsonVal::as_obj)
            .cloned()
            .unwrap_or_default();

        for (key, original) in original_map {
            if devices.get(key) != Some(&none_dev) {
                return Err(
                    "quarantine mask changed; refused to overwrite operator configuration"
                        .to_string(),
                );
            }
            if *original == JsonVal::Null {
                devices.remove(key);
            } else {
                devices.insert(key.clone(), original.clone());
            }
        }

        let identity = backup
            .get("volatile_identity")
            .and_then(JsonVal::as_obj)
            .cloned()
            .unwrap_or_default();

        if !identity.is_empty() {
            let mut temporary = item
                .get("devices")
                .and_then(JsonVal::as_obj)
                .cloned()
                .unwrap_or_default();
            for (key, expanded) in expanded_map {
                if !matches!(expanded.get_str("type"), Some("nic" | "infiniband")) {
                    continue;
                }
                let mut dev_map = expanded.as_obj().cloned().unwrap_or_default();
                for field in ["hwaddr", "name"] {
                    let vol_key = format!("volatile.{key}.{field}");
                    if let Some(val) = identity.get(&vol_key).and_then(JsonVal::as_str) {
                        if !val.is_empty() {
                            dev_map.insert(field.to_string(), JsonVal::Str(val.to_string()));
                        }
                    }
                }
                temporary.insert(key.clone(), JsonVal::Obj(dev_map));
            }
            self.set_devices(&item, &etag, temporary, None)?;
            let pair = self.inspect()?;
            item = pair.0;
            etag = pair.1;
            let cur_devices = item
                .get("devices")
                .and_then(JsonVal::as_obj)
                .cloned()
                .unwrap_or_default();
            self.set_devices(&item, &etag, cur_devices, Some(&identity))?;
            let pair2 = self.inspect()?;
            item = pair2.0;
            etag = pair2.1;
        }

        self.set_devices(&item, &etag, devices, None)?;
        let (fresh, _) = self.inspect()?;
        let fresh_devices = fresh
            .get("devices")
            .and_then(JsonVal::as_obj)
            .cloned()
            .unwrap_or_default();

        for (key, original) in original_map {
            let matches = if *original == JsonVal::Null {
                matches!(fresh_devices.get(key), None | Some(JsonVal::Null))
            } else {
                fresh_devices.get(key) == Some(original)
            };
            if !matches {
                return Err("Incus restore readback mismatch".to_string());
            }
        }

        let fresh_cfg = fresh.get("config").and_then(JsonVal::as_obj);
        for (key, val) in &identity {
            if fresh_cfg.and_then(|c| c.get(key)) != Some(val) {
                return Err("Incus restored NIC identity readback mismatch".to_string());
            }
        }

        let fresh_expanded = fresh.get("expanded_devices").and_then(JsonVal::as_obj);
        for (key, expected) in expanded_map {
            if fresh_expanded.and_then(|e| e.get(key)) != Some(expected) {
                return Err(
                    "Incus inherited network configuration changed; manual review required"
                        .to_string(),
                );
            }
        }

        if !identity.is_empty() {
            let state_path = format!("{}/state", self.path);
            let (state, _) = self.api.request("GET", &state_path, None, None)?;
            let net_map = state.get("network").and_then(JsonVal::as_obj);
            if let Some(guest_names) = backup.get("guest_names").and_then(JsonVal::as_obj) {
                for (key, name_val) in guest_names {
                    let Some(iface_name) = name_val.as_str() else {
                        continue;
                    };
                    if let Some(expected_mac) = identity
                        .get(&format!("volatile.{key}.hwaddr"))
                        .and_then(JsonVal::as_str)
                    {
                        if !expected_mac.is_empty() {
                            let actual_mac = net_map
                                .and_then(|n| n.get(iface_name))
                                .and_then(|i| i.get_str("hwaddr"))
                                .unwrap_or("");
                            if !actual_mac.eq_ignore_ascii_case(expected_mac) {
                                return Err(
                                    "Incus runtime MAC restoration was not confirmed".to_string(),
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(DriverReleaseOutcome {
            container_deleted: false,
        })
    }

    fn prove_replaced(&mut self) -> Result<String, String> {
        let current = match self.api.request("GET", &self.path, None, None) {
            Ok((val, _)) => Some(val),
            Err(err) if err.contains("status 404") => None,
            Err(err) => return Err(err),
        };

        let (instances_val, _) =
            self.api.request("GET", "/1.0/instances?recursion=2", None, None)?;
        let Some(instances) = instances_val.as_arr() else {
            return Err("Incus instance inventory could not be verified".to_string());
        };
        for inst in instances {
            if inst.as_obj().is_none() {
                return Err("Incus instance inventory was invalid".to_string());
            }
            let identity = inst
                .get("config")
                .and_then(|c| c.get_str("volatile.uuid"))
                .unwrap_or("");
            if identity == self.instance_id {
                return Err("old Incus instance still exists".to_string());
            }
        }

        let Some(cur_item) = current else {
            return Ok("none".to_string());
        };
        let current_id = cur_item
            .get("config")
            .and_then(|c| c.get_str("volatile.uuid"))
            .unwrap_or("");
        if !is_safe_instance_id(current_id) || current_id == self.instance_id {
            return Err("Incus replacement identity could not be verified".to_string());
        }

        let found_current = instances.iter().any(|inst| {
            inst.get_str("name") == Some(self.name.as_str())
                && inst
                    .get("config")
                    .and_then(|c| c.get_str("volatile.uuid"))
                    == Some(current_id)
        });
        if !found_current {
            return Err("replacement was not present in the Incus project inventory".to_string());
        }
        Ok(current_id.to_string())
    }
}

fn is_podman_not_found(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("no such object")
        || lower.contains("no such container")
        || lower.contains("no container with name or id")
        || lower.contains("not found")
}

pub struct PodmanIsolation<'a> {
    pub runner: &'a mut dyn CommandRunner,
    pub binary: String,
    pub name: String,
    pub instance_id: String,
}

impl<'a> PodmanIsolation<'a> {
    pub fn new(
        runner: &'a mut dyn CommandRunner,
        binary: impl Into<String>,
        name: impl Into<String>,
        instance_id: impl Into<String>,
    ) -> Self {
        Self {
            runner,
            binary: binary.into(),
            name: name.into(),
            instance_id: instance_id.into(),
        }
    }

    fn command(&mut self, args: &[String]) -> Result<String, String> {
        let mut full = Vec::with_capacity(args.len() + 1);
        full.push(self.binary.clone());
        full.extend_from_slice(args);
        let (ok, output) = self.runner.run(&full, None);
        if !ok {
            return Err("Podman network operation failed".to_string());
        }
        Ok(output)
    }

    pub fn inspect(&mut self) -> Result<JsonVal, String> {
        let args = podman_inspect_args(&self.name);
        let out = self.command(&args)?;
        let parsed = JsonVal::parse(&out)
            .map_err(|_| "invalid Podman inspection".to_string())?;
        let item = parsed
            .as_arr()
            .and_then(|arr| arr.first())
            .cloned()
            .ok_or_else(|| "invalid Podman inspection".to_string())?;
        let identity = item
            .get_str("Id")
            .or_else(|| item.get_str("ID"))
            .unwrap_or("");
        if self.instance_id.len() < 12 || !identity.starts_with(&self.instance_id) {
            return Err("Podman container identity changed; refused".to_string());
        }

        let host_cfg = item.get("HostConfig");
        let mode = host_cfg
            .and_then(|h| h.get_str("NetworkMode"))
            .unwrap_or("");
        let pid_mode = host_cfg.and_then(|h| h.get_str("PidMode")).unwrap_or("");
        let has_pod = item.get_str("Pod").is_some_and(|p| !p.is_empty());

        if has_pod
            || mode == "host"
            || mode.starts_with("container:")
            || mode.starts_with("ns:")
            || mode.starts_with("pasta")
            || mode.starts_with("slirp4netns")
            || pid_mode == "host"
            || pid_mode.starts_with("container:")
        {
            return Err("shared/host/rootless network requires manual isolation".to_string());
        }
        let privileged = host_cfg
            .and_then(|h| h.get_bool("Privileged"))
            .unwrap_or(false);
        let has_devices = host_cfg
            .and_then(|h| h.get("Devices"))
            .and_then(JsonVal::as_arr)
            .is_some_and(|d| !d.is_empty());
        if privileged || has_devices {
            return Err("privileged/device-passthrough container requires manual isolation".to_string());
        }
        Ok(item)
    }
}

impl<'a> IsolationDriver for PodmanIsolation<'a> {
    fn snapshot(&mut self) -> Result<JsonVal, String> {
        let item = self.inspect()?;
        let networks = item
            .get("NetworkSettings")
            .and_then(|ns| ns.get("Networks"))
            .and_then(JsonVal::as_obj)
            .filter(|m| !m.is_empty())
            .ok_or_else(|| "no managed Podman attachments; cannot prove isolation".to_string())?;
        let id = item
            .get_str("Id")
            .or_else(|| item.get_str("ID"))
            .unwrap_or("")
            .to_string();
        let mut map = BTreeMap::new();
        map.insert("networks".to_string(), JsonVal::Obj(networks.clone()));
        map.insert("id".to_string(), JsonVal::Str(id));
        Ok(JsonVal::Obj(map))
    }

    fn isolate(&mut self, backup: &JsonVal) -> Result<(), String> {
        let item = self.inspect()?;
        let backup_id = backup
            .get_str("id")
            .ok_or_else(|| "invalid Podman backup".to_string())?
            .to_string();
        if let Some(networks) = item
            .get("NetworkSettings")
            .and_then(|ns| ns.get("Networks"))
            .and_then(JsonVal::as_obj)
        {
            let net_names: Vec<String> = networks.keys().cloned().collect();
            for network in net_names {
                self.command(&[
                    "network".to_string(),
                    "disconnect".to_string(),
                    "--force".to_string(),
                    network,
                    backup_id.clone(),
                ])?;
            }
        }
        self.verify(backup)
    }

    fn verify(&mut self, _backup: &JsonVal) -> Result<(), String> {
        let item = self.inspect()?;
        let has_nets = item
            .get("NetworkSettings")
            .and_then(|ns| ns.get("Networks"))
            .and_then(JsonVal::as_obj)
            .is_some_and(|m| !m.is_empty());
        if has_nets {
            return Err("Podman networks remain attached".to_string());
        }
        Ok(())
    }

    fn release(&mut self, backup: &JsonVal) -> Result<DriverReleaseOutcome, String> {
        if let Err(err) = self.verify(backup) {
            let check_cmd = vec![
                self.binary.clone(),
                "inspect".to_string(),
                "--type".to_string(),
                "container".to_string(),
                "--format".to_string(),
                "{{.Id}}".to_string(),
                self.instance_id.clone(),
            ];
            let (ok, output) = self.runner.run(&check_cmd, None);
            if !ok && is_podman_not_found(&output) {
                return Ok(DriverReleaseOutcome {
                    container_deleted: true,
                });
            }
            return Err(err);
        }

        let networks = backup
            .get("networks")
            .and_then(JsonVal::as_obj)
            .ok_or_else(|| "invalid Podman backup".to_string())?;
        let backup_id = backup
            .get_str("id")
            .ok_or_else(|| "invalid Podman backup".to_string())?
            .to_string();

        let mut restored = Vec::new();
        let res = (|| -> Result<(), String> {
            for (net_name, net_obj) in networks {
                let mut args = vec!["network".to_string(), "connect".to_string()];
                for (field, flag) in [
                    ("IPAddress", "--ip"),
                    ("GlobalIPv6Address", "--ip6"),
                    ("MacAddress", "--mac-address"),
                ] {
                    if let Some(val) = net_obj.get_str(field).filter(|s| !s.is_empty()) {
                        args.push(flag.to_string());
                        args.push(val.to_string());
                    }
                }
                if let Some(aliases) = net_obj.get("Aliases").and_then(JsonVal::as_arr) {
                    for alias in aliases {
                        if let Some(alias_str) = alias.as_str() {
                            args.push("--alias".to_string());
                            args.push(alias_str.to_string());
                        }
                    }
                }
                args.push(net_name.clone());
                args.push(backup_id.clone());
                self.command(&args)?;
                restored.push(net_name.clone());
            }

            let fresh_item = self.inspect()?;
            let fresh_nets = fresh_item
                .get("NetworkSettings")
                .and_then(|ns| ns.get("Networks"))
                .and_then(JsonVal::as_obj)
                .ok_or_else(|| "Podman restore readback mismatch".to_string())?;
            let expected_keys: BTreeSet<&String> = networks.keys().collect();
            let actual_keys: BTreeSet<&String> = fresh_nets.keys().collect();
            if expected_keys != actual_keys {
                return Err("Podman restore readback mismatch".to_string());
            }

            for (net_name, previous) in networks {
                let fresh_net = &fresh_nets[net_name];
                for field in ["IPAddress", "GlobalIPv6Address", "MacAddress"] {
                    if let Some(prev_val) = previous.get_str(field).filter(|s| !s.is_empty()) {
                        let cur_val = fresh_net.get_str(field).unwrap_or("");
                        if !cur_val.eq_ignore_ascii_case(prev_val) {
                            return Err("Podman restored address readback mismatch".to_string());
                        }
                    }
                }
                let prev_aliases: BTreeSet<&str> = previous
                    .get("Aliases")
                    .and_then(JsonVal::as_arr)
                    .map(|a| a.iter().filter_map(JsonVal::as_str).collect())
                    .unwrap_or_default();
                let cur_aliases: BTreeSet<&str> = fresh_net
                    .get("Aliases")
                    .and_then(JsonVal::as_arr)
                    .map(|a| a.iter().filter_map(JsonVal::as_str).collect())
                    .unwrap_or_default();
                if !prev_aliases.is_subset(&cur_aliases) {
                    return Err("Podman restored aliases readback mismatch".to_string());
                }
            }
            Ok(())
        })();

        if let Err(err) = res {
            for net_name in restored {
                let _ = self.command(&[
                    "network".to_string(),
                    "disconnect".to_string(),
                    "--force".to_string(),
                    net_name,
                    backup_id.clone(),
                ]);
            }
            return Err(err);
        }

        Ok(DriverReleaseOutcome {
            container_deleted: false,
        })
    }

    fn prove_replaced(&mut self) -> Result<String, String> {
        let current_id = self.inspect().ok().and_then(|item| {
            item.get_str("Id")
                .or_else(|| item.get_str("ID"))
                .map(ToString::to_string)
        });

        let check_cmd = vec![
            self.binary.clone(),
            "inspect".to_string(),
            "--type".to_string(),
            "container".to_string(),
            "--format".to_string(),
            "{{.Id}}".to_string(),
            self.instance_id.clone(),
        ];
        let (ok, output) = self.runner.run(&check_cmd, None);
        let id_lower = self.instance_id.to_ascii_lowercase();
        if ok {
            let old_ids: Vec<String> = output
                .lines()
                .map(|l| l.trim().to_ascii_lowercase())
                .filter(|l| !l.is_empty())
                .collect();
            if old_ids.is_empty()
                || old_ids.iter().any(|old_id| {
                    old_id == &id_lower
                        || old_id.starts_with(&id_lower)
                        || id_lower.starts_with(old_id)
                })
            {
                return Err("old Podman container still exists".to_string());
            }
            return Err("Podman returned an unexpected old-container identity".to_string());
        }
        if !is_podman_not_found(&output) {
            return Err("Podman could not prove the old container absent".to_string());
        }

        let Some(cur_id) = current_id else {
            return Ok("none".to_string());
        };
        if !is_hex_12_64(&cur_id) {
            return Err("Podman replacement identity could not be verified".to_string());
        }
        let cur_lower = cur_id.to_ascii_lowercase();
        if cur_lower.starts_with(&id_lower) || id_lower.starts_with(&cur_lower) {
            return Err("Podman container identity did not change".to_string());
        }
        Ok(cur_id)
    }
}

pub trait RunmanTransport {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), String>;
}

pub struct LiveRunmanTransport {
    pub socket_path: String,
}

impl LiveRunmanTransport {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }
}

impl RunmanTransport for LiveRunmanTransport {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), String> {
        runman_request(&self.socket_path, method, path, body)
    }
}

pub struct RunmanIsolation<T: RunmanTransport> {
    pub transport: T,
    pub name: String,
    pub instance_id: String,
}

impl<T: RunmanTransport> RunmanIsolation<T> {
    pub fn new(transport: T, name: impl Into<String>, instance_id: impl Into<String>) -> Self {
        Self {
            transport,
            name: name.into(),
            instance_id: instance_id.into(),
        }
    }

    pub fn command(&mut self, action: &str) -> Result<JsonVal, String> {
        let payload = format!(
            "{{\"container_name\":\"{}\",\"project\":\"default\",\"instance_id\":\"{}\",\"action\":\"{}\"}}",
            json_escape(&self.name),
            json_escape(&self.instance_id),
            json_escape(action),
        );
        let (status, raw) = self
            .transport
            .request("POST", "/v1/network-quarantine", Some(payload.as_bytes()))
            .map_err(|_| "Runman network quarantine socket unavailable or invalid".to_string())?;
        if status != 200 || raw.len() > MAX_RUNMAN_QUARANTINE_BYTES {
            return Err("Runman network quarantine request was not confirmed".to_string());
        }
        let result = if raw.is_empty() {
            JsonVal::Obj(BTreeMap::new())
        } else {
            let text = std::str::from_utf8(&raw)
                .map_err(|_| "Runman network quarantine socket unavailable or invalid".to_string())?;
            JsonVal::parse(text)
                .map_err(|_| "Runman network quarantine socket unavailable or invalid".to_string())?
        };
        if result.get_bool("ok") != Some(true) {
            return Err("Runman network quarantine returned an invalid response".to_string());
        }
        let generation = result.get_str("instance_id").unwrap_or("");
        if action != "replacement" && generation != self.instance_id {
            return Err("Runman instance generation changed; refused".to_string());
        }
        if result.get_bool("isolated").is_none()
            || result.get_bool("interface_up").is_none()
            || result.get_bool("running").is_none()
        {
            return Err("Runman network quarantine readback is incomplete".to_string());
        }
        Ok(result)
    }

    pub fn inspect(&mut self) -> Result<JsonVal, String> {
        self.command("inspect")
    }

    pub fn inventory(&mut self) -> Result<Vec<JsonVal>, String> {
        let (status, raw) = self
            .transport
            .request("GET", "/v1/inventory", None)
            .map_err(|_| "Runman inventory socket unavailable or invalid".to_string())?;
        if status != 200 || raw.len() > MAX_RUNMAN_INVENTORY_BYTES {
            return Err("Runman inventory request failed".to_string());
        }
        let text = std::str::from_utf8(&raw)
            .map_err(|_| "Runman inventory socket unavailable or invalid".to_string())?;
        let parsed = JsonVal::parse(text)
            .map_err(|_| "Runman inventory socket unavailable or invalid".to_string())?;
        if parsed.get_i64("schema") != Some(1) {
            return Err("Runman inventory schema invalid".to_string());
        }
        let items = parsed
            .get("items")
            .and_then(JsonVal::as_arr)
            .ok_or_else(|| "Runman inventory schema invalid".to_string())?;
        Ok(items.to_vec())
    }
}

impl<T: RunmanTransport> IsolationDriver for RunmanIsolation<T> {
    fn snapshot(&mut self) -> Result<JsonVal, String> {
        let state = self.inspect()?;
        if state.get_bool("running") != Some(true)
            || state.get_bool("isolated") != Some(false)
            || state.get_bool("interface_up") != Some(true)
        {
            return Err("Runman interface is not in a verified connected state".to_string());
        }
        Ok(JsonVal::Obj(BTreeMap::from([(
            "interface_was_up".to_string(),
            JsonVal::Bool(true),
        )])))
    }

    fn isolate(&mut self, backup: &JsonVal) -> Result<(), String> {
        if backup.get_bool("interface_was_up") != Some(true) {
            return Err("Runman quarantine recovery state is invalid".to_string());
        }
        let state = self.command("isolate")?;
        if state.get_bool("running") != Some(true)
            || state.get_bool("isolated") != Some(true)
            || state.get_bool("interface_up") != Some(false)
        {
            return Err("Runman interface-down isolation was not confirmed".to_string());
        }
        Ok(())
    }

    fn verify(&mut self, _backup: &JsonVal) -> Result<(), String> {
        let state = self.inspect()?;
        if state.get_bool("running") != Some(true)
            || state.get_bool("isolated") != Some(true)
            || state.get_bool("interface_up") != Some(false)
        {
            return Err("Runman quarantine is not active on the host veth".to_string());
        }
        Ok(())
    }

    fn release(&mut self, backup: &JsonVal) -> Result<DriverReleaseOutcome, String> {
        if backup.get_bool("interface_was_up") != Some(true) {
            return Err("Runman quarantine recovery state is invalid".to_string());
        }
        if let Err(err) = self.verify(backup) {
            let items = self.inventory()?;
            let present = items.iter().any(|item| {
                let gen_match = item.get_str("instance_id") == Some(self.instance_id.as_str());
                let id_match = item
                    .get_str("id")
                    .is_some_and(|id| id.eq_ignore_ascii_case(&self.name));
                gen_match || id_match
            });
            if !present {
                return Ok(DriverReleaseOutcome {
                    container_deleted: true,
                });
            }
            return Err(err);
        }

        let state = self.command("release")?;
        let isolated = state.get_bool("isolated").unwrap_or(true);
        let running = state.get_bool("running").unwrap_or(false);
        let interface_up = state.get_bool("interface_up").unwrap_or(false);
        if isolated || (running && !interface_up) {
            return Err("Runman network release readback mismatch".to_string());
        }
        Ok(DriverReleaseOutcome {
            container_deleted: false,
        })
    }

    fn prove_replaced(&mut self) -> Result<String, String> {
        if let Ok(state) = self.command("replacement") {
            let gen = state.get_str("instance_id").unwrap_or("");
            if !gen.is_empty() && gen != self.instance_id {
                return Ok(gen.to_string());
            }
        }

        let items = self.inventory()?;
        for item in items {
            if item.as_obj().is_none() {
                continue;
            }
            let gen = item.get_str("instance_id").unwrap_or("");
            if gen == self.instance_id {
                return Err("old Runman instance still exists".to_string());
            }
            let vm_id = item.get_str("id").unwrap_or("");
            if vm_id.eq_ignore_ascii_case(&self.name) {
                if !gen.is_empty() && gen != self.instance_id {
                    return Ok(gen.to_string());
                }
                return Err("Runman container identity did not change".to_string());
            }
        }
        Ok("none".to_string())
    }
}

/// Persist recovery record before mutating connectivity, then isolate and verify.
pub fn quarantine_entry(
    journal: &QuarantineJournal,
    key: &str,
    driver: &mut dyn IsolationDriver,
    evidence: &[JsonVal],
    now_unix: u64,
) -> Result<JsonVal, String> {
    let _guard = lock_guard(&QUARANTINE_LOCK);
    let mut entries = journal.read()?;

    if !entries.contains_key(key) {
        if entries.len() >= MAX_JOURNAL_ENTRIES {
            return Err("quarantine journal full".to_string());
        }
        let backup = driver.snapshot()?;
        let cleaned = safe_evidence(evidence)?;
        let mut entry = BTreeMap::new();
        entry.insert("status".to_string(), JsonVal::Str("applying".to_string()));
        entry.insert("created_at".to_string(), JsonVal::Num(now_unix as f64));
        entry.insert("backup".to_string(), backup);
        entry.insert("evidence".to_string(), JsonVal::Arr(cleaned));
        entries.insert(key.to_string(), JsonVal::Obj(entry));
        journal.write(&entries)?;
    }

    let apply_res = (|| -> Result<u64, String> {
        let mut backup_copy = entries
            .get(key)
            .and_then(|e| e.get("backup"))
            .cloned()
            .ok_or_else(|| "missing backup in quarantine journal".to_string())?;
        driver.refresh_backup(&mut backup_copy)?;
        if let Some(JsonVal::Obj(entry_obj)) = entries.get_mut(key) {
            entry_obj.insert("backup".to_string(), backup_copy.clone());
        }
        journal.write(&entries)?;

        driver.isolate(&backup_copy)?;
        let verified_at = current_unix_ts().max(now_unix);
        Ok(verified_at)
    })();

    match apply_res {
        Ok(verified_at) => {
            if let Some(JsonVal::Obj(entry_obj)) = entries.get_mut(key) {
                entry_obj.insert("status".to_string(), JsonVal::Str("isolated".to_string()));
                entry_obj.insert("verified_at".to_string(), JsonVal::Num(verified_at as f64));
                entry_obj.insert("last_error".to_string(), JsonVal::Str(String::new()));
            }
            journal.write(&entries)?;
            Ok(JsonVal::Obj(BTreeMap::from([
                ("status".to_string(), JsonVal::Str("isolated".to_string())),
                ("ingress_blocked".to_string(), JsonVal::Bool(true)),
                ("egress_blocked".to_string(), JsonVal::Bool(true)),
                ("verified_at".to_string(), JsonVal::Num(verified_at as f64)),
                ("data_preserved".to_string(), JsonVal::Bool(true)),
            ])))
        }
        Err(err) => {
            if let Some(JsonVal::Obj(entry_obj)) = entries.get_mut(key) {
                entry_obj.insert("status".to_string(), JsonVal::Str("failed".to_string()));
                entry_obj.insert("last_error".to_string(), JsonVal::Str(err.clone()));
            }
            journal.write(&entries)?;
            Err(err)
        }
    }
}

/// Release an active quarantine entry; on release failure, re-isolate and retain journal entry.
pub fn release_journal_entry(
    journal: &QuarantineJournal,
    key: &str,
    driver: &mut dyn IsolationDriver,
) -> Result<DriverReleaseOutcome, String> {
    let _guard = lock_guard(&QUARANTINE_LOCK);
    let mut entries = journal.read()?;
    let backup = entries
        .get(key)
        .and_then(|e| e.get("backup"))
        .cloned()
        .ok_or_else(|| "no quarantine recovery record".to_string())?;

    match driver.release(&backup) {
        Ok(outcome) => {
            entries.remove(key);
            journal.write(&entries)?;
            Ok(outcome)
        }
        Err(err) => {
            let reisolated = driver.isolate(&backup).is_ok();
            if let Some(JsonVal::Obj(entry_obj)) = entries.get_mut(key) {
                entry_obj.insert(
                    "status".to_string(),
                    JsonVal::Str(
                        if reisolated {
                            "release_failed"
                        } else {
                            "failed"
                        }
                        .to_string(),
                    ),
                );
                entry_obj.insert("last_error".to_string(), JsonVal::Str(err.clone()));
            }
            journal.write(&entries)?;
            Err(err)
        }
    }
}

/// Archive the old quarantine journal entry only after runtime identity absence is proven.
pub fn retire_replaced_journal_entry(
    journal: &QuarantineJournal,
    key: &str,
    driver: &mut dyn IsolationDriver,
) -> Result<String, String> {
    let _guard = lock_guard(&QUARANTINE_LOCK);
    let mut entries = journal.read()?;
    let current_id = driver.prove_replaced()?;
    entries.remove(key);
    journal.write(&entries)?;
    Ok(current_id)
}

pub fn release_network_quarantine(
    runtime: &str,
    project: &str,
    name: &str,
    instance_id: &str,
) -> ActionOutcome {
    let Ok(journal) = QuarantineJournal::new(None) else {
        return ActionOutcome::err(
            "Network restore could not be verified; inspect the recovery journal; no data deleted",
        );
    };
    let res = with_live_driver(runtime, project, name, instance_id, |key, driver| {
        release_network_quarantine_with(runtime, project, name, instance_id, &journal, driver, key)
    });
    res.unwrap_or_else(|_| {
        ActionOutcome::err(
            "Network restore could not be verified; inspect the recovery journal; no data deleted",
        )
    })
}

pub fn release_network_quarantine_with(
    _runtime: &str,
    _project: &str,
    _name: &str,
    _instance_id: &str,
    journal: &QuarantineJournal,
    driver: &mut dyn IsolationDriver,
    key: &str,
) -> ActionOutcome {
    match release_journal_entry(journal, key, driver) {
        Ok(outcome) if outcome.container_deleted => ActionOutcome::ok(
            "container_deleted_verified old_instance_absent=true old_journal_cleared=true",
        ),
        Ok(_) => ActionOutcome::ok(
            "Network quarantine released; data preserved; fresh prohibited activity will be isolated again",
        ),
        Err(_) => ActionOutcome::err(
            "Network restore could not be verified; inspect the recovery journal; no data deleted",
        ),
    }
}

pub fn confirm_replaced_network_quarantine(
    runtime: &str,
    project: &str,
    name: &str,
    instance_id: &str,
) -> ActionOutcome {
    let Ok(journal) = QuarantineJournal::new(None) else {
        return ActionOutcome::err(
            "Container replacement could not be verified; old quarantine remains pending; no replacement network changed",
        );
    };
    let res = with_live_driver(runtime, project, name, instance_id, |key, driver| {
        confirm_replaced_network_quarantine_with(
            runtime,
            project,
            name,
            instance_id,
            &journal,
            driver,
            key,
        )
    });
    res.unwrap_or_else(|_| {
        ActionOutcome::err(
            "Container replacement could not be verified; old quarantine remains pending; no replacement network changed",
        )
    })
}

pub fn confirm_replaced_network_quarantine_with(
    _runtime: &str,
    _project: &str,
    _name: &str,
    _instance_id: &str,
    journal: &QuarantineJournal,
    driver: &mut dyn IsolationDriver,
    key: &str,
) -> ActionOutcome {
    match retire_replaced_journal_entry(journal, key, driver) {
        Ok(replacement_id) if replacement_id == "none" => ActionOutcome::ok(
            "replacement_verified current_instance_id=none container_deleted=true old_instance_absent=true old_journal_cleared=true",
        ),
        Ok(replacement_id) => ActionOutcome::ok(format!(
            "replacement_verified current_instance_id={replacement_id} old_instance_absent=true old_journal_cleared=true"
        )),
        Err(_) => ActionOutcome::err(
            "Container replacement could not be verified; old quarantine remains pending; no replacement network changed",
        ),
    }
}

fn with_live_driver<F>(
    runtime: &str,
    project: &str,
    name: &str,
    instance_id: &str,
    op: F,
) -> Result<ActionOutcome, String>
where
    F: FnOnce(&str, &mut dyn IsolationDriver) -> ActionOutcome,
{
    let key = quarantine_target(runtime, project, name, instance_id)?;
    match runtime {
        "incus" => {
            let mut driver = IncusIsolation::new(
                UnixIncusApi::new(project, DEFAULT_INCUS_SOCKET),
                name,
                instance_id,
            );
            Ok(op(&key, &mut driver))
        }
        "podman" => {
            let binary = NetToolPaths::discover()
                .podman_bin
                .ok_or_else(|| "Podman unavailable".to_string())?;
            let mut runner = LiveCommandRunner;
            let mut driver = PodmanIsolation::new(&mut runner, binary, name, instance_id);
            Ok(op(&key, &mut driver))
        }
        "runman" => {
            let mut driver = RunmanIsolation::new(
                LiveRunmanTransport::new(DEFAULT_RUNMAN_SOCKET),
                name,
                instance_id,
            );
            Ok(op(&key, &mut driver))
        }
        _ => Err("unsupported runtime".to_string()),
    }
}

// ---------------------------------------------------------------------------
// 6. Comprehensive Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn make_temp_dir(label: &str) -> PathBuf {
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!(
            "narwhal_net_guard_{label}_{}_{seq}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    #[derive(Default)]
    struct MockRunner {
        calls: Vec<(Vec<String>, Option<String>)>,
        responses: VecDeque<(bool, String)>,
        default_ok: bool,
        default_out: String,
    }

    impl MockRunner {
        fn always(ok: bool, out: &str) -> Self {
            Self {
                calls: Vec::new(),
                responses: VecDeque::new(),
                default_ok: ok,
                default_out: out.to_string(),
            }
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&mut self, args: &[String], stdin: Option<&str>) -> (bool, String) {
            self.calls
                .push((args.to_vec(), stdin.map(ToString::to_string)));
            if let Some(resp) = self.responses.pop_front() {
                resp
            } else {
                (self.default_ok, self.default_out.clone())
            }
        }
    }

    fn tools_with_all() -> NetToolPaths {
        NetToolPaths {
            nsenter_bin: Some("/usr/bin/nsenter".to_string()),
            nft_bin: Some("/usr/sbin/nft".to_string()),
            iptables_bin: Some("/usr/sbin/iptables".to_string()),
            podman_bin: Some("/usr/bin/podman".to_string()),
            sysctl_bin: Some("sysctl".to_string()),
        }
    }

    #[test]
    fn test_identifier_regex_validators() {
        assert!(is_safe_key("test-vm_1.prod:80@host+a"));
        assert!(!is_safe_key(""));
        assert!(!is_safe_key("bad/name"));
        assert!(!is_safe_key(&"a".repeat(257)));

        assert!(is_safe_veth("veth1a2b"));
        assert!(is_safe_veth("eth0.10-a_b"));
        assert!(!is_safe_veth(""));
        assert!(!is_safe_veth("."));
        assert!(!is_safe_veth(".."));
        assert!(!is_safe_veth("bad;veth"));
        assert!(!is_safe_veth("vethname_too_long_17"));

        assert!(is_safe_quarantine_name("customer-1"));
        assert!(!is_safe_quarantine_name("narwhal-monitor-client"));
        assert!(!is_safe_quarantine_name("narwhal-monitor-server"));
        assert!(!is_safe_quarantine_name("narwhal-monitor-caddy"));
        assert!(!is_safe_quarantine_name("x;evil"));

        assert!(is_uuid_lower("11111111-2222-3333-4444-555555555555"));
        assert!(!is_uuid_v4_lower("11111111-2222-3333-4444-555555555555"));
        assert!(is_uuid_v4_lower("22222222-2222-4222-8222-222222222222"));
        assert!(!is_uuid_v4_lower("22222222-2222-4222-0222-222222222222"));

        assert!(is_valid_incus_operation(
            "/1.0/operations/11111111-2222-3333-4444-555555555555"
        ));
        assert!(!is_valid_incus_operation("/1.0/operations/../bad"));
    }

    #[test]
    fn test_udp_blackhole_validation_rules_and_lifecycle() {
        let dir = make_temp_dir("udp");
        let journal = dir.join("udp-blackhole.json");
        let tools = tools_with_all();
        let mut runner = MockRunner::always(true, "table inet narwhal_udp_guard");

        // Invalid parameters
        let bad_rt = UdpBlackholeApply::new("docker", "my-container", 100);
        let r_rt = apply_udp_blackhole_with(&bad_rt, &journal, &tools, &mut runner, 1000);
        assert!(!r_rt.ok);
        assert!(r_rt.message.contains("不支持的运行时"));

        let bad_name = UdpBlackholeApply::new("runman", "bad/name", 100);
        let r_name = apply_udp_blackhole_with(&bad_name, &journal, &tools, &mut runner, 1000);
        assert!(!r_name.ok);
        assert!(r_name.message.contains("容器名称格式无效"));

        let bad_pid = UdpBlackholeApply::new("runman", "c1", 1);
        let r_pid = apply_udp_blackhole_with(&bad_pid, &journal, &tools, &mut runner, 1000);
        assert!(!r_pid.ok);
        assert!(r_pid.message.contains("容器 PID 无效"));

        let no_nsenter = NetToolPaths {
            nsenter_bin: None,
            ..tools.clone()
        };
        let valid_req = UdpBlackholeApply {
            auto_triggered: true,
            duration: 1200,
            reason: "高危小包泛洪".to_string(),
            ..UdpBlackholeApply::new("runman", "test-vm-1", 1234)
        };
        let r_ns = apply_udp_blackhole_with(&valid_req, &journal, &no_nsenter, &mut runner, 1000);
        assert!(!r_ns.ok);
        assert!(r_ns.message.contains("nsenter"));

        // Apply with allow_dns=true
        let r_ok = apply_udp_blackhole_with(&valid_req, &journal, &tools, &mut runner, 1000);
        assert!(r_ok.ok);
        assert!(r_ok.message.contains("专项阻断"));
        assert!(r_ok.message.contains("放行 53 端口 DNS"));
        assert_eq!(runner.calls.len(), 1);
        assert_eq!(
            runner.calls[0].0,
            vec![
                "/usr/bin/nsenter",
                "-t",
                "1234",
                "-n",
                "--",
                "/usr/sbin/nft",
                "-f",
                "-"
            ]
        );
        let nft_stdin = runner.calls[0].1.as_deref().unwrap();
        assert!(nft_stdin.contains("table inet narwhal_udp_guard"));
        assert!(nft_stdin.contains("udp dport 53 accept"));
        assert!(nft_stdin.contains("ip protocol udp drop"));
        assert!(nft_stdin.contains("ip6 nexthdr udp drop"));

        // Status check
        let st = get_udp_blackhole_status_with(
            "runman",
            "test-vm-1",
            1234,
            &journal,
            &tools,
            Some(&mut runner),
            1040,
        )
        .expect("status");
        assert!(st.active);
        assert!(st.allow_dns);
        assert!(st.auto_triggered);
        assert_eq!(st.expires_at, Some(2200));
        assert_eq!(st.remaining_seconds, Some(1160));
        assert_eq!(st.reason, "高危小包泛洪");

        // Release
        runner.calls.clear();
        let rel = release_udp_blackhole_with(
            "runman",
            "test-vm-1",
            1234,
            "",
            "default",
            &journal,
            &tools,
            &mut runner,
        );
        assert!(rel.ok);
        assert!(rel.message.contains("已解除"));
        assert!(runner
            .calls
            .iter()
            .any(|(args, _)| args.ends_with(&[
                "delete".to_string(),
                "table".to_string(),
                "inet".to_string(),
                "narwhal_udp_guard".to_string()
            ])));

        let st_after = get_udp_blackhole_status_with(
            "runman",
            "test-vm-1",
            1234,
            &journal,
            &tools,
            None,
            1050,
        )
        .expect("status after");
        assert!(!st_after.active);

        // Fallback to iptables when nft fails and allow_dns=false
        let mut fb_runner = MockRunner::always(false, "");
        fb_runner.responses.push_back((false, "nft missing".to_string()));
        fb_runner.responses.push_back((true, String::new()));
        let no_dns = UdpBlackholeApply {
            allow_dns: false,
            ..UdpBlackholeApply::new("incus", "c-no-dns", 2222)
        };
        let r_fb = apply_udp_blackhole_with(&no_dns, &journal, &tools, &mut fb_runner, 2000);
        assert!(r_fb.ok);
        assert!(r_fb.message.contains("完全阻断全部 UDP"));
        assert_eq!(fb_runner.calls.len(), 2);
        assert_eq!(fb_runner.calls[1].0[4], "sh");
        assert!(!fb_runner.calls[1].0[6].contains("--dport 53"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_anti_spoof_validation_rules_and_lifecycle() {
        let dir = make_temp_dir("spoof");
        let journal = dir.join("anti-spoof.json");
        let tools = tools_with_all();
        let mut runner = MockRunner::always(true, "");

        let (v4, v6) = parse_valid_ips(&[
            "192.168.1.100",
            "127.0.0.1",
            "2001:0db8::1",
            "::1",
            "invalid-ip",
            "10.0.0.2",
        ]);
        assert_eq!(v4, vec!["10.0.0.2", "192.168.1.100"]);
        assert_eq!(v6, vec!["2001:db8::1"]);

        let bad_veth = apply_anti_spoof_with(
            "bad;veth",
            &["192.168.1.10"],
            "runman",
            "vm1",
            &journal,
            &tools,
            &mut runner,
            1000,
        );
        assert!(!bad_veth.ok);
        assert!(bad_veth.message.contains("无效的网卡接口名"));

        let bad_ips = apply_anti_spoof_with(
            "veth123",
            &["not-an-ip", "127.0.0.1"],
            "runman",
            "vm1",
            &journal,
            &tools,
            &mut runner,
            1000,
        );
        assert!(!bad_ips.ok);
        assert!(bad_ips.message.contains("未提供已分配的有效 IPv4 / IPv6 列表"));

        // Apply with both v4 and v6
        let ok_res = apply_anti_spoof_with(
            "veth1a2b",
            &["198.51.100.10", "2001:db8::5"],
            "runman",
            "test-vm",
            &journal,
            &tools,
            &mut runner,
            5000,
        );
        assert!(ok_res.ok);
        assert!(ok_res.message.contains("已在接口 veth1a2b 启用源地址防伪造保护"));
        assert!(runner
            .calls
            .iter()
            .any(|(args, _)| args == &["sysctl", "-w", "net.ipv4.conf.veth1a2b.rp_filter=1"]));
        assert!(runner.calls.iter().any(|(args, _)| {
            args.first().map(String::as_str) == Some("/usr/sbin/nft")
                && args.contains(&"ip".to_string())
                && args.contains(&"198.51.100.10".to_string())
        }));

        // v4-only rule blocks ip6
        let v4_only_rules =
            build_anti_spoof_nft_rules("veth1a2b", &["198.51.100.10".to_string()], &[]);
        assert_eq!(v4_only_rules.len(), 2);
        assert_eq!(
            v4_only_rules[1],
            "add rule inet narwhal_antispoof forward iifname \"veth1a2b\" ip6 drop"
        );

        let st = get_anti_spoof_status_with("veth1a2b", &journal).expect("status");
        assert!(st.active);
        assert_eq!(st.v4_ips, vec!["198.51.100.10"]);
        assert_eq!(st.v6_ips, vec!["2001:db8::5"]);

        let st_c =
            get_anti_spoof_status_for_container_with("RUNMAN", "test-vm", "", &journal).expect("lookup");
        assert!(st_c.active);
        assert_eq!(st_c.veth, "veth1a2b");

        runner.calls.clear();
        let rel = release_anti_spoof_with("veth1a2b", "runman", "test-vm", &journal, &tools, &mut runner);
        assert!(rel.ok);
        assert!(rel.message.contains("已在接口 veth1a2b 解除"));
        assert!(runner
            .calls
            .iter()
            .any(|(args, _)| args == &["sysctl", "-w", "net.ipv4.conf.veth1a2b.rp_filter=2"]));
        assert!(runner
            .calls
            .iter()
            .any(|(args, _)| args == &["/usr/sbin/nft", "delete", "table", "inet", "narwhal_antispoof"]));

        let st_after = get_anti_spoof_status_with("veth1a2b", &journal).expect("status after");
        assert!(!st_after.active);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_journal_permissions_symlink_rejection_and_atomic_replace() {
        let dir = make_temp_dir("journal");
        let journal_path = dir.join("sub").join("test.json");

        assert!(QuarantineJournal::new(Some(Path::new("relative.json"))).is_err());

        let qj = QuarantineJournal::new(Some(&journal_path)).expect("abs path");
        let mut data = BTreeMap::new();
        data.insert("k1".to_string(), JsonVal::Num(12345.0));
        qj.write(&data).expect("write 1");

        // Overwrite existing file cleanly on all platforms
        data.insert("k2".to_string(), JsonVal::Bool(true));
        qj.write(&data).expect("write 2");
        let read_back = qj.read().expect("read");
        assert_eq!(read_back.get("k1").and_then(JsonVal::as_i64), Some(12345));
        assert_eq!(read_back.get("k2").and_then(JsonVal::as_bool), Some(true));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let mode = fs::metadata(&journal_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);

            let link_path = dir.join("symlink.json");
            symlink(&journal_path, &link_path).unwrap();
            assert!(read_json_journal(&link_path).is_err());
            assert!(write_json_journal(&link_path, &data, ".t-", false).is_err());
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_quarantine_target_and_safe_evidence() {
        let vm_id = "11111111-2222-3333-4444-555555555555";
        let gen_id = "22222222-2222-4222-8222-222222222222";
        assert_eq!(
            quarantine_target("runman", "default", vm_id, gen_id).unwrap(),
            format!("[\"runman\",\"default\",\"{vm_id}\",\"{gen_id}\"]")
        );
        assert!(quarantine_target("docker", "", "cust", gen_id).is_err());
        assert!(quarantine_target("podman", "", "narwhal-monitor-server", gen_id).is_err());
        assert!(quarantine_target("incus", "", "x;evil", gen_id).is_err());
        assert!(quarantine_target("incus", "", "cust", "short").is_err());
        assert!(quarantine_target("runman", "other", vm_id, gen_id).is_err());
        assert!(quarantine_target("runman", "default", "cust", gen_id).is_err());
        assert!(quarantine_target("runman", "default", vm_id, "generation-1").is_err());

        let unsafe_ev = vec![JsonVal::parse(r#"{"source":"secret-code","argv":["--pass"]}"#).unwrap()];
        assert!(safe_evidence(&unsafe_ev).is_err());

        let mixed_ev = vec![JsonVal::parse(
            r#"{"kind":"identity_enumeration","confidence":"high","pid":20,"source":"strip-me","argv":["secret"],"features":{"http_calls":true,"unknown":1}}"#,
        )
        .unwrap()];
        let cleaned = safe_evidence(&mixed_ev).unwrap();
        assert_eq!(cleaned.len(), 1);
        let serialized = json_val_to_string(&JsonVal::Arr(cleaned), false);
        assert!(!serialized.contains("strip-me"));
        assert!(!serialized.contains("secret"));
        assert!(serialized.contains("\"kind\":\"identity_enumeration\""));
        assert!(serialized.contains("\"http_calls\":true"));
        assert!(!serialized.contains("\"unknown\""));
    }

    struct MockRunman {
        isolated: bool,
        interface_up: bool,
        running: bool,
        instance_id: String,
        deleted: bool,
    }

    impl RunmanTransport for MockRunman {
        fn request(
            &mut self,
            method: &str,
            path: &str,
            body: Option<&[u8]>,
        ) -> Result<(u16, Vec<u8>), String> {
            if method == "GET" && path == "/v1/inventory" {
                let items = if self.deleted {
                    "[]".to_string()
                } else {
                    format!(
                        "[{{\"id\":\"11111111-2222-3333-4444-555555555555\",\"instance_id\":\"{}\"}}]",
                        self.instance_id
                    )
                };
                return Ok((200, format!("{{\"schema\":1,\"items\":{items}}}").into_bytes()));
            }
            if method == "POST" && path == "/v1/network-quarantine" {
                if self.deleted {
                    return Ok((404, b"{}".to_vec()));
                }
                let req = JsonVal::parse(std::str::from_utf8(body.unwrap()).unwrap()).unwrap();
                match req.get_str("action") {
                    Some("isolate") => {
                        self.isolated = true;
                        self.interface_up = false;
                    }
                    Some("release") => {
                        self.isolated = false;
                        self.interface_up = true;
                    }
                    Some("replacement") => {
                        self.instance_id = "33333333-3333-4333-8333-333333333333".to_string();
                    }
                    _ => {}
                }
                let resp = format!(
                    "{{\"ok\":true,\"instance_id\":\"{}\",\"isolated\":{},\"interface_up\":{},\"running\":{}}}",
                    self.instance_id, self.isolated, self.interface_up, self.running
                );
                return Ok((200, resp.into_bytes()));
            }
            Err("unexpected request".to_string())
        }
    }

    #[test]
    fn test_runman_quarantine_release_deleted_and_replaced() {
        let dir = make_temp_dir("runman_q");
        let journal = QuarantineJournal::new(Some(&dir.join("q.json"))).unwrap();
        let vm = "11111111-2222-3333-4444-555555555555";
        let gen1 = "22222222-2222-4222-8222-222222222222";
        let key = quarantine_target("runman", "default", vm, gen1).unwrap();
        let evidence = vec![JsonVal::parse(r#"{"kind":"outbound_scan","pid":20}"#).unwrap()];

        let transport = MockRunman {
            isolated: false,
            interface_up: true,
            running: true,
            instance_id: gen1.to_string(),
            deleted: false,
        };
        let mut driver = RunmanIsolation::new(transport, vm, gen1);

        let res = quarantine_entry(&journal, &key, &mut driver, &evidence, 1000).unwrap();
        assert_eq!(res.get_str("status"), Some("isolated"));
        assert!(driver.transport.isolated);

        // Release normal
        let out = release_network_quarantine_with("runman", "default", vm, gen1, &journal, &mut driver, &key);
        assert!(out.ok);
        assert_eq!(
            out.message,
            "Network quarantine released; data preserved; fresh prohibited activity will be isolated again"
        );
        assert!(!driver.transport.isolated);
        assert!(journal.read().unwrap().is_empty());

        // Re-quarantine then simulate deletion -> release returns container_deleted_verified
        quarantine_entry(&journal, &key, &mut driver, &evidence, 2000).unwrap();
        driver.transport.deleted = true;
        let del_out = release_network_quarantine_with("runman", "default", vm, gen1, &journal, &mut driver, &key);
        assert!(del_out.ok);
        assert_eq!(
            del_out.message,
            "container_deleted_verified old_instance_absent=true old_journal_cleared=true"
        );
        assert!(journal.read().unwrap().is_empty());

        // Confirm replaced (new generation)
        driver.transport.deleted = false;
        driver.transport.isolated = false;
        driver.transport.interface_up = true;
        quarantine_entry(&journal, &key, &mut driver, &evidence, 3000).unwrap();
        let rep_out = confirm_replaced_network_quarantine_with(
            "runman",
            "default",
            vm,
            gen1,
            &journal,
            &mut driver,
            &key,
        );
        assert!(rep_out.ok);
        assert_eq!(
            rep_out.message,
            "replacement_verified current_instance_id=33333333-3333-4333-8333-333333333333 old_instance_absent=true old_journal_cleared=true"
        );
        assert!(journal.read().unwrap().is_empty());

        // Confirm replaced when deleted -> current_instance_id=none
        driver.transport.deleted = true;
        let rep_del = confirm_replaced_network_quarantine_with(
            "runman",
            "default",
            vm,
            gen1,
            &journal,
            &mut driver,
            &key,
        );
        assert!(rep_del.ok);
        assert_eq!(
            rep_del.message,
            "replacement_verified current_instance_id=none container_deleted=true old_instance_absent=true old_journal_cleared=true"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    struct FakeIncusApi {
        profile: BTreeMap<String, JsonVal>,
        item: Option<JsonVal>,
        revision: u64,
        fail_update: bool,
    }

    impl FakeIncusApi {
        fn new(uuid: &str) -> Self {
            let profile = BTreeMap::from([(
                "eth0".to_string(),
                JsonVal::parse(r#"{"type":"nic","name":"eth0","network":"incusbr0"}"#).unwrap(),
            )]);
            let item = JsonVal::parse(&format!(
                r#"{{
                    "config": {{
                        "volatile.uuid": "{uuid}",
                        "user.note": "preserved",
                        "volatile.eth0.hwaddr": "10:66:6a:00:00:11",
                        "volatile.eth0.name": "eth0"
                    }},
                    "devices": {{
                        "root": {{"type":"disk","path":"/","pool":"default"}},
                        "ssh": {{"type":"proxy","listen":"tcp:0.0.0.0:12345","connect":"tcp:127.0.0.1:22"}}
                    }},
                    "profiles": ["default"],
                    "description": "customer data",
                    "ephemeral": false
                }}"#
            ))
            .unwrap();
            Self {
                profile,
                item: Some(item),
                revision: 0,
                fail_update: false,
            }
        }
    }

    impl IncusTransport for FakeIncusApi {
        fn request(
            &mut self,
            method: &str,
            path: &str,
            body: Option<&JsonVal>,
            etag: Option<&str>,
        ) -> Result<(JsonVal, Option<String>), String> {
            if path.starts_with("/1.0/instances?recursion=2") {
                return match &self.item {
                    None => Ok((JsonVal::Arr(Vec::new()), None)),
                    Some(item) => {
                        let cfg = item.get("config").cloned().unwrap_or(JsonVal::Null);
                        let row = JsonVal::Obj(BTreeMap::from([
                            ("name".to_string(), JsonVal::Str("customer".to_string())),
                            ("config".to_string(), cfg),
                        ]));
                        Ok((JsonVal::Arr(vec![row]), None))
                    }
                };
            }
            let Some(ref cur) = self.item else {
                return Err("Incus API request failed: status 404".to_string());
            };
            if path.ends_with("/state") {
                let mut expanded = self.profile.clone();
                if let Some(devs) = cur.get("devices").and_then(JsonVal::as_obj) {
                    for (k, v) in devs {
                        expanded.insert(k.clone(), v.clone());
                    }
                }
                let mut nets = BTreeMap::new();
                let cfg = cur.get("config").and_then(JsonVal::as_obj);
                for (k, v) in expanded {
                    if v.get_str("type") == Some("nic") {
                        let name = v
                            .get_str("name")
                            .or_else(|| {
                                cfg.and_then(|c| {
                                    c.get(&format!("volatile.{k}.name")).and_then(JsonVal::as_str)
                                })
                            })
                            .unwrap_or("eth0")
                            .to_string();
                        let hw = v
                            .get_str("hwaddr")
                            .or_else(|| {
                                cfg.and_then(|c| {
                                    c.get(&format!("volatile.{k}.hwaddr"))
                                        .and_then(JsonVal::as_str)
                                })
                            })
                            .unwrap_or("")
                            .to_string();
                        nets.insert(
                            name,
                            JsonVal::Obj(BTreeMap::from([
                                ("state".to_string(), JsonVal::Str("up".to_string())),
                                ("hwaddr".to_string(), JsonVal::Str(hw)),
                            ])),
                        );
                    }
                }
                return Ok((
                    JsonVal::Obj(BTreeMap::from([("network".to_string(), JsonVal::Obj(nets))])),
                    None,
                ));
            }
            if method == "PUT" {
                if self.fail_update || etag != Some(self.revision.to_string().as_str()) {
                    return Err("conditional update failed".to_string());
                }
                let before_devs = cur
                    .get("devices")
                    .and_then(JsonVal::as_obj)
                    .cloned()
                    .unwrap_or_default();
                let mut before = self.profile.clone();
                before.extend(before_devs);

                let mut next_item = body.unwrap().as_obj().cloned().unwrap();
                let after_devs = next_item
                    .get("devices")
                    .and_then(JsonVal::as_obj)
                    .cloned()
                    .unwrap_or_default();
                let mut after = self.profile.clone();
                after.extend(after_devs);

                let all_keys: BTreeSet<String> =
                    before.keys().chain(after.keys()).cloned().collect();
                if let Some(JsonVal::Obj(ref mut cfg)) = next_item.get_mut("config") {
                    for k in all_keys {
                        let b_ty = before.get(&k).and_then(|d| d.get_str("type"));
                        let a_ty = after.get(&k).and_then(|d| d.get_str("type"));
                        if b_ty != a_ty {
                            for f in ["hwaddr", "name", "host_name"] {
                                cfg.remove(&format!("volatile.{k}.{f}"));
                            }
                            if a_ty == Some("nic") {
                                let dev = &after[&k];
                                if dev.get_str("hwaddr").unwrap_or("").is_empty() {
                                    cfg.insert(
                                        format!("volatile.{k}.hwaddr"),
                                        JsonVal::Str("10:66:6a:00:00:99".to_string()),
                                    );
                                }
                                if dev.get_str("name").unwrap_or("").is_empty() {
                                    cfg.insert(
                                        format!("volatile.{k}.name"),
                                        JsonVal::Str("eth0".to_string()),
                                    );
                                }
                            }
                        }
                    }
                }
                self.item = Some(JsonVal::Obj(next_item));
                self.revision += 1;
                return Ok((JsonVal::Obj(BTreeMap::new()), None));
            }
            let mut res = cur.as_obj().cloned().unwrap();
            let mut expanded = self.profile.clone();
            if let Some(devs) = res.get("devices").and_then(JsonVal::as_obj) {
                expanded.extend(devs.clone());
            }
            res.insert("expanded_devices".to_string(), JsonVal::Obj(expanded));
            Ok((JsonVal::Obj(res), Some(self.revision.to_string())))
        }
    }

    #[test]
    fn test_incus_quarantine_release_and_volatile_mac_restore() {
        let dir = make_temp_dir("incus_q");
        let journal = QuarantineJournal::new(Some(&dir.join("q.json"))).unwrap();
        let uuid = "c7a35d5c-e17c-4e25-8479-123456789abc";
        let key = quarantine_target("incus", "default", "customer", uuid).unwrap();
        let evidence = vec![JsonVal::parse(r#"{"kind":"identity_enumeration","pid":20}"#).unwrap()];

        let api = FakeIncusApi::new(uuid);
        let original_item = api.item.clone().unwrap();
        let mut driver = IncusIsolation::new(api, "customer", uuid);

        let res = quarantine_entry(&journal, &key, &mut driver, &evidence, 1000).unwrap();
        assert_eq!(res.get_str("status"), Some("isolated"));
        let cur_devs = driver
            .api
            .item
            .as_ref()
            .unwrap()
            .get("devices")
            .unwrap();
        assert_eq!(cur_devs.get("eth0").and_then(|d| d.get_str("type")), Some("none"));
        assert_eq!(cur_devs.get("ssh").and_then(|d| d.get_str("type")), Some("none"));

        let out = release_network_quarantine_with("incus", "default", "customer", uuid, &journal, &mut driver, &key);
        assert!(out.ok);
        assert_eq!(driver.api.item.as_ref().unwrap(), &original_item);
        assert!(journal.read().unwrap().is_empty());

        // Deletion case
        quarantine_entry(&journal, &key, &mut driver, &evidence, 2000).unwrap();
        driver.api.item = None;
        let del_out = release_network_quarantine_with("incus", "default", "customer", uuid, &journal, &mut driver, &key);
        assert!(del_out.ok);
        assert!(del_out.message.contains("container_deleted_verified"));

        let _ = fs::remove_dir_all(&dir);
    }

    struct FakePodmanRunner {
        item: JsonVal,
        deleted: bool,
        corrupt_ip_on_connect: bool,
    }

    impl FakePodmanRunner {
        fn new(id: &str) -> Self {
            let item = JsonVal::parse(&format!(
                r#"{{
                    "Id": "{id}",
                    "Pod": "",
                    "HostConfig": {{"NetworkMode": "bridge", "PidMode": "", "Privileged": false, "Devices": []}},
                    "NetworkSettings": {{
                        "Networks": {{
                            "one": {{"IPAddress": "10.90.0.2", "Aliases": ["customer"]}},
                            "two": {{"GlobalIPv6Address": "fd00::2", "MacAddress": "02:00:00:00:00:02"}}
                        }}
                    }},
                    "State": {{"Pid": 123}}
                }}"#
            ))
            .unwrap();
            Self {
                item,
                deleted: false,
                corrupt_ip_on_connect: false,
            }
        }
    }

    impl CommandRunner for FakePodmanRunner {
        fn run(&mut self, args: &[String], _stdin: Option<&str>) -> (bool, String) {
            if self.deleted {
                return (false, "Error: no such container".to_string());
            }
            if args.get(1).map(String::as_str) == Some("inspect") {
                return (
                    true,
                    json_val_to_string(&JsonVal::Arr(vec![self.item.clone()]), false),
                );
            }
            if args.get(1).map(String::as_str) == Some("network") {
                let op = args[2].as_str();
                let net_name = args[args.len() - 2].clone();
                let JsonVal::Obj(ref mut root) = self.item else {
                    return (false, "bad state".to_string());
                };
                let JsonVal::Obj(ref mut ns) = root.get_mut("NetworkSettings").unwrap() else {
                    return (false, "bad ns".to_string());
                };
                let JsonVal::Obj(ref mut nets) = ns.get_mut("Networks").unwrap() else {
                    return (false, "bad nets".to_string());
                };
                if op == "disconnect" {
                    nets.remove(&net_name);
                    return (true, String::new());
                } else if op == "connect" {
                    let opts = &args[3..args.len() - 2];
                    let mut restored = BTreeMap::new();
                    let mut aliases = Vec::new();
                    let mut i = 0;
                    while i < opts.len() {
                        match opts[i].as_str() {
                            "--ip" => {
                                let ip = if self.corrupt_ip_on_connect {
                                    "10.0.0.99".to_string()
                                } else {
                                    opts[i + 1].clone()
                                };
                                restored.insert("IPAddress".to_string(), JsonVal::Str(ip));
                                i += 2;
                            }
                            "--ip6" => {
                                restored.insert(
                                    "GlobalIPv6Address".to_string(),
                                    JsonVal::Str(opts[i + 1].clone()),
                                );
                                i += 2;
                            }
                            "--mac-address" => {
                                restored.insert(
                                    "MacAddress".to_string(),
                                    JsonVal::Str(opts[i + 1].clone()),
                                );
                                i += 2;
                            }
                            "--alias" => {
                                aliases.push(JsonVal::Str(opts[i + 1].clone()));
                                i += 2;
                            }
                            _ => i += 1,
                        }
                    }
                    restored.insert("Aliases".to_string(), JsonVal::Arr(aliases));
                    nets.insert(net_name, JsonVal::Obj(restored));
                    return (true, String::new());
                }
            }
            (false, "unsupported".to_string())
        }
    }

    #[test]
    fn test_podman_quarantine_release_and_rollback_on_mismatch() {
        let dir = make_temp_dir("podman_q");
        let journal = QuarantineJournal::new(Some(&dir.join("q.json"))).unwrap();
        let pod_id = "a".repeat(64);
        let key = quarantine_target("podman", "", "customer", &pod_id).unwrap();
        let evidence = vec![JsonVal::parse(r#"{"kind":"outbound_scan","pid":20}"#).unwrap()];

        let mut runner = FakePodmanRunner::new(&pod_id);
        {
            let mut driver = PodmanIsolation::new(&mut runner, "podman", "customer", &pod_id);
            quarantine_entry(&journal, &key, &mut driver, &evidence, 1000).unwrap();

            // Corrupt IP during connect -> release fails, rolls back connections, keeps journal!
            driver.runner = &mut *(driver.runner); // keep borrow clear
        }
        runner.corrupt_ip_on_connect = true;
        {
            let mut driver = PodmanIsolation::new(&mut runner, "podman", "customer", &pod_id);
            let fail_out = release_network_quarantine_with(
                "podman",
                "",
                "customer",
                &pod_id,
                &journal,
                &mut driver,
                &key,
            );
            assert!(!fail_out.ok);
            assert!(fail_out.message.contains("Network restore could not be verified"));
        }
        let nets_after_rollback = runner
            .item
            .get("NetworkSettings")
            .unwrap()
            .get("Networks")
            .unwrap()
            .as_obj()
            .unwrap();
        assert!(nets_after_rollback.is_empty());
        assert!(journal.read().unwrap().contains_key(&key));

        // Now release cleanly
        runner.corrupt_ip_on_connect = false;
        {
            let mut driver = PodmanIsolation::new(&mut runner, "podman", "customer", &pod_id);
            let ok_out = release_network_quarantine_with(
                "podman",
                "",
                "customer",
                &pod_id,
                &journal,
                &mut driver,
                &key,
            );
            assert!(ok_out.ok);
        }
        let nets_after_ok = runner
            .item
            .get("NetworkSettings")
            .unwrap()
            .get("Networks")
            .unwrap()
            .as_obj()
            .unwrap();
        assert_eq!(nets_after_ok.len(), 2);
        assert!(journal.read().unwrap().is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_incus_api_and_runman_isolation_over_unix_socket() {
        use std::os::unix::net::UnixListener;

        let dir = make_temp_dir("unix_sock");
        let incus_sock = dir.join("incus.sock");
        let listener = UnixListener::bind(&incus_sock).expect("bind unix socket");

        let handle = thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 2048];
            let n = conn.read(&mut buf).expect("read");
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.contains("GET /1.0/instances/cust?project=default HTTP/1.1"));

            let body = br#"{"type":"sync","metadata":{"config":{"volatile.uuid":"uuid-123456789012"}}}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"rev-1\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            conn.write_all(resp.as_bytes()).unwrap();
            conn.write_all(body).unwrap();
        });

        let mut api = UnixIncusApi::new("", incus_sock.to_string_lossy().into_owned());
        let (meta, etag) = api
            .request("GET", "/1.0/instances/cust", None, None)
            .expect("unix incus request");
        assert_eq!(etag.as_deref(), Some("\"rev-1\""));
        assert_eq!(
            meta.get("config").and_then(|c| c.get_str("volatile.uuid")),
            Some("uuid-123456789012")
        );
        handle.join().unwrap();

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_http_response_parser_headers_and_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nETag: \"abc-1\"\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        let (status, headers, body) = parse_http_response_with_headers(raw).expect("parse http");
        assert_eq!(status, 200);
        assert_eq!(headers.get("etag").map(String::as_str), Some("\"abc-1\""));
        assert_eq!(body, b"{\"a\":1}");
    }

    #[test]
    fn test_incus_safety_guards_refresh_and_confirm_replaced() {
        let dir = make_temp_dir("incus_extra");
        let journal = QuarantineJournal::new(Some(&dir.join("q.json"))).unwrap();
        let uuid = "c7a35d5c-e17c-4e25-8479-123456789abc";
        let key = quarantine_target("incus", "default", "customer", uuid).unwrap();
        let evidence = vec![JsonVal::parse(r#"{"kind":"identity_enumeration","pid":20}"#).unwrap()];

        // Unmanaged raw.lxc network must be rejected without PUT
        let mut raw_lxc_api = FakeIncusApi::new(uuid);
        if let Some(JsonVal::Obj(ref mut root)) = raw_lxc_api.item {
            if let Some(JsonVal::Obj(ref mut cfg)) = root.get_mut("config") {
                cfg.insert(
                    "raw.lxc".to_string(),
                    JsonVal::Str("lxc.net.0.type = phys".to_string()),
                );
            }
        }
        let mut raw_driver = IncusIsolation::new(raw_lxc_api, "customer", uuid);
        assert!(raw_driver.snapshot().is_err());

        // PCI passthrough device must be rejected
        let mut pci_api = FakeIncusApi::new(uuid);
        if let Some(JsonVal::Obj(ref mut root)) = pci_api.item {
            if let Some(JsonVal::Obj(ref mut devs)) = root.get_mut("devices") {
                devs.insert(
                    "gpu".to_string(),
                    JsonVal::Obj(BTreeMap::from([("type".to_string(), JsonVal::Str("pci".to_string()))])),
                );
            }
        }
        let mut pci_driver = IncusIsolation::new(pci_api, "customer", uuid);
        assert!(pci_driver.snapshot().is_err());

        // Operator modification blocks release & retains journal
        let mut op_driver = IncusIsolation::new(FakeIncusApi::new(uuid), "customer", uuid);
        quarantine_entry(&journal, &key, &mut op_driver, &evidence, 1000).unwrap();

        // Adding a new NIC while quarantined is automatically refreshed and masked
        if let Some(JsonVal::Obj(ref mut root)) = op_driver.api.item {
            if let Some(JsonVal::Obj(ref mut devs)) = root.get_mut("devices") {
                devs.insert(
                    "eth1".to_string(),
                    JsonVal::parse(r#"{"type":"nic","name":"eth1","network":"br1"}"#).unwrap(),
                );
            }
        }
        quarantine_entry(&journal, &key, &mut op_driver, &evidence, 1100).unwrap();
        assert_eq!(
            op_driver
                .api
                .item
                .as_ref()
                .unwrap()
                .get("devices")
                .unwrap()
                .get("eth1")
                .unwrap()
                .get_str("type"),
            Some("none")
        );

        // Operator overwrites quarantine mask -> release refused & journal preserved
        if let Some(JsonVal::Obj(ref mut root)) = op_driver.api.item {
            if let Some(JsonVal::Obj(ref mut devs)) = root.get_mut("devices") {
                devs.insert(
                    "ssh".to_string(),
                    JsonVal::parse(r#"{"type":"disk","path":"/new","pool":"default"}"#).unwrap(),
                );
            }
        }
        let rel_fail =
            release_network_quarantine_with("incus", "default", "customer", uuid, &journal, &mut op_driver, &key);
        assert!(!rel_fail.ok);
        assert!(journal.read().unwrap().contains_key(&key));

        // Replacement verification fails while old UUID exists, succeeds with new UUID
        let rep_fail = confirm_replaced_network_quarantine_with(
            "incus",
            "default",
            "customer",
            uuid,
            &journal,
            &mut op_driver,
            &key,
        );
        assert!(!rep_fail.ok);
        assert!(journal.read().unwrap().contains_key(&key));

        let new_uuid = "d8b46e6d-f28d-4f36-9580-abcdef012345";
        if let Some(JsonVal::Obj(ref mut root)) = op_driver.api.item {
            if let Some(JsonVal::Obj(ref mut cfg)) = root.get_mut("config") {
                cfg.insert("volatile.uuid".to_string(), JsonVal::Str(new_uuid.to_string()));
            }
        }
        let rep_ok = confirm_replaced_network_quarantine_with(
            "incus",
            "default",
            "customer",
            uuid,
            &journal,
            &mut op_driver,
            &key,
        );
        assert!(rep_ok.ok);
        assert_eq!(
            rep_ok.message,
            format!("replacement_verified current_instance_id={new_uuid} old_instance_absent=true old_journal_cleared=true")
        );
        assert!(journal.read().unwrap().is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_podman_shared_network_rejection_and_deleted_release() {
        let dir = make_temp_dir("podman_extra");
        let journal = QuarantineJournal::new(Some(&dir.join("q.json"))).unwrap();
        let pod_id = "b".repeat(64);
        let key = quarantine_target("podman", "", "customer", &pod_id).unwrap();
        let evidence = vec![JsonVal::parse(r#"{"kind":"outbound_scan","pid":20}"#).unwrap()];

        for mode in ["host", "container:other", "pasta", "slirp4netns"] {
            let mut r = FakePodmanRunner::new(&pod_id);
            if let JsonVal::Obj(ref mut root) = r.item {
                if let Some(JsonVal::Obj(ref mut hc)) = root.get_mut("HostConfig") {
                    hc.insert("NetworkMode".to_string(), JsonVal::Str(mode.to_string()));
                }
            }
            let mut drv = PodmanIsolation::new(&mut r, "podman", "customer", &pod_id);
            assert!(drv.snapshot().is_err(), "mode {mode} must be rejected");
        }

        let mut runner = FakePodmanRunner::new(&pod_id);
        {
            let mut drv = PodmanIsolation::new(&mut runner, "podman", "customer", &pod_id);
            quarantine_entry(&journal, &key, &mut drv, &evidence, 1000).unwrap();
        }
        runner.deleted = true;
        {
            let mut drv = PodmanIsolation::new(&mut runner, "podman", "customer", &pod_id);
            let del_out = release_network_quarantine_with(
                "podman",
                "",
                "customer",
                &pod_id,
                &journal,
                &mut drv,
                &key,
            );
            assert!(del_out.ok);
            assert_eq!(
                del_out.message,
                "container_deleted_verified old_instance_absent=true old_journal_cleared=true"
            );
        }
        assert!(journal.read().unwrap().is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_journal_corrupt_and_capacity_limits_and_outcomes() {
        let dir = make_temp_dir("j_limits");
        let bad_json = dir.join("bad.json");
        fs::write(&bad_json, "{corrupt").unwrap();
        assert!(read_json_journal(&bad_json).is_err());

        let arr_json = dir.join("arr.json");
        fs::write(&arr_json, "[]").unwrap();
        assert!(read_json_journal(&arr_json).is_err());

        let mut big = BTreeMap::new();
        for i in 0..=MAX_JOURNAL_ENTRIES {
            big.insert(format!("k{i}"), JsonVal::Bool(true));
        }
        assert!(write_json_journal(&dir.join("big.json"), &big, ".b-", false).is_err());

        let ok_out = ActionOutcome::ok("done");
        assert_eq!(ok_out.clone().into_result(), Ok("done".to_string()));
        let err_out = ActionOutcome::err("nope");
        assert_eq!(Result::<String, String>::from(err_out), Err("nope".to_string()));

        let _ = fs::remove_dir_all(&dir);
    }
}
