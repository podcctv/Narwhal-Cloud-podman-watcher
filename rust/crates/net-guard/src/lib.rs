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
mod tests;
