#![forbid(unsafe_code)]

pub mod actions;
mod banner;
mod cpu_guard_exec;
mod resource_guard_exec;
pub use banner::{build_shell_banner_install_script, build_ssh_banner_install_script};
use banner::MotdDeliveryState;
#[cfg(any(unix, test))]
use banner::fnv1a_hex;
use cpu_guard_exec::{ContainerMetricsSummary, CpuGuardEnforcer};
use resource_guard_exec::{IoGuardEnforcer, MemoryGuardEnforcer};
pub mod gfw_probe;
pub mod host_audit;

use std::collections::{BTreeSet, HashMap};
use std::fmt::{self, Write as _};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cgroup_probe::{collect_psi_snapshot, read_psi, PsiStatus};
use geoip_probe::lookup_countries;
use guard_core::security::{
    detect_suspicious_processes, evaluate_socket_abuse, ProcInfo, SocketAbuseInput,
    SocketAbuseVerdict, SuspiciousProcFinding,
};
use guard_core::{
    CpuContainerSample, CpuGuardConfig, CpuGuardTracker, HostCpuSample, HostDeviceSample,
    IoContainerSample, IoGuardConfig, IoGuardTracker, IoRates, MemoryContainerSample,
    MemoryGuardConfig, MemoryGuardTracker, PsiSample,
};
use host_metrics::{
    collect_diskstats, collect_host_metrics, parse_loadavg, parse_proc_stat_cpu, CpuMetrics,
};
use net_probe::is_allowed_host;
use proc_probe::{collect_host_proc_snapshot_from_root, json_escape};
use runtime_drivers::{discover_and_sample_containers, ContainerSample};
use socket_sec::collect_conntrack;
use transport::{TransportClient, TransportConfig, TransportError};

pub const DEFAULT_ENV_FILE: &str = "/opt/narwhal-monitor/client.env";
pub const DEFAULT_SERVER_URL: &str = "https://127.0.0.1:8080";
pub const DEFAULT_SHARED_SECRET: &str = "change-me";
pub const DEFAULT_REPORT_INTERVAL: u64 = 300;
pub const MIN_REPORT_INTERVAL: u64 = 60;
pub const DEFAULT_ACTION_POLL_INTERVAL: u64 = 10;
pub const MIN_ACTION_POLL_INTERVAL: u64 = 5;
pub const DEFAULT_GUARD_INTERVAL: u64 = 30;
pub const MIN_GUARD_INTERVAL: u64 = 15;
pub const DEFAULT_CONTAINER_RUNTIMES: &str = "auto";
pub const DEFAULT_DOCKER_MONITOR_MODE: &str = "notice";
pub const DEFAULT_INCUS_PROJECT: &str = "all";
pub const DEFAULT_ACCESS_LOG_MAX_BYTES: usize = 1_048_576;
pub const MIN_ACCESS_LOG_MAX_BYTES: usize = 65_536;
pub const DEFAULT_WEB_SCAN_PATTERNS: &str = ".env,.git,wp-login,wp-admin,phpmyadmin,actuator,server-status,cgi-bin,vendor/phpunit,etc/passwd,boaform,hnap1";
pub const MANAGED_UPDATE_RESULT_FILE: &str = "/opt/narwhal-monitor/managed-update-result.json";
pub const AGENT_VERSION: &str = env!("NARWHAL_AGENT_VERSION");

pub fn resolved_agent_version() -> String {
    if let Ok(v) = std::env::var("NARWHAL_VERSION") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    AGENT_VERSION.trim().to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    InvalidFlag(String),
    MissingFlagValue(String),
    InvalidInt { flag: String, value: String },
    HelpRequested,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFlag(flag) => write!(f, "unknown CLI flag: {flag}"),
            Self::MissingFlagValue(flag) => write!(f, "missing value for CLI flag: {flag}"),
            Self::InvalidInt { flag, value } => {
                write!(f, "invalid integer for {flag}: {value}")
            }
            Self::HelpRequested => write!(f, "help requested"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub server_url: String,
    pub shared_secret: String,
    pub report_interval: u64,
    pub action_poll_interval: u64,
    pub guard_interval: u64,
    pub host_id: String,
    pub node_id: String,
    pub server_tls_ca_file: Option<PathBuf>,
    pub container_runtimes: String,
    pub docker_monitor_mode: String,
    pub incus_project: String,
    pub security_monitor_enabled: bool,
    pub security_access_log_paths: Vec<String>,
    pub security_access_log_max_bytes: usize,
    pub security_web_scan_patterns: Vec<String>,
    pub once: bool,
    pub dry_run: bool,
    pub check_config: bool,
    pub release_admission: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: DEFAULT_SERVER_URL.to_string(),
            shared_secret: DEFAULT_SHARED_SECRET.to_string(),
            report_interval: DEFAULT_REPORT_INTERVAL,
            action_poll_interval: DEFAULT_ACTION_POLL_INTERVAL,
            guard_interval: DEFAULT_GUARD_INTERVAL,
            host_id: detect_default_host_id(),
            node_id: String::new(),
            server_tls_ca_file: None,
            container_runtimes: DEFAULT_CONTAINER_RUNTIMES.to_string(),
            docker_monitor_mode: DEFAULT_DOCKER_MONITOR_MODE.to_string(),
            incus_project: DEFAULT_INCUS_PROJECT.to_string(),
            security_monitor_enabled: true,
            security_access_log_paths: Vec::new(),
            security_access_log_max_bytes: DEFAULT_ACCESS_LOG_MAX_BYTES,
            security_web_scan_patterns: parse_csv_lowercase(DEFAULT_WEB_SCAN_PATTERNS),
            once: false,
            dry_run: false,
            check_config: false,
            release_admission: false,
        }
    }
}

impl Config {
    pub fn from_env_and_args() -> Result<Self, ConfigError> {
        let env_file_path = std::env::var("NARWHAL_CLIENT_ENV_FILE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_ENV_FILE.to_string());
        let env_file = Path::new(&env_file_path);
        let env_map: HashMap<String, String> = std::env::vars().collect();
        let args: Vec<String> = std::env::args().skip(1).collect();
        Self::from_sources(
            if env_file.is_file() {
                Some(env_file)
            } else {
                None
            },
            &env_map,
            &args,
        )
    }

    pub fn from_sources(
        env_file: Option<&Path>,
        process_env: &HashMap<String, String>,
        args: &[String],
    ) -> Result<Self, ConfigError> {
        let mut merged: HashMap<String, String> = HashMap::new();
        if let Some(path) = env_file {
            if let Ok(raw) = fs::read_to_string(path) {
                for (k, v) in parse_env_file(&raw) {
                    merged.insert(k, v);
                }
            }
        }
        for (k, v) in process_env {
            merged.insert(k.clone(), v.clone());
        }

        let mut cfg = Self::default();

        if let Some(v) = non_empty_env(&merged, "SERVER_URL") {
            cfg.server_url = v;
        }
        if let Some(v) = merged.get("SHARED_SECRET") {
            if !v.is_empty() {
                cfg.shared_secret = v.clone();
            }
        }
        if let Some(v) = non_empty_env(&merged, "REPORT_INTERVAL") {
            if let Ok(parsed) = v.parse::<u64>() {
                cfg.report_interval = parsed.max(MIN_REPORT_INTERVAL);
            }
        }
        if let Some(v) = non_empty_env(&merged, "ACTION_POLL_INTERVAL") {
            if let Ok(parsed) = v.parse::<u64>() {
                cfg.action_poll_interval = parsed.max(MIN_ACTION_POLL_INTERVAL);
            }
        }
        if let Some(v) = non_empty_env(&merged, "GUARD_SAMPLE_INTERVAL")
            .or_else(|| non_empty_env(&merged, "NARWHAL_GUARD_INTERVAL"))
        {
            if let Ok(parsed) = v.parse::<u64>() {
                cfg.guard_interval = parsed.max(MIN_GUARD_INTERVAL);
            }
        }
        if let Some(v) = non_empty_env(&merged, "HOST_ID") {
            cfg.host_id = v;
        }
        if let Some(v) = merged.get("NODE_ID") {
            cfg.node_id = v.trim().to_string();
        }
        if let Some(v) = non_empty_env(&merged, "SERVER_TLS_CA_FILE") {
            cfg.server_tls_ca_file = Some(PathBuf::from(v));
        }
        if let Some(v) = non_empty_env(&merged, "CONTAINER_RUNTIMES") {
            cfg.container_runtimes = v;
        }
        if let Some(v) = non_empty_env(&merged, "DOCKER_MONITOR_MODE") {
            cfg.docker_monitor_mode = v;
        }
        if let Some(v) = non_empty_env(&merged, "INCUS_PROJECT") {
            cfg.incus_project = v;
        }
        if let Some(v) = non_empty_env(&merged, "SECURITY_MONITOR_ENABLED") {
            cfg.security_monitor_enabled = parse_bool_flag(&v);
        }
        if let Some(v) = non_empty_env(&merged, "SECURITY_ACCESS_LOG_PATHS") {
            cfg.security_access_log_paths = parse_csv_items(&v);
        }
        if let Some(v) = non_empty_env(&merged, "SECURITY_ACCESS_LOG_MAX_BYTES") {
            if let Ok(parsed) = v.parse::<usize>() {
                cfg.security_access_log_max_bytes = parsed.max(MIN_ACCESS_LOG_MAX_BYTES);
            }
        }
        if let Some(v) = non_empty_env(&merged, "SECURITY_WEB_SCAN_PATTERNS") {
            cfg.security_web_scan_patterns = parse_csv_lowercase(&v);
        }

        let mut i = 0usize;
        while i < args.len() {
            match args[i].as_str() {
                "--server" => {
                    let val = next_cli_value(args, &mut i, "--server")?;
                    cfg.server_url = val.to_string();
                }
                "--secret" => {
                    let val = next_cli_value(args, &mut i, "--secret")?;
                    cfg.shared_secret = val.to_string();
                }
                "--interval" => {
                    let val = next_cli_value(args, &mut i, "--interval")?;
                    let parsed = val.parse::<u64>().map_err(|_| ConfigError::InvalidInt {
                        flag: "--interval".to_string(),
                        value: val.to_string(),
                    })?;
                    cfg.report_interval = parsed.max(MIN_REPORT_INTERVAL);
                }
                "--host-id" => {
                    let val = next_cli_value(args, &mut i, "--host-id")?;
                    cfg.host_id = val.to_string();
                }
                "--node-id" => {
                    let val = next_cli_value(args, &mut i, "--node-id")?;
                    cfg.node_id = val.to_string();
                }
                "--once" => {
                    cfg.once = true;
                }
                "--dry-run" => {
                    cfg.dry_run = true;
                }
                "--check-config" => {
                    cfg.check_config = true;
                }
                "--release-admission" => {
                    cfg.release_admission = true;
                }
                "-h" | "--help" => {
                    return Err(ConfigError::HelpRequested);
                }
                other => {
                    return Err(ConfigError::InvalidFlag(other.to_string()));
                }
            }
            i += 1;
        }

        Ok(cfg)
    }

    pub fn to_transport_config(&self) -> TransportConfig {
        TransportConfig::new(self.server_url.as_str(), self.shared_secret.as_str())
            .with_ca_cert_path(self.server_tls_ca_file.as_deref())
    }

    pub fn sanitized_summary(&self) -> String {
        let secret_status = if self.shared_secret.is_empty()
            || self.shared_secret == DEFAULT_SHARED_SECRET
        {
            "default-or-empty"
        } else {
            "configured(redacted)"
        };
        let ca_file = self
            .server_tls_ca_file
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        format!(
            "{{\"agent_version\":\"{}\",\"server_url\":\"{}\",\"shared_secret\":\"{}\",\"report_interval\":{},\"action_poll_interval\":{},\"host_id\":\"{}\",\"node_id\":\"{}\",\"server_tls_ca_file\":\"{}\",\"container_runtimes\":\"{}\",\"docker_monitor_mode\":\"{}\",\"incus_project\":\"{}\",\"security_monitor_enabled\":{},\"once\":{},\"dry_run\":{},\"check_config\":{}}}",
            json_escape(&resolved_agent_version()),
            json_escape(&self.server_url),
            secret_status,
            self.report_interval,
            self.action_poll_interval,
            json_escape(&self.host_id),
            json_escape(&self.node_id),
            json_escape(&ca_file),
            json_escape(&self.container_runtimes),
            json_escape(&self.docker_monitor_mode),
            json_escape(&self.incus_project),
            self.security_monitor_enabled,
            self.once,
            self.dry_run,
            self.check_config,
        )
    }
}

pub fn parse_env_file(raw: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let without_export = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        let Some((key, val)) = without_export.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let val = strip_matching_quotes(val.trim());
        out.push((key.to_string(), val.to_string()));
    }
    out
}

fn strip_matching_quotes(val: &str) -> &str {
    if val.len() >= 2 {
        let bytes = val.as_bytes();
        if (bytes[0] == b'"' && bytes[val.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[val.len() - 1] == b'\'')
        {
            return &val[1..val.len() - 1];
        }
    }
    val
}

fn non_empty_env(map: &HashMap<String, String>, key: &str) -> Option<String> {
    map.get(key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_bool_flag(raw: &str) -> bool {
    !matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn next_cli_value<'a>(
    args: &'a [String],
    idx: &mut usize,
    flag: &str,
) -> Result<&'a str, ConfigError> {
    *idx += 1;
    args.get(*idx)
        .map(|s| s.as_str())
        .ok_or_else(|| ConfigError::MissingFlagValue(flag.to_string()))
}

fn detect_default_host_id() -> String {
    if let Ok(raw) = fs::read_to_string("/proc/sys/kernel/hostname") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(raw) = fs::read_to_string("/etc/hostname") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(name) = std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")) {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "unknown-host".to_string()
}

pub struct AgentState {
    cpu_guard: CpuGuardTracker,
    memory_guard: MemoryGuardTracker,
    io_guard: IoGuardTracker,
    prev_cpu: Option<CpuMetrics>,
    prev_container_cpu: HashMap<String, (u64, u64)>,
    prev_host_disks: HashMap<String, (u64, u64, u64, u64, u64)>,
    prev_container_io: HashMap<String, HashMap<String, (u64, u64, u64, u64)>>,
    prev_container_net: HashMap<String, (u64, u64, u64, u64)>,
    last_sample_ts: Option<u64>,
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    conntrack_path: PathBuf,
    cpu_guard_enforcer: CpuGuardEnforcer,
    memory_guard_enforcer: MemoryGuardEnforcer,
    io_guard_enforcer: IoGuardEnforcer,
    geoip_db_path: Option<PathBuf>,
    rfw_restart_observation: Option<RfwRestartObservation>,
    access_log_states: HashMap<String, AccessLogCursor>,
    host_audit_state: host_audit::HostAuditState,
    operations_services: Vec<ServiceProbeSpec>,
    bandwidth_state_path: PathBuf,
    cleanup_journal_path: PathBuf,
    cleanup_policy: app_guard::disk_cleanup::CleanupPolicy,
    disk_cleanup_running: Arc<AtomicBool>,
    disk_cleanup_recovered: bool,
    last_containers: Vec<ContainerSample>,
    last_traffic_samples: Vec<tc_guard::TrafficSampleInput>,
    last_sample_interval_secs: u64,
    abuse_engine: Option<Arc<abuse_guard::SharedAbuseEngine>>,
    #[cfg(unix)]
    admission_controller: Option<
        Arc<
            admission_guard::AdmissionController<
                admission_guard::LiveNftRunner,
                admission_guard::NativeNfqBackend,
            >,
        >,
    >,
    #[cfg(not(unix))]
    admission_controller: Option<Arc<admission_guard::AdmissionController>>,
    #[cfg(unix)]
    admission_init_error: Option<String>,
    pasarguard: protocol_guard::pasarguard::PasarGuardMonitor,
    microburst: protocol_guard::microburst::MicroburstDetector,
    udp_blackhole_auto_states: HashMap<String, (u32, u64)>,
    #[cfg_attr(not(unix), allow(dead_code))]
    speedtest_caches: protocol_guard::speedtest::SpeedtestReconcileCaches,
    #[cfg_attr(not(unix), allow(dead_code))]
    motd_states: Vec<runtime_drivers::JsonVal>,
    #[cfg_attr(not(unix), allow(dead_code))]
    last_alerts_json: String,
    motd_deliveries: HashMap<(String, String, String), MotdDeliveryState>,
    sni_whitelist: Option<Vec<String>>,
    service_audit_enabled: bool,
    disallowed_protocols: Option<Vec<String>>,
    last_bandwidth_reconcile_ts: u64,
    last_bandwidth_revision: i64,
    last_managed_upgrade_check: Option<(u64, bool)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceProbeSpec {
    pub id: String,
    pub kind: String,
    pub target: String,
    pub latency_warning_ms: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AccessLogCursor {
    pub inode: u64,
    pub offset: u64,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct RfwRestartObservation {
    boot_id: String,
    restart_count: u64,
    restart_events: Vec<u64>,
}

fn resolve_default_geoip_db_path() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("GEOIP_MMDB_PATH") {
        let trimmed = env_path.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    for candidate in [
        "/opt/narwhal-monitor/GeoLite2-Country.mmdb",
        "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    ] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

impl AgentState {
    pub fn new(config: &Config) -> Self {
        Self::with_paths(
            config,
            PathBuf::from("/proc"),
            PathBuf::from("/proc/net/nf_conntrack"),
        )
    }

    pub fn with_paths(config: &Config, proc_root: PathBuf, conntrack_path: PathBuf) -> Self {
        let interval = config.report_interval as f64;
        let mut cpu_cfg = CpuGuardConfig {
            interval_seconds: interval,
            ..CpuGuardConfig::default()
        };
        if let Some(v) = std::env::var("CPU_AUTO_LIMIT_SATURATION_PERCENT")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite())
        {
            cpu_cfg.high_threshold_percent = v;
        }
        if let Some(v) = std::env::var("CPU_AUTO_LIMIT_HOST_BUSY_PERCENT")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite())
        {
            cpu_cfg.host_busy_threshold_percent = v;
        }
        if let Some(v) = std::env::var("CPU_AUTO_LIMIT_HOST_PSI_PERCENT")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite())
        {
            cpu_cfg.host_psi_threshold_percent = v;
        }
        if let Some(v) = std::env::var("CPU_AUTO_LIMIT_REQUIRED_SECONDS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
        {
            cpu_cfg.required_duration_seconds = v.max(60);
            cpu_cfg.explicit_required_duration_override = true;
        }
        let mut mem_cfg = MemoryGuardConfig {
            interval_seconds: interval,
            ..MemoryGuardConfig::default()
        };
        if let Some(v) = std::env::var("MEMORY_AUTO_LIMIT_USAGE_PERCENT")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite())
        {
            mem_cfg.start_usage_percent = v;
        }
        if let Some(v) = std::env::var("MEMORY_AUTO_LIMIT_HOST_PSI_PERCENT")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite())
        {
            mem_cfg.host_psi_threshold_percent = v;
        }
        if let Some(v) = std::env::var("MEMORY_AUTO_LIMIT_CGROUP_PSI_PERCENT")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite())
        {
            mem_cfg.container_psi_threshold_percent = v;
        }
        if let Some(v) = std::env::var("MEMORY_AUTO_LIMIT_REQUIRED_SECONDS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
        {
            mem_cfg.required_duration_seconds = v;
        }
        let mut io_cfg = IoGuardConfig {
            interval_seconds: interval,
            ..IoGuardConfig::default()
        };
        if let Some(v) = std::env::var("IO_AUTO_LIMIT_DEVICE_BUSY_PERCENT")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite())
        {
            io_cfg.device_busy_threshold_percent = v;
        }
        if let Some(v) = std::env::var("IO_AUTO_LIMIT_HOST_PSI_PERCENT")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite())
        {
            io_cfg.host_psi_threshold_percent = v;
        }
        if let Some(v) = std::env::var("IO_AUTO_LIMIT_REQUIRED_SECONDS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
        {
            io_cfg.required_duration_seconds = v;
        }
        let geoip_db_path = resolve_default_geoip_db_path();
        let sni_enabled = std::env::var("NARWHAL_SNI_WHITELIST_ENABLED")
            .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off" | "no"))
            .unwrap_or(true);
        #[cfg(unix)]
        let (admission_controller, admission_init_error) =
            match admission_guard::Guard::open_live_unix() {
                Ok(g) => {
                    let cn_lookup = geoip_db_path.clone().map(|p| {
                        let cb: Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync> =
                            Arc::new(move |ip| geoip_probe::is_country_ip(&p, ip, "CN"));
                        cb
                    });
                    g.set_sni_enforcement(sni_enabled, cn_lookup);
                    (
                        Some(Arc::new(admission_guard::AdmissionController::new(g))),
                        None,
                    )
                }
                Err(e) => (None, Some(e.to_string())),
            };
        #[cfg(not(unix))]
        let admission_controller = admission_guard::Guard::open_default().ok().map(|g| {
            let cn_lookup = geoip_db_path.clone().map(|p| {
                let cb: Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync> =
                    Arc::new(move |ip| geoip_probe::is_country_ip(&p, ip, "CN"));
                cb
            });
            g.set_sni_enforcement(sni_enabled, cn_lookup);
            Arc::new(admission_guard::AdmissionController::new(Arc::new(g)))
        });
        Self {
            cpu_guard: CpuGuardTracker::new(cpu_cfg),
            memory_guard: MemoryGuardTracker::new(mem_cfg),
            io_guard: IoGuardTracker::new(io_cfg),
            prev_cpu: None,
            prev_container_cpu: HashMap::new(),
            prev_host_disks: HashMap::new(),
            prev_container_io: HashMap::new(),
            prev_container_net: HashMap::new(),
            last_sample_ts: None,
            proc_root,
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            conntrack_path,
            cpu_guard_enforcer: CpuGuardEnforcer::new(cpu_guard_exec::default_cpu_guard_state_path()),
            memory_guard_enforcer: MemoryGuardEnforcer::new(resource_guard_exec::default_memory_guard_state_path()),
            io_guard_enforcer: IoGuardEnforcer::new(resource_guard_exec::default_io_guard_state_path()),
            geoip_db_path,
            rfw_restart_observation: None,
            access_log_states: HashMap::new(),
            host_audit_state: host_audit::HostAuditState::default(),
            operations_services: Vec::new(),
            bandwidth_state_path: tc_guard::default_state_path(),
            cleanup_journal_path: PathBuf::from(app_guard::disk_cleanup::DEFAULT_STATE_PATH),
            cleanup_policy: app_guard::disk_cleanup::CleanupPolicy::default(),
            disk_cleanup_running: std::sync::Arc::new(AtomicBool::new(false)),
            disk_cleanup_recovered: false,
            last_containers: Vec::new(),
            last_traffic_samples: Vec::new(),
            last_sample_interval_secs: config.report_interval.max(1),
            abuse_engine: abuse_guard::AbuseEngine::with_defaults()
                .ok()
                .map(|e| Arc::new(abuse_guard::SharedAbuseEngine::new(e))),
            #[cfg(unix)]
            admission_controller,
            #[cfg(unix)]
            admission_init_error,
            #[cfg(not(unix))]
            admission_controller,
            pasarguard: protocol_guard::pasarguard::PasarGuardMonitor::new(),
            microburst: protocol_guard::microburst::MicroburstDetector::new(),
            udp_blackhole_auto_states: HashMap::new(),
            speedtest_caches: protocol_guard::speedtest::SpeedtestReconcileCaches::default(),
            motd_states: Vec::new(),
            last_alerts_json: "[]".to_string(),
            motd_deliveries: HashMap::new(),
            sni_whitelist: None,
            service_audit_enabled: true,
            disallowed_protocols: None,
            last_bandwidth_reconcile_ts: 0,
            last_bandwidth_revision: -1,
            last_managed_upgrade_check: None,
        }
    }

    pub fn with_geoip_db(mut self, db_path: Option<PathBuf>) -> Self {
        self.geoip_db_path = db_path.clone();
        if let Some(ref ctrl) = self.admission_controller {
            let sni_enabled = std::env::var("NARWHAL_SNI_WHITELIST_ENABLED")
                .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off" | "no"))
                .unwrap_or(true);
            let cn_lookup = db_path.map(|p| {
                let cb: Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync> =
                    Arc::new(move |ip| geoip_probe::is_country_ip(&p, ip, "CN"));
                cb
            });
        ctrl.guard.set_sni_enforcement(sni_enabled, cn_lookup);
        }
        self
    }

    #[cfg(test)]
    pub(crate) fn with_cgroup_root(mut self, cgroup_root: PathBuf) -> Self {
        self.cgroup_root = cgroup_root;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_cpu_guard_state_path(mut self, state_path: PathBuf) -> Self {
        self.cpu_guard_enforcer = CpuGuardEnforcer::new(state_path);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_memory_guard_state_path(mut self, state_path: PathBuf) -> Self {
        self.memory_guard_enforcer = MemoryGuardEnforcer::new(state_path);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_io_guard_state_path(mut self, state_path: PathBuf) -> Self {
        self.io_guard_enforcer = IoGuardEnforcer::new(state_path);
        self
    }

    pub fn apply_dynamic_security_policy(&mut self, policy: &runtime_drivers::JsonVal) {
        let sni_env_enabled = std::env::var("NARWHAL_SNI_WHITELIST_ENABLED")
            .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off" | "no"))
            .unwrap_or(true);
        let sni_enabled = sni_env_enabled
            && policy
                .get("sni_enforcement")
                .and_then(runtime_drivers::JsonVal::as_bool)
                .unwrap_or(true);
        let block_cn_missing = policy
            .get("block_cn_missing_sni")
            .and_then(runtime_drivers::JsonVal::as_bool)
            .unwrap_or(true);
        let whitelist = policy
            .get("sni_whitelist")
            .and_then(runtime_drivers::JsonVal::as_arr)
            .map(|arr| {
                arr.iter()
                    .filter_map(runtime_drivers::JsonVal::as_str)
                    .filter_map(admission_guard::sni::normalize_sni)
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty());
        self.sni_whitelist = whitelist.clone();
        self.service_audit_enabled = policy
            .get("service_audit_enabled")
            .and_then(runtime_drivers::JsonVal::as_bool)
            .unwrap_or(true);
        self.disallowed_protocols = policy
            .get("disallowed_protocols")
            .and_then(runtime_drivers::JsonVal::as_arr)
            .map(|arr| {
                arr.iter()
                    .filter_map(runtime_drivers::JsonVal::as_str)
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            });
        if let Some(ref ctrl) = self.admission_controller {
            ctrl.guard
                .update_sni_policy(sni_enabled, whitelist, block_cn_missing);
        }
    }

    pub fn lookup_geoip_json(&self, ips: &[String]) -> String {
        match &self.geoip_db_path {
            Some(path) => lookup_countries(path, ips),
            None => "{\"available\":false,\"results\":{}}".to_string(),
        }
    }

    pub fn validate_probe_target(host: &str) -> bool {
        is_allowed_host(host)
    }

    /// Build the exact `/api/v1/report` JSON payload using in-process Rust probes and guard state machines.
    pub fn build_report_json(&mut self, config: &Config, timestamp: u64) -> String {
        let containers = discover_and_sample_containers(&config.container_runtimes);
        self.build_report_json_with_containers(config, timestamp, &containers)
    }

    fn build_report_json_with_containers(
        &mut self,
        config: &Config,
        timestamp: u64,
        containers: &[ContainerSample],
    ) -> String {
        let dt = self.last_sample_ts.and_then(|prev| {
            if timestamp > prev {
                Some((timestamp - prev) as f64)
            } else {
                None
            }
        });
        let interval_secs = dt.unwrap_or(config.report_interval as f64);
        self.last_sample_ts = Some(timestamp);

        let host_metrics_json = collect_host_metrics(&self.proc_root);
        let psi_snapshot_json = collect_psi_snapshot(&self.proc_root, None);
        let conntrack_json =
            collect_conntrack(&self.conntrack_path.to_string_lossy(), 50_000);
        let proc_snapshot_json =
            collect_host_proc_snapshot_from_root(&self.proc_root, 20_000, 100.0);

        let host_cpu_sample = self.sample_host_cpu();
        let host_mem_psi = read_psi_sample(&self.proc_root.join("pressure").join("memory"));
        let host_io_psi = read_psi_sample(&self.proc_root.join("pressure").join("io"))
            .effective_avg();
        let host_devices = self.sample_host_disks(dt);

        let (mem_samples, cpu_samples, mut metrics_by_key) =
            extract_container_guard_samples_and_metrics(
                &mut self.prev_container_cpu,
                containers,
                timestamp,
                host_cpu_sample.logical_cpus,
                Some((&self.proc_root, &self.cgroup_root)),
            );
        let io_samples = self.extract_container_io_samples(containers, dt);
        let ((total_rx_bps, total_tx_bps, total_rx_pps, total_tx_pps), per_container_net) =
            self.compute_container_net_rates_with_per_container(containers, dt);
        for (key, (rx_bps, tx_bps)) in per_container_net {
            if let Some(m) = metrics_by_key.get_mut(&key) {
                m.net_rx_bps = rx_bps;
                m.net_tx_bps = tx_bps;
            }
        }

        let allow_new_limits = config.security_monitor_enabled;
        let allow_cpu_limits = allow_new_limits && cpu_guard_exec::cpu_auto_limit_enabled_from_env();
        let allow_mem_limits =
            allow_new_limits && resource_guard_exec::memory_auto_limit_enabled_from_env();
        let allow_io_limits =
            allow_new_limits && resource_guard_exec::io_auto_limit_enabled_from_env();

        let cpu_out = self
            .cpu_guard
            .observe(timestamp, &host_cpu_sample, &cpu_samples, allow_cpu_limits);
        self.cpu_guard_enforcer.execute_actions(
            containers,
            &cpu_out.actions,
            &self.proc_root,
            &self.cgroup_root,
            timestamp,
        );
        let (mem_decisions, mem_actions) = self.memory_guard.observe(
            timestamp,
            host_mem_psi,
            &mem_samples,
            allow_mem_limits,
        );
        self.memory_guard_enforcer.execute_actions(
            containers,
            &mem_actions,
            &self.proc_root,
            &self.cgroup_root,
            timestamp,
        );
        let (io_decisions, io_actions) = self.io_guard.observe(
            timestamp,
            host_cpu_sample.ready,
            &host_devices,
            host_io_psi,
            &io_samples,
            allow_io_limits,
        );
        self.io_guard_enforcer.execute_actions(
            containers,
            &io_actions,
            &self.proc_root,
            &self.cgroup_root,
            timestamp,
        );

        let cpu_cfg = self.cpu_guard.config().clone();
        let (cpu_guard_status_by_key, cpu_guard_alerts) = self
            .cpu_guard_enforcer
            .build_container_cpu_guard_status_and_alerts(
                containers,
                &metrics_by_key,
                &cpu_out.decisions,
                &host_cpu_sample,
                cpu_cfg.high_threshold_percent,
                cpu_cfg.host_busy_threshold_percent,
                cpu_cfg.host_psi_threshold_percent,
                &self.proc_root,
                timestamp,
            );
        let (mem_guard_status_by_key, mem_guard_alerts) = self
            .memory_guard_enforcer
            .build_status_and_alerts(
                containers,
                &metrics_by_key,
                &mem_decisions,
                host_mem_psi.avg10,
            );
        let (io_guard_status_by_key, io_guard_alerts) = self
            .io_guard_enforcer
            .build_status_and_alerts(containers, &io_decisions, host_io_psi);

        let (containers_json, container_alerts_base_json) =
            self.build_container_telemetry_and_alerts_with_guards(
                config,
                containers,
                timestamp,
                &metrics_by_key,
                &cpu_guard_status_by_key,
                &mem_guard_status_by_key,
                &io_guard_status_by_key,
            );
        let cpu_guard_alerts_json = format!("[{}]", cpu_guard_alerts.join(","));
        let mem_guard_alerts_json = format!("[{}]", mem_guard_alerts.join(","));
        let io_guard_alerts_json = format!("[{}]", io_guard_alerts.join(","));
        let container_alerts_json = merge_json_arrays(
            &merge_json_arrays(&container_alerts_base_json, &cpu_guard_alerts_json),
            &merge_json_arrays(&mem_guard_alerts_json, &io_guard_alerts_json),
        );

        let effective_interval = interval_secs.max(1.0);
        let access_stats = collect_access_log_stats(
            &config.security_access_log_paths,
            config.security_access_log_max_bytes,
            &config.security_web_scan_patterns,
            effective_interval,
            &mut self.access_log_states,
        );
        let access_log_json = access_stats.to_json();
        let access_sources_json = access_stats.to_sources_json();
        let suspicious_findings = if config.security_monitor_enabled {
            let proc_infos = extract_proc_infos_from_snapshot(&proc_snapshot_json);
            detect_suspicious_processes(&proc_infos)
        } else {
            Vec::new()
        };
        let suspicious_json = serialize_suspicious_findings_json(&suspicious_findings);
        let socket_abuse_input = aggregate_socket_abuse_from_containers(containers, timestamp);
        let socket_verdict = evaluate_socket_abuse(&socket_abuse_input);
        let socket_abuse_json = socket_verdict.to_json();
        let security_alerts_base = build_security_alerts_json(&socket_verdict, &suspicious_findings);
        let security_alerts_with_containers =
            merge_json_arrays(&security_alerts_base, &container_alerts_json);
        let incus_report = collect_incus_runtime_health(config, timestamp);
        let sni_alerts_json = if let Some(ref ctrl) = self.admission_controller {
            let violations = ctrl.guard.drain_sni_violations();
            if violations.is_empty() {
                "[]".to_string()
            } else {
                let items: Vec<String> = violations
                    .into_iter()
                    .map(|v| {
                        let proto_name = if v.proto == 17 { "quic" } else { "tls" };
                        let sni_field = v
                            .sni
                            .as_deref()
                            .map(|s| format!(",\"sni\":\"{}\"", json_escape(s)))
                            .unwrap_or_default();
                        let msg = if v.reason == "missing_or_invalid_sni_cn" || v.sni.is_none() {
                            format!(
                                "检测到来自 CN 方向的入站 {}/{} 握手未携带有效 SNI，已阻断连接。请使用平台允许的 9 个白名单 SNI 之一。",
                                proto_name.to_ascii_uppercase(),
                                v.dst_port
                            )
                        } else {
                            format!(
                                "检测到容器入站 {}/{} 携带非白名单 SNI（{}），已阻断连接。请改用平台允许的 9 个白名单 SNI 之一。",
                                proto_name.to_ascii_uppercase(),
                                v.dst_port,
                                v.sni.as_deref().unwrap_or("")
                            )
                        };
                        format!(
                            "{{\"type\":\"sni_whitelist_violation\",\"runtime\":\"{}\",\"project\":\"{}\",\"container_name\":\"{}\",\"instance_id\":\"{}\",\"severity\":\"warning\",\"title\":\"容器入站 SNI 不在白名单，已阻断\",\"message\":\"{}\",\"dst_port\":{},\"proto\":\"{}\",\"reason\":\"{}\",\"action\":\"blocked\"{}}}",
                            json_escape(&v.runtime),
                            json_escape(&v.project),
                            json_escape(&v.container_name),
                            json_escape(&v.instance_id),
                            json_escape(&msg),
                            v.dst_port,
                            proto_name,
                            json_escape(&v.reason),
                            sni_field
                        )
                    })
                    .collect();
                format!("[{}]", items.join(","))
            }
        } else {
            "[]".to_string()
        };
        let security_alerts_with_sni =
            merge_json_arrays(&security_alerts_with_containers, &sni_alerts_json);
        let security_alerts_json = match incus_report.as_ref() {
            Some(incus) => merge_json_arrays(&security_alerts_with_sni, &incus.alerts_json),
            None => security_alerts_with_sni,
        };
        self.last_alerts_json = security_alerts_json.clone();
        let rfw_service_health_json = self.collect_rfw_service_health_json(timestamp);
        let ipv4_ok = host_ip_family_available(false);
        let ipv6_ok = host_ip_family_available(true);
        let (runtime_inventory_json, runtime_empty) = detect_runtime_inventory_with_empty(containers);
        let ops_health_base = build_operations_health_json(
            config.security_monitor_enabled,
            runtime_empty,
            containers.len(),
            &access_stats,
        );
        let (ops_health_json, ops_capabilities_json, incus_runtime_field) = match incus_report {
            Some(incus) => (
                append_json_object_to_array(&ops_health_base, &incus.operations_health_json),
                "[\"operations-v1\",\"agent-rust-v2\",\"service-probes\",\"log-discovery\",\"public-tcp-v2\",\"incus-runtime-health-v1\"]",
                format!(",\"incus_runtime\":{}", incus.snapshot_json),
            ),
            None => (
                ops_health_base,
                "[\"operations-v1\",\"agent-rust-v2\",\"service-probes\",\"log-discovery\",\"public-tcp-v2\"]",
                String::new(),
            ),
        };
        let ops_arch = normalize_arch(std::env::consts::ARCH);
        let upgrade_result_json = read_managed_upgrade_result_json(Path::new(MANAGED_UPDATE_RESULT_FILE));
        let managed_upgrade = match self.last_managed_upgrade_check {
            Some((prev_ts, cached)) if timestamp.saturating_sub(prev_ts) < 60 => cached,
            _ => {
                let avail = managed_upgrade_available(Path::new("/opt/narwhal-monitor"));
                self.last_managed_upgrade_check = Some((timestamp, avail));
                avail
            }
        };
        let auto_update_json = collect_auto_update_status_json(Path::new("/opt/narwhal-monitor"));
        let ops_services_json = probe_operations_services_json(&self.operations_services, timestamp);
        let ops_disk_cleanup_json = self.build_disk_cleanup_summary_json(timestamp);
        let manual_bw_json = tc_guard::last_status_json(&self.bandwidth_state_path);
        self.last_containers = containers.to_vec();

        let agent_ver = resolved_agent_version();
        let host_fw_json =
            host_audit::collect_host_firewall_full_json(timestamp, containers, &mut self.host_audit_state);
        let host_audit_json = if config.security_monitor_enabled {
            host_audit::collect_host_audit_json(
                timestamp,
                self.geoip_db_path.is_some(),
                &mut self.host_audit_state,
            )
        } else {
            "{\"enabled\":false}".to_string()
        };
        let mut out = String::with_capacity(8192);
        let _ = write!(
            out,
            "{{\"host_id\":\"{}\",\"node_id\":\"{}\",\"client_config\":{{\"host_id\":\"{}\",\"report_interval\":{},\"action_poll_interval\":{},\"container_runtimes\":\"{}\",\"docker_monitor_mode\":\"{}\",\"incus_project\":\"{}\",\"security_monitor_enabled\":{}}},\"agent_version\":\"{}\",\"timestamp\":{},\"container_network\":{{\"ipv4_ok\":{},\"ipv6_ok\":{}}},\"podman_network\":{{\"ipv4_ok\":{},\"ipv6_ok\":{}}},\"containers\":{},\"security\":{{\"enabled\":{},\"interval_seconds\":{:.3},\"total_rx_bps\":{:.3},\"total_tx_bps\":{:.3},\"total_rx_pps\":{:.3},\"total_tx_pps\":{:.3},\"syn_recv_count\":{},\"access_log\":{},\"access_sources\":{},\"alerts\":{},\"suspicious_processes\":{},\"socket_abuse\":{},\"rfw_service_health\":{},\"host_firewall\":{},\"host_audit\":{},\"manual_bandwidth_limits\":{}{},\"conntrack\":{},\"psi_snapshot\":{},\"cpu_guard\":{{\"multi_container_contention\":{},\"decisions\":{},\"actions\":{}}},\"memory_guard\":{{\"decisions\":{},\"actions\":{}}},\"io_guard\":{{\"decisions\":{},\"actions\":{}}}}},\"operations\":{{\"host_metrics\":{},\"psi_snapshot\":{},\"proc_snapshot\":{},\"health\":{},\"runtime_inventory\":{},\"services\":{},\"disk_cleanup\":{},\"architecture\":\"{}\",\"interval_seconds\":{:.3},\"upgrade_result\":{},\"managed_upgrade\":{},\"auto_update\":{},\"capabilities\":{},\"schema_version\":1,\"guard_actions\":{{\"cpu\":{},\"memory\":{},\"io\":{}}}}}}}",
            json_escape(&config.host_id),
            json_escape(&config.node_id),
            json_escape(&config.host_id),
            config.report_interval,
            config.action_poll_interval,
            json_escape(&config.container_runtimes),
            json_escape(&config.docker_monitor_mode),
            json_escape(&config.incus_project),
            config.security_monitor_enabled,
            json_escape(&agent_ver),
            timestamp,
            ipv4_ok,
            ipv6_ok,
            ipv4_ok,
            ipv6_ok,
            containers_json,
            config.security_monitor_enabled,
            effective_interval,
            total_rx_bps,
            total_tx_bps,
            total_rx_pps,
            total_tx_pps,
            socket_abuse_input.tcp_syn_recv,
            access_log_json,
            access_sources_json,
            security_alerts_json,
            suspicious_json,
            socket_abuse_json,
            rfw_service_health_json,
            host_fw_json,
            host_audit_json,
            manual_bw_json,
            incus_runtime_field,
            conntrack_json,
            psi_snapshot_json,
            cpu_out.multi_container_contention,
            cpu_out.decisions.len(),
            cpu_out.actions.len(),
            mem_decisions.len(),
            mem_actions.len(),
            io_decisions.len(),
            io_actions.len(),
            host_metrics_json,
            psi_snapshot_json,
            proc_snapshot_json,
            ops_health_json,
            runtime_inventory_json,
            ops_services_json,
            ops_disk_cleanup_json,
            json_escape(ops_arch),
            effective_interval,
            upgrade_result_json,
            managed_upgrade,
            auto_update_json,
            ops_capabilities_json,
            cpu_out.actions.len(),
            mem_actions.len(),
            io_actions.len(),
        );
        out
    }

    fn collect_rfw_service_health_json(&mut self, timestamp: u64) -> String {
        collect_rfw_service_health_json(
            &self.proc_root,
            timestamp,
            &mut self.rfw_restart_observation,
        )
    }

    fn sample_host_cpu(&mut self) -> HostCpuSample {
        let stat_raw = fs::read_to_string(self.proc_root.join("stat")).ok();
        let current_cpu = stat_raw.as_deref().and_then(parse_proc_stat_cpu);
        let load_1m = fs::read_to_string(self.proc_root.join("loadavg"))
            .ok()
            .and_then(|raw| parse_loadavg(&raw))
            .map(|l| l.m1);
        let cpu_psi = read_psi_sample(&self.proc_root.join("pressure").join("cpu")).avg10;

        let (ready, busy_percent) = match (self.prev_cpu.as_ref(), current_cpu.as_ref()) {
            (Some(prev), Some(curr)) => {
                let total_delta = curr.total.saturating_sub(prev.total);
                let busy_delta = curr.busy.saturating_sub(prev.busy);
                if total_delta > 0 {
                    (true, (busy_delta as f64 / total_delta as f64) * 100.0)
                } else {
                    (false, 0.0)
                }
            }
            (None, Some(_)) => (false, 0.0),
            _ => (false, 0.0),
        };
        if let Some(curr) = current_cpu {
            self.prev_cpu = Some(curr);
        }

        let logical_cpus = thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1)
            .max(1);

        HostCpuSample {
            ready,
            busy_percent,
            logical_cpus,
            load_1m,
            psi_some_avg10: cpu_psi,
        }
    }

    fn sample_host_disks(&mut self, dt: Option<f64>) -> Vec<HostDeviceSample> {
        let raw = collect_diskstats(&self.proc_root);
        let Ok(root) = actions::parse_json(&raw) else {
            self.prev_host_disks.clear();
            return Vec::new();
        };
        if root.get("available").and_then(|v| v.as_bool()) != Some(true) {
            self.prev_host_disks.clear();
            return Vec::new();
        }
        let Some(devices) = root.get("devices").and_then(|v| v.as_object()) else {
            self.prev_host_disks.clear();
            return Vec::new();
        };

        let mut samples = Vec::new();
        let mut next_disks = HashMap::with_capacity(devices.len());
        for (dev, val) in devices {
            let rios = val.get("rios").and_then(|v| v.as_u64()).unwrap_or(0);
            let rsectors = val.get("rsectors").and_then(|v| v.as_u64()).unwrap_or(0);
            let wios = val.get("wios").and_then(|v| v.as_u64()).unwrap_or(0);
            let wsectors = val.get("wsectors").and_then(|v| v.as_u64()).unwrap_or(0);
            let busy_ms = val.get("busy_ms").and_then(|v| v.as_u64()).unwrap_or(0);

            if let Some(dt_secs) = dt.filter(|d| *d > 0.0) {
                if let Some(&(p_rios, p_rsec, p_wios, p_wsec, p_busy)) =
                    self.prev_host_disks.get(dev)
                {
                    let d_rios = rios.saturating_sub(p_rios);
                    let d_rsec = rsectors.saturating_sub(p_rsec);
                    let d_wios = wios.saturating_sub(p_wios);
                    let d_wsec = wsectors.saturating_sub(p_wsec);
                    let d_busy = busy_ms.saturating_sub(p_busy);
                    let read_bps = (d_rsec as f64 * 512.0) / dt_secs;
                    let write_bps = (d_wsec as f64 * 512.0) / dt_secs;
                    let total_iops = d_rios.saturating_add(d_wios) as f64 / dt_secs;
                    let busy_percent =
                        ((d_busy as f64 / (dt_secs * 1000.0)) * 100.0).clamp(0.0, 100.0);
                    samples.push(HostDeviceSample {
                        device: dev.clone(),
                        busy_percent,
                        total_bps: read_bps + write_bps,
                        total_iops,
                    });
                }
            }
            next_disks.insert(dev.clone(), (rios, rsectors, wios, wsectors, busy_ms));
        }
        self.prev_host_disks = next_disks;
        samples
    }

    fn extract_container_io_samples(
        &mut self,
        containers: &[ContainerSample],
        dt: Option<f64>,
    ) -> Vec<IoContainerSample> {
        let mut samples = Vec::new();
        let mut next_io: HashMap<String, HashMap<String, (u64, u64, u64, u64)>> =
            HashMap::with_capacity(containers.len());

        for c in containers {
            let key = container_guard_key(c);
            if key.is_empty() {
                continue;
            }
            let Some(cg_val) = c
                .cgroup_metrics_json
                .as_deref()
                .and_then(|s| actions::parse_json(s).ok())
            else {
                continue;
            };
            let Some(devices) = cg_val
                .get("io")
                .and_then(|io| io.get("devices"))
                .and_then(|d| d.as_array())
            else {
                continue;
            };

            let prev_devs = self.prev_container_io.get(&key);
            let mut next_devs = HashMap::with_capacity(devices.len());
            let mut device_rates = Vec::new();

            for item in devices {
                let Some(dev) = item
                    .get("dev")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                else {
                    continue;
                };
                let rbytes = item.get("rbytes").and_then(|v| v.as_u64()).unwrap_or(0);
                let wbytes = item.get("wbytes").and_then(|v| v.as_u64()).unwrap_or(0);
                let rios = item.get("rios").and_then(|v| v.as_u64()).unwrap_or(0);
                let wios = item.get("wios").and_then(|v| v.as_u64()).unwrap_or(0);

                if let Some(dt_secs) = dt.filter(|d| *d > 0.0) {
                    if let Some(&(p_rb, p_wb, p_ri, p_wi)) = prev_devs.and_then(|m| m.get(dev)) {
                        device_rates.push((
                            dev.to_string(),
                            IoRates {
                                rbps: rbytes.saturating_sub(p_rb) as f64 / dt_secs,
                                wbps: wbytes.saturating_sub(p_wb) as f64 / dt_secs,
                                riops: rios.saturating_sub(p_ri) as f64 / dt_secs,
                                wiops: wios.saturating_sub(p_wi) as f64 / dt_secs,
                            },
                        ));
                    }
                }
                next_devs.insert(dev.to_string(), (rbytes, wbytes, rios, wios));
            }

            if !device_rates.is_empty() {
                let original_limits = resource_guard_exec::read_container_io_max_map(
                    &self.proc_root,
                    &self.cgroup_root,
                    c,
                );
                samples.push(IoContainerSample {
                    key: key.clone(),
                    device_rates,
                    original_limits,
                });
            }
            next_io.insert(key, next_devs);
        }

        self.prev_container_io = next_io;
        samples
    }

    fn compute_container_net_rates(
        &mut self,
        containers: &[ContainerSample],
        dt: Option<f64>,
    ) -> (f64, f64, f64, f64) {
        self.compute_container_net_rates_with_per_container(containers, dt).0
    }

    fn compute_container_net_rates_with_per_container(
        &mut self,
        containers: &[ContainerSample],
        dt: Option<f64>,
    ) -> ((f64, f64, f64, f64), HashMap<String, (f64, f64)>) {
        let mut total_rx_bps = 0.0;
        let mut total_tx_bps = 0.0;
        let mut total_rx_pps = 0.0;
        let mut total_tx_pps = 0.0;
        let mut next_net: HashMap<String, (u64, u64, u64, u64)> =
            HashMap::with_capacity(containers.len());
        let mut per_container_rates: HashMap<String, (f64, f64)> =
            HashMap::with_capacity(containers.len());
        let mut traffic_samples = Vec::with_capacity(containers.len());

        for c in containers {
            let key = container_guard_key(c);
            if key.is_empty() {
                continue;
            }
            let Some(pm_val) = c
                .pid_metrics_json
                .as_deref()
                .and_then(|s| actions::parse_json(s).ok())
            else {
                continue;
            };
            let Some(net) = pm_val.get("net") else {
                continue;
            };
            let rx_bytes = net.get("rx_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
            let tx_bytes = net.get("tx_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
            let rx_packets = net.get("rx_packets").and_then(|v| v.as_u64()).unwrap_or(0);
            let tx_packets = net.get("tx_packets").and_then(|v| v.as_u64()).unwrap_or(0);

            let mut net_rx_bps = None;
            let mut net_tx_bps = None;
            if let Some(dt_secs) = dt.filter(|d| *d > 0.0) {
                if let Some(&(p_rb, p_tb, p_rp, p_tp)) = self.prev_container_net.get(&key) {
                    let c_rx_bps = rx_bytes.saturating_sub(p_rb) as f64 / dt_secs;
                    let c_tx_bps = tx_bytes.saturating_sub(p_tb) as f64 / dt_secs;
                    total_rx_bps += c_rx_bps;
                    total_tx_bps += c_tx_bps;
                    total_rx_pps += rx_packets.saturating_sub(p_rp) as f64 / dt_secs;
                    total_tx_pps += tx_packets.saturating_sub(p_tp) as f64 / dt_secs;
                    net_rx_bps = Some(c_rx_bps);
                    net_tx_bps = Some(c_tx_bps);
                    per_container_rates.insert(key.clone(), (c_rx_bps, c_tx_bps));
                }
            }
            traffic_samples.push(tc_guard::TrafficSampleInput {
                runtime: c.runtime.clone(),
                project: c.project.clone(),
                container_name: c.name.clone(),
                container_id: if c.runtime == "runman" {
                    c.instance_id.clone()
                } else {
                    c.id.clone()
                },
                traffic_counters_available: net_rx_bps.is_some() && net_tx_bps.is_some(),
                net_tx_bps,
                net_rx_bps,
            });
            next_net.insert(key, (rx_bytes, tx_bytes, rx_packets, tx_packets));
        }

        self.prev_container_net = next_net;
        self.last_traffic_samples = traffic_samples;
        if let Some(dt_secs) = dt.filter(|d| *d > 0.0) {
            self.last_sample_interval_secs = dt_secs.round().max(1.0) as u64;
        }
        ((total_rx_bps, total_tx_bps, total_rx_pps, total_tx_pps), per_container_rates)
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn agent_container_scope(proc_root: &Path) -> bool {
    if Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists() {
        return true;
    }
    if fs::read_to_string("/run/systemd/container")
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "docker" | "podman" | "lxc" | "incus" | "systemd-nspawn" | "openvz"
            )
        })
        .unwrap_or(false)
    {
        return true;
    }
    for path in [proc_root.join("self/cgroup"), proc_root.join("1/cgroup")] {
        if let Ok(raw) = fs::read_to_string(path) {
            let lower = raw.to_ascii_lowercase();
            if ["/docker-", "/libpod-", "/kubepods", "/lxc/", "/incus/"]
                .iter()
                .any(|marker| lower.contains(marker))
            {
                return true;
            }
        }
    }
    for path in [proc_root.join("self/mountinfo"), proc_root.join("1/mountinfo")] {
        if let Ok(raw) = fs::read_to_string(path) {
            let lower = raw.to_ascii_lowercase();
            if lower.contains("/var/lib/incus/containers/")
                || lower.contains("/var/lib/lxc/containers/")
            {
                return true;
            }
        }
    }
    false
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn systemd_rfw_properties() -> Result<String, &'static str> {
    let mut child = Command::new("systemctl")
        .args([
            "show",
            "rfw.service",
            "--no-pager",
            "--property=LoadState,ActiveState,SubState,NRestarts,ActiveEnterTimestampMonotonic",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "systemd_unavailable")?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err("systemd_unavailable");
                }
                let output = child
                    .wait_with_output()
                    .map_err(|_| "systemd_unavailable")?;
                return String::from_utf8(output.stdout).map_err(|_| "systemd_output_invalid");
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("systemd_timeout");
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("systemd_unavailable");
            }
        }
    }
}

fn collect_rfw_service_health_json(
    proc_root: &Path,
    timestamp: u64,
    observation: &mut Option<RfwRestartObservation>,
) -> String {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (proc_root, observation);
        format!(
            "{{\"status\":\"not_applicable\",\"checked_at\":{},\"reason\":\"platform_unsupported\"}}",
            timestamp
        )
    }

    #[cfg(target_os = "linux")]
    {
        let base = |status: &str, reason: &str| {
            format!(
                "{{\"status\":\"{}\",\"checked_at\":{},\"reason\":\"{}\"}}",
                status, timestamp, reason
            )
        };
        if agent_container_scope(proc_root) {
            return base("not_applicable", "agent_container");
        }
        let raw = match systemd_rfw_properties() {
            Ok(value) => value,
            Err(reason) => return base("unavailable", reason),
        };
        let mut load_state = "";
        let mut active_state = "";
        let mut sub_state = "";
        let mut restart_count = 0u64;
        let mut active_enter_us = 0u64;
        for line in raw.lines() {
            if let Some((key, value)) = line.split_once('=') {
                match key {
                    "LoadState" => load_state = value.trim(),
                    "ActiveState" => active_state = value.trim(),
                    "SubState" => sub_state = value.trim(),
                    "NRestarts" => restart_count = value.trim().parse().unwrap_or(0),
                    "ActiveEnterTimestampMonotonic" => {
                        active_enter_us = value.trim().parse().unwrap_or(0)
                    }
                    _ => {}
                }
            }
        }
        if load_state == "not-found" {
            return base("not_installed", "unit_not_found");
        }
        if load_state.is_empty() || active_state.is_empty() || sub_state.is_empty() {
            return base("unavailable", "systemd_properties_unavailable");
        }

        let boot_id = fs::read_to_string(proc_root.join("sys/kernel/random/boot_id"))
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let same_boot = !boot_id.is_empty()
            && observation
                .as_ref()
                .map(|previous| previous.boot_id == boot_id)
                .unwrap_or(false);
        let mut restart_events = observation
            .as_ref()
            .filter(|previous| same_boot)
            .map(|previous| previous.restart_events.clone())
            .unwrap_or_default();
        restart_events.retain(|event| timestamp.saturating_sub(*event) <= 300);
        if let Some(previous) = observation.as_ref().filter(|_| same_boot) {
            if restart_count >= previous.restart_count {
                let new_restarts = restart_count.saturating_sub(previous.restart_count).min(32);
                restart_events.extend(std::iter::repeat(timestamp).take(new_restarts as usize));
            } else {
                restart_events.clear();
            }
        } else {
            restart_events.clear();
        }
        if restart_events.len() > 32 {
            let excess = restart_events.len() - 32;
            restart_events.drain(..excess);
        }
        *observation = Some(RfwRestartObservation {
            boot_id,
            restart_count,
            restart_events: restart_events.clone(),
        });

        let active_seconds = if active_enter_us > 0 {
            fs::read_to_string(proc_root.join("uptime"))
                .ok()
                .and_then(|raw| raw.split_whitespace().next()?.parse::<f64>().ok())
                .map(|uptime| uptime.max(0.0) as u64)
                .map(|uptime| uptime.saturating_sub(active_enter_us / 1_000_000))
        } else {
            None
        };
        let (status, reason) = if matches!(active_state, "inactive" | "failed" | "deactivating") {
            ("stopped", "service_not_active")
        } else if active_state == "activating" && sub_state == "auto-restart" {
            ("restart_loop", "systemd_auto_restart")
        } else if active_state == "active" {
            if restart_events.len() >= 3
                || (restart_count >= 3 && active_seconds.map(|age| age <= 180).unwrap_or(false))
            {
                ("restart_loop", "repeated_restarts")
            } else {
                ("healthy", "service_active")
            }
        } else {
            ("unknown", "transitional_service_state")
        };
        let active_seconds_json = active_seconds
            .map(|value| value.to_string())
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"status\":\"{}\",\"checked_at\":{},\"active_state\":\"{}\",\"sub_state\":\"{}\",\"restart_count\":{},\"restarts_5m\":{},\"active_seconds\":{},\"reason\":\"{}\"}}",
            status,
            timestamp,
            json_escape(active_state),
            json_escape(sub_state),
            restart_count,
            restart_events.len(),
            active_seconds_json,
            reason
        )
    }
}

pub fn command_in_path(name: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path_var).any(|dir| {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return true;
        }
        #[cfg(windows)]
        {
            if dir.join(format!("{name}.exe")).is_file() {
                return true;
            }
        }
        false
    })
}

pub fn managed_upgrade_available(base_dir: &Path) -> bool {
    managed_upgrade_available_with_cmd_check(base_dir, command_in_path)
}

pub fn managed_upgrade_available_with_cmd_check<F>(base_dir: &Path, has_cmd: F) -> bool
where
    F: Fn(&str) -> bool,
{
    let script = base_dir.join("managed-client-update.sh");
    let config = base_dir.join("client-auto-update.env");
    if !script.is_file() || !has_cmd("systemd-run") || !config.is_file() {
        return false;
    }
    let Ok(raw_env) = fs::read_to_string(&config) else {
        return false;
    };
    let mut mode = String::from("git");
    let mut repo_value = String::new();
    for line in raw_env.lines() {
        let trimmed = line.trim();
        if let Some(v) = trimmed.strip_prefix("AUTO_UPDATE_MODE=") {
            mode = v.trim().trim_matches('"').trim_matches('\'').to_string();
        } else if let Some(v) = trimmed.strip_prefix("AUTO_UPDATE_REPO_DIR=") {
            repo_value = v.trim().trim_matches('"').trim_matches('\'').to_string();
        }
    }
    if mode == "archive" {
        return base_dir.join("update_archive.py").is_file() && has_cmd("python3");
    }
    if mode != "git" || !has_cmd("git") {
        return false;
    }
    let repo = Path::new(&repo_value);
    if !repo.is_absolute() || !repo.join(".git").is_dir() {
        return false;
    }
    let Ok(dirty) = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["status", "--porcelain"])
        .output()
    else {
        return false;
    };
    if !dirty.status.success() || !String::from_utf8_lossy(&dirty.stdout).trim().is_empty() {
        return false;
    }
    let Ok(origin) = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["remote", "get-url", "origin"])
        .output()
    else {
        return false;
    };
    origin.status.success()
        && String::from_utf8_lossy(&origin.stdout).trim()
            == "https://github.com/podcctv/Narwhal-Cloud-podman-watcher.git"
}

pub fn collect_auto_update_status_json(base_dir: &Path) -> String {
    let mut enabled = true;
    let mut mode = String::new();
    if let Ok(raw_env) = fs::read_to_string(base_dir.join("client-auto-update.env")) {
        for line in raw_env.lines() {
            let trimmed = line.trim();
            if let Some(v) = trimmed.strip_prefix("AUTO_UPDATE_ENABLED=") {
                enabled = v.trim().trim_matches('"') == "true";
            } else if let Some(v) = trimmed.strip_prefix("AUTO_UPDATE_MODE=") {
                mode = v.trim().trim_matches('"').to_string();
            }
        }
    }
    let deployed_commit = fs::read_to_string(base_dir.join("client-auto-update.version"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let mut last_line = String::new();
    let mut last_error = String::new();
    if let Ok(raw_log) = fs::read_to_string(base_dir.join("client-auto-update.log")) {
        let tail: Vec<&str> = raw_log
            .lines()
            .rev()
            .filter(|l| !l.trim().is_empty())
            .take(10)
            .collect();
        if let Some(first) = tail.first() {
            last_line = first.chars().take(240).collect();
        }
        if let Some(err) = tail.into_iter().find(|l| l.contains("ERROR ")) {
            last_error = err.chars().take(240).collect();
        }
    }
    let has_error = !last_error.is_empty() && last_line.contains("ERROR ");
    format!(
        "{{\"enabled\":{},\"mode\":\"{}\",\"deployed_commit\":\"{}\",\"has_error\":{},\"last_line\":\"{}\",\"last_error\":\"{}\"}}",
        enabled,
        json_escape(&mode),
        json_escape(&deployed_commit),
        has_error,
        json_escape(&last_line),
        json_escape(&last_error),
    )
}

fn serialize_containers_with_security_json(
    containers: &[ContainerSample],
    security_jsons: &[String],
    metrics_by_key: &HashMap<String, ContainerMetricsSummary>,
) -> String {
    if containers.is_empty() {
        return "[]".to_string();
    }
    let mut out = String::from("[");
    for (idx, c) in containers.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let pid_str = c
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "null".to_string());
        let mut addrs_json = String::from("[");
        for (a_idx, addr) in c.network_addresses.iter().enumerate() {
            if a_idx > 0 {
                addrs_json.push(',');
            }
            let _ = write!(addrs_json, "\"{}\"", json_escape(addr));
        }
        addrs_json.push(']');

        let key = container_guard_key(c);
        let m = metrics_by_key.get(&key).cloned().unwrap_or_default();

        let _ = write!(
            out,
            "{{\"id\":\"{}\",\"stable_id\":\"{}\",\"name\":\"{}\",\"image\":\"{}\",\"runtime\":\"{}\",\"runtime_bin\":\"{}\",\"project\":\"{}\",\"pid\":{},\"status\":\"{}\",\"instance_id\":\"{}\",\"network_addresses\":{},\"cpu_percent\":{:.2},\"cpu_effective_cpus\":{:.3},\"mem_bytes\":{},\"mem_limit_bytes\":{},\"mem_percent\":{:.2},\"net_rx_bps\":{:.2},\"net_tx_bps\":{:.2},\"conn_count\":{}",
            json_escape(&c.id),
            json_escape(&c.stable_id),
            json_escape(&c.name),
            json_escape(&c.image),
            json_escape(&c.runtime),
            json_escape(&c.runtime_bin),
            json_escape(&c.project),
            pid_str,
            json_escape(&c.status),
            json_escape(&c.instance_id),
            addrs_json,
            m.cpu_percent,
            m.cpu_effective_cpus,
            m.mem_bytes,
            m.mem_limit_bytes,
            m.mem_percent,
            m.net_rx_bps,
            m.net_tx_bps,
            m.conn_count,
        );
        if let Some(ref pid_metrics) = c.pid_metrics_json {
            let _ = write!(out, ",\"pid_metrics\":{pid_metrics}");
        }
        if let Some(ref socket_tables) = c.socket_tables_json {
            let _ = write!(out, ",\"socket_tables\":{socket_tables}");
        }
        if let Some(ref cgroup_metrics) = c.cgroup_metrics_json {
            let _ = write!(out, ",\"cgroup_metrics\":{cgroup_metrics}");
        }
        if let Some(sec_json) = security_jsons.get(idx) {
            if !sec_json.is_empty() {
                let _ = write!(out, ",\"security\":{sec_json}");
            }
        }
        out.push('}');
    }
    out.push(']');
    out
}

pub fn evaluate_udp_flood_candidate(
    mb: &protocol_guard::microburst::MicroburstResult,
    udp_tx_bps: f64,
    udp_concurrency: usize,
) -> Option<String> {
    let is_small_pkt_flood =
        mb.flood_type == "outbound_small_packet_flood" && mb.tx_pps >= 3000.0;
    let is_massive_burst = mb.tx_pps >= 6000.0;
    let udp_heavy_flood = udp_tx_bps >= 40_000_000.0 && udp_concurrency >= 300;
    if is_small_pkt_flood {
        Some(format!(
            "检测到高危出站小包泛洪 (发包率 {} PPS，平均包长 {}B)",
            mb.tx_pps, mb.avg_tx_packet_size
        ))
    } else if is_massive_burst {
        Some(format!("检测到超高频出站发包泛洪 ({} PPS)", mb.tx_pps))
    } else if udp_heavy_flood {
        Some(format!(
            "检测到大流量高并发 UDP 异常打流 ({:.1} Mbps, 并发 {})",
            udp_tx_bps / (1024.0 * 1024.0),
            udp_concurrency
        ))
    } else {
        None
    }
}

fn extract_net_counters(c: &ContainerSample) -> (u64, u64, u64, u64) {
    let Some(pm_val) = c
        .pid_metrics_json
        .as_deref()
        .and_then(|s| actions::parse_json(s).ok())
    else {
        return (0, 0, 0, 0);
    };
    let Some(net) = pm_val.get("net") else {
        return (0, 0, 0, 0);
    };
    let rx_bytes = net.get("rx_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
    let tx_bytes = net.get("tx_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
    let rx_packets = net.get("rx_packets").and_then(|v| v.as_u64()).unwrap_or(0);
    let tx_packets = net.get("tx_packets").and_then(|v| v.as_u64()).unwrap_or(0);
    (rx_bytes, tx_bytes, rx_packets, tx_packets)
}

fn build_udp_flood_blackhole_alert_json(
    c: &ContainerSample,
    trigger_reason: &str,
    tx_pps: f64,
    duration: u64,
) -> String {
    let inst_id = if !c.instance_id.is_empty() {
        &c.instance_id
    } else {
        &c.id
    };
    let msg = format!(
        "{trigger_reason}；已自动注入黑洞规则（放行 53 端口 DNS 与已建 TCP 连接），计划保护 {} 分钟。",
        duration / 60
    );
    format!(
        "{{\"type\":\"udp_flood_blackhole\",\"severity\":\"critical\",\"title\":\"已自动实施出站 UDP 专项阻断\",\"message\":\"{}\",\"value\":{},\"threshold\":3000,\"runtime\":\"{}\",\"project\":\"{}\",\"container_name\":\"{}\",\"instance_id\":\"{}\"}}",
        json_escape(&msg),
        tx_pps.round() as u64,
        json_escape(&c.runtime),
        json_escape(&c.project),
        json_escape(&c.name),
        json_escape(inst_id),
    )
}

#[cfg(unix)]
fn build_socket_inode_owner_map_from_procs(
    procs: &[abuse_guard::ScopedHostProcess],
    proc_root: &Path,
) -> HashMap<u64, (u32, String)> {
    let mut owners = HashMap::new();
    for p in procs.iter().take(256) {
        let fd_dir = proc_root.join(p.host_pid.to_string()).join("fd");
        let Ok(entries) = fs::read_dir(&fd_dir) else {
            continue;
        };
        for entry in entries.flatten().take(512) {
            let Ok(target) = fs::read_link(entry.path()) else {
                continue;
            };
            let Some(s) = target.to_str() else {
                continue;
            };
            if let Some(rest) = s.strip_prefix("socket:[") {
                if let Some(inode_str) = rest.strip_suffix(']') {
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        owners.insert(inode, (p.pid, p.process.clone()));
                    }
                }
            }
        }
    }
    owners
}

#[cfg(not(unix))]
fn build_socket_inode_owner_map_from_procs(
    _procs: &[abuse_guard::ScopedHostProcess],
    _proc_root: &Path,
) -> HashMap<u64, (u32, String)> {
    HashMap::new()
}

fn map_tcp_state_hex(state_hex: &str) -> &'static str {
    match state_hex {
        "01" => "established",
        "02" => "syn_sent",
        "03" => "syn_recv",
        "06" => "time_wait",
        "0A" => "listen",
        _ => "other",
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn extract_live_listeners_and_sockets(
    c: &ContainerSample,
    proc_root: &Path,
) -> (
    Vec<protocol_guard::vmess::ServiceListener>,
    bool,
    Vec<abuse_guard::SocketRecord>,
) {
    let scoped = c
        .pid
        .filter(|&p| p > 1)
        .and_then(|p| abuse_guard::scoped_host_processes(p, proc_root, 20_000).ok())
        .unwrap_or_default();
    extract_live_listeners_and_sockets_with_procs(c, proc_root, &scoped)
}

fn extract_live_listeners_and_sockets_with_procs(
    c: &ContainerSample,
    proc_root: &Path,
    scoped_procs: &[abuse_guard::ScopedHostProcess],
) -> (
    Vec<protocol_guard::vmess::ServiceListener>,
    bool,
    Vec<abuse_guard::SocketRecord>,
) {
    let raw_opt = c.socket_tables_json.clone().or_else(|| {
        #[cfg(unix)]
        {
            c.pid
                .filter(|&p| p > 1)
                .map(|p| socket_sec::collect_socket_tables_from_root(proc_root, p))
        }
        #[cfg(not(unix))]
        {
            None
        }
    });
    let Some(raw) = raw_opt else {
        return (Vec::new(), false, Vec::new());
    };
    let Ok(val) = runtime_drivers::JsonVal::parse(&raw) else {
        return (Vec::new(), false, Vec::new());
    };
    let available = val.get_bool("available").unwrap_or(false);
    let malformed = val.get_bool("malformed").unwrap_or(true);
    let complete = available && !malformed;

    let inode_owners = if !scoped_procs.is_empty() {
        build_socket_inode_owner_map_from_procs(scoped_procs, proc_root)
    } else {
        HashMap::new()
    };

    let mut listeners = Vec::new();
    let mut sockets = Vec::new();

    for (field, proto_name) in [("tcp_entries", "tcp"), ("udp_entries", "udp")] {
        let Some(entries) = val.get(field).and_then(|v| v.as_arr()) else {
            continue;
        };
        for entry in entries {
            let local_ip = entry.get_str("local_ip").unwrap_or("");
            let local_port = entry.get_i64("local_port").unwrap_or(0);
            let remote_ip = entry.get_str("remote_ip").unwrap_or("");
            let remote_port = entry.get_i64("remote_port").unwrap_or(0);
            let state_hex = entry.get_str("state_hex").unwrap_or("");
            let inode = entry.get_i64("inode").unwrap_or(0).max(0) as u64;
            let (owner_pid, owner_comm) = inode_owners
                .get(&inode)
                .cloned()
                .unwrap_or((0, String::new()));

            let is_listener = if proto_name == "tcp" {
                state_hex == "0A" && local_port > 0 && local_port <= 65535
            } else {
                local_port > 0 && local_port <= 65535 && remote_port == 0
            };

            if is_listener {
                listeners.push(protocol_guard::vmess::ServiceListener {
                    pid: owner_pid,
                    process: owner_comm.to_ascii_lowercase(),
                    proto: proto_name.to_string(),
                    local: local_ip.to_string(),
                    port: local_port as u16,
                    ..Default::default()
                });
            } else if remote_port > 0 && !remote_ip.is_empty() {
                let state = if proto_name == "tcp" {
                    map_tcp_state_hex(state_hex).to_string()
                } else {
                    "udp".to_string()
                };
                sockets.push(abuse_guard::SocketRecord {
                    pid: owner_pid,
                    remote_ip: remote_ip.to_string(),
                    remote: format!("{remote_ip}:{remote_port}"),
                    state,
                    proto: proto_name.to_string(),
                    direction: "outbound".to_string(),
                });
            }
        }
    }

    (listeners, complete, sockets)
}

#[cfg(unix)]
fn extract_protocol_configs_with_procs(
    c: &ContainerSample,
    proc_root: &Path,
    procs: &[abuse_guard::ScopedHostProcess],
) -> (
    Vec<protocol_guard::vmess::ConfiguredProtocol>,
    Vec<protocol_guard::vmess::ProcessScanState>,
    &'static str,
) {
    if c.pid.filter(|&p| p > 1).is_none() || procs.is_empty() {
        return (Vec::new(), Vec::new(), "partial");
    }
    let mut host_by_inner: HashMap<u32, u32> = HashMap::new();
    let mut ps_lines = String::new();
    for p in procs.iter().take(256) {
        host_by_inner.insert(p.pid, p.host_pid);
        let cmdline_raw = fs::read(proc_root.join(p.host_pid.to_string()).join("cmdline"))
            .unwrap_or_default();
        let cmdline = cmdline_raw
            .split(|&b| b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        if cmdline.is_empty() {
            continue;
        }
        let _ = writeln!(ps_lines, "{} S {} {}", p.pid, p.process, cmdline);
    }
    let cfg_json = app_guard::socks_detector::parse_process_configs_json(&ps_lines);
    let Ok(cfg_val) = runtime_drivers::JsonVal::parse(&cfg_json) else {
        return (Vec::new(), Vec::new(), "partial");
    };
    let Some(rows) = cfg_val.as_arr() else {
        return (Vec::new(), Vec::new(), "partial");
    };

    let mut configured = Vec::new();
    let mut scan_states = Vec::new();
    let mut all_complete = true;

    for row in rows {
        let proc_pid = row.get_i64("pid").unwrap_or(0).max(0) as u32;
        let host_pid = host_by_inner.get(&proc_pid).copied().unwrap_or(proc_pid);
        let process = row.get_str("process").unwrap_or("").to_ascii_lowercase();
        let unparsed = row.get_bool("unparsed").unwrap_or(false);
        let mut config_files = Vec::new();
        let mut proc_complete = !unparsed && proc_pid > 1;
        let proc_root_dir = proc_root.join(host_pid.to_string()).join("root");

        if let Some(paths) = row.get("paths").and_then(|v| v.as_arr()) {
            for path_val in paths.iter().take(8) {
                let Some(rel) = path_val.as_str() else {
                    continue;
                };
                if !rel.starts_with('/') || rel.contains("..") {
                    proc_complete = false;
                    continue;
                }
                config_files.push(rel.to_string());
                let host_path = proc_root_dir.join(rel.trim_start_matches('/'));
                match fs::read_to_string(&host_path) {
                    Ok(raw) => {
                        let parsed_inbounds =
                            app_guard::socks_detector::parse_inbound_protocols_json(&raw, &process);
                        if let Ok(inb_val) = runtime_drivers::JsonVal::parse(&parsed_inbounds) {
                            if inb_val.get_bool("parsed") != Some(true) {
                                proc_complete = false;
                            }
                            if let Some(eps) = inb_val.get("endpoints").and_then(|v| v.as_arr()) {
                                for ep in eps {
                                    let proto = ep.get_str("protocol").unwrap_or("").to_ascii_lowercase();
                                    let port = ep.get_i64("port").unwrap_or(0);
                                    if port <= 0 || port > 65535 {
                                        continue;
                                    }
                                    let listen = ep.get_str("listen").unwrap_or("*").to_string();
                                    let transports = ep
                                        .get("transports")
                                        .and_then(|v| v.as_arr())
                                        .map(|arr| {
                                            arr.iter()
                                                .filter_map(|t| t.as_str().map(str::to_string))
                                                .collect::<Vec<_>>()
                                        })
                                        .filter(|v| !v.is_empty());
                                    let complete_ep =
                                        ep.get_bool("port_config_complete").unwrap_or(false);
                                    configured.push(protocol_guard::vmess::ConfiguredProtocol {
                                        pid: proc_pid,
                                        process: process.clone(),
                                        protocol: proto,
                                        port: port as u16,
                                        listen,
                                        transports,
                                        port_config_complete: complete_ep,
                                        config_file: rel.to_string(),
                                    });
                                }
                            }
                        } else {
                            proc_complete = false;
                        }
                    }
                    Err(_) => {
                        proc_complete = false;
                    }
                }
            }
        }
        if !proc_complete {
            all_complete = false;
        }
        scan_states.push(protocol_guard::vmess::ProcessScanState {
            pid: proc_pid,
            process,
            state: if proc_complete { "complete" } else { "partial" }.to_string(),
            start_ticks: protocol_guard::vmess::pid_epoch_from(proc_root, host_pid),
            config_files,
            ..Default::default()
        });
    }

    (
        configured,
        scan_states,
        if all_complete { "complete" } else { "partial" },
    )
}

#[cfg(not(unix))]
fn extract_protocol_configs_with_procs(
    _c: &ContainerSample,
    _proc_root: &Path,
    _procs: &[abuse_guard::ScopedHostProcess],
) -> (
    Vec<protocol_guard::vmess::ConfiguredProtocol>,
    Vec<protocol_guard::vmess::ProcessScanState>,
    &'static str,
) {
    (Vec::new(), Vec::new(), "partial")
}

#[cfg(unix)]
fn run_container_guest_script(
    runtime: &str,
    project: &str,
    name: &str,
    instance_id: &str,
    podman_bin: Option<&str>,
    script: &str,
) -> (bool, String) {
    match runtime {
        "incus" => {
            let mut cmd = Command::new("incus");
            if !project.is_empty() {
                cmd.arg("--project").arg(project);
            }
            cmd.args(["exec", name, "--", "sh", "-c", script]);
            match cmd.output() {
                Ok(out) => (
                    out.status.success(),
                    String::from_utf8_lossy(&out.stdout).into_owned(),
                ),
                Err(_) => (false, String::new()),
            }
        }
        "podman" => {
            let bin = podman_bin.filter(|s| !s.is_empty()).unwrap_or("podman");
            let mut cmd = Command::new(bin);
            cmd.args(["exec", name, "sh", "-c", script]);
            match cmd.output() {
                Ok(out) => (
                    out.status.success(),
                    String::from_utf8_lossy(&out.stdout).into_owned(),
                ),
                Err(_) => (false, String::new()),
            }
        }
        "runman" => {
            if name.is_empty() || instance_id.is_empty() || script.is_empty() {
                return (false, String::new());
            }
            let body = format!(
                "{{\"container_name\":\"{}\",\"project\":\"default\",\"instance_id\":\"{}\",\"command\":\"{}\",\"timeout_seconds\":30}}",
                json_escape(name),
                json_escape(instance_id),
                json_escape(script),
            );
            let Ok((status, raw)) = runtime_drivers::runman_request(
                runtime_drivers::RUNMAN_SOCK_PATH,
                "POST",
                "/v1/exec",
                Some(body.as_bytes()),
            ) else {
                return (false, String::new());
            };
            if status != 200 {
                return (false, String::new());
            }
            let text = String::from_utf8_lossy(&raw);
            let Ok(val) = runtime_drivers::JsonVal::parse(&text) else {
                return (false, String::new());
            };
            let ok = val.get_bool("ok") == Some(true);
            let inst_ok = val.get_str("instance_id") == Some(instance_id);
            let exit_ok = val.get_i64("exit_code") == Some(0);
            let stdout = val.get_str("stdout").unwrap_or("").to_string();
            (ok && inst_ok && exit_ok, stdout)
        }
        _ => (false, String::new()),
    }
}

#[cfg(unix)]
struct OwnedPodmanIsolation {
    binary: String,
    name: String,
    instance_id: String,
}

#[cfg(unix)]
impl net_guard::IsolationDriver for OwnedPodmanIsolation {
    fn snapshot(&mut self) -> Result<runtime_drivers::JsonVal, String> {
        let mut runner = net_guard::LiveCommandRunner;
        net_guard::PodmanIsolation::new(&mut runner, &self.binary, &self.name, &self.instance_id)
            .snapshot()
    }
    fn refresh_backup(&mut self, backup: &mut runtime_drivers::JsonVal) -> Result<(), String> {
        let mut runner = net_guard::LiveCommandRunner;
        net_guard::PodmanIsolation::new(&mut runner, &self.binary, &self.name, &self.instance_id)
            .refresh_backup(backup)
    }
    fn isolate(&mut self, backup: &runtime_drivers::JsonVal) -> Result<(), String> {
        let mut runner = net_guard::LiveCommandRunner;
        net_guard::PodmanIsolation::new(&mut runner, &self.binary, &self.name, &self.instance_id)
            .isolate(backup)
    }
    fn verify(&mut self, backup: &runtime_drivers::JsonVal) -> Result<(), String> {
        let mut runner = net_guard::LiveCommandRunner;
        net_guard::PodmanIsolation::new(&mut runner, &self.binary, &self.name, &self.instance_id)
            .verify(backup)
    }
    fn release(
        &mut self,
        backup: &runtime_drivers::JsonVal,
    ) -> Result<net_guard::DriverReleaseOutcome, String> {
        let mut runner = net_guard::LiveCommandRunner;
        net_guard::PodmanIsolation::new(&mut runner, &self.binary, &self.name, &self.instance_id)
            .release(backup)
    }
    fn prove_replaced(&mut self) -> Result<String, String> {
        let mut runner = net_guard::LiveCommandRunner;
        net_guard::PodmanIsolation::new(&mut runner, &self.binary, &self.name, &self.instance_id)
            .prove_replaced()
    }
}

#[cfg(unix)]
enum LiveIsolationDriver {
    Incus(net_guard::IncusIsolation<net_guard::UnixIncusApi>),
    Podman(OwnedPodmanIsolation),
    Runman(net_guard::RunmanIsolation<net_guard::LiveRunmanTransport>),
    Unsupported(String),
}

#[cfg(unix)]
impl LiveIsolationDriver {
    fn from_target(t: &abuse_guard::ContainerTarget, inst_id: &str) -> Self {
        match t.runtime.as_str() {
            "incus" => Self::Incus(net_guard::IncusIsolation::new(
                net_guard::UnixIncusApi::new(&t.project, net_guard::DEFAULT_INCUS_SOCKET),
                &t.name,
                inst_id,
            )),
            "podman" => {
                let binary = if !t.runtime_bin.is_empty() {
                    Some(t.runtime_bin.clone())
                } else {
                    net_guard::NetToolPaths::discover().podman_bin
                };
                match binary {
                    Some(bin) => Self::Podman(OwnedPodmanIsolation {
                        binary: bin,
                        name: t.name.clone(),
                        instance_id: inst_id.to_string(),
                    }),
                    None => Self::Unsupported("Podman unavailable".to_string()),
                }
            }
            "runman" => Self::Runman(net_guard::RunmanIsolation::new(
                net_guard::LiveRunmanTransport::new(net_guard::DEFAULT_RUNMAN_SOCKET),
                &t.name,
                inst_id,
            )),
            other => Self::Unsupported(format!("unsupported runtime: {other}")),
        }
    }
}

#[cfg(unix)]
impl net_guard::IsolationDriver for LiveIsolationDriver {
    fn snapshot(&mut self) -> Result<runtime_drivers::JsonVal, String> {
        match self {
            Self::Incus(d) => d.snapshot(),
            Self::Podman(d) => d.snapshot(),
            Self::Runman(d) => d.snapshot(),
            Self::Unsupported(e) => Err(e.clone()),
        }
    }
    fn refresh_backup(&mut self, backup: &mut runtime_drivers::JsonVal) -> Result<(), String> {
        match self {
            Self::Incus(d) => d.refresh_backup(backup),
            Self::Podman(d) => d.refresh_backup(backup),
            Self::Runman(d) => d.refresh_backup(backup),
            Self::Unsupported(e) => Err(e.clone()),
        }
    }
    fn isolate(&mut self, backup: &runtime_drivers::JsonVal) -> Result<(), String> {
        match self {
            Self::Incus(d) => d.isolate(backup),
            Self::Podman(d) => d.isolate(backup),
            Self::Runman(d) => d.isolate(backup),
            Self::Unsupported(e) => Err(e.clone()),
        }
    }
    fn verify(&mut self, backup: &runtime_drivers::JsonVal) -> Result<(), String> {
        match self {
            Self::Incus(d) => d.verify(backup),
            Self::Podman(d) => d.verify(backup),
            Self::Runman(d) => d.verify(backup),
            Self::Unsupported(e) => Err(e.clone()),
        }
    }
    fn release(
        &mut self,
        backup: &runtime_drivers::JsonVal,
    ) -> Result<net_guard::DriverReleaseOutcome, String> {
        match self {
            Self::Incus(d) => d.release(backup),
            Self::Podman(d) => d.release(backup),
            Self::Runman(d) => d.release(backup),
            Self::Unsupported(e) => Err(e.clone()),
        }
    }
    fn prove_replaced(&mut self) -> Result<String, String> {
        match self {
            Self::Incus(d) => d.prove_replaced(),
            Self::Podman(d) => d.prove_replaced(),
            Self::Runman(d) => d.prove_replaced(),
            Self::Unsupported(e) => Err(e.clone()),
        }
    }
}

impl AgentState {
    pub fn build_container_telemetry_and_alerts(
        &mut self,
        config: &Config,
        containers: &[ContainerSample],
        timestamp: u64,
    ) -> (String, String) {
        let empty_metrics = HashMap::new();
        let empty_guard = HashMap::new();
        self.build_container_telemetry_and_alerts_with_guards(
            config,
            containers,
            timestamp,
            &empty_metrics,
            &empty_guard,
            &empty_guard,
            &empty_guard,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_container_telemetry_and_alerts_with_guards(
        &mut self,
        config: &Config,
        containers: &[ContainerSample],
        timestamp: u64,
        metrics_by_key: &HashMap<String, ContainerMetricsSummary>,
        cpu_guard_status_by_key: &HashMap<String, String>,
        mem_guard_status_by_key: &HashMap<String, String>,
        io_guard_status_by_key: &HashMap<String, String>,
    ) -> (String, String) {
        if containers.is_empty() {
            return ("[]".to_string(), "[]".to_string());
        }
        let speedtest_policy = protocol_guard::speedtest::load_policy(None);
        let auto_bh_enabled = std::env::var("SECURITY_UDP_BLACKHOLE_AUTO")
            .map(|v| parse_bool_flag(&v))
            .unwrap_or(true);
        let bh_duration: u64 = std::env::var("SECURITY_UDP_BLACKHOLE_DURATION")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .filter(|&d| d >= 60)
            .unwrap_or(1800);

        let mut security_jsons = Vec::with_capacity(containers.len());
        let mut alert_jsons: Vec<String> = Vec::new();
        let pid_ns_map = service_audit::collect_pid_ns_map(&self.proc_root);
        let batch_init_pids: Vec<u32> = containers
            .iter()
            .filter_map(|c| c.pid.filter(|&p| p > 1))
            .collect();
        let scoped_procs_by_pid = if batch_init_pids.is_empty() {
            HashMap::new()
        } else {
            abuse_guard::scoped_host_processes_batch(&batch_init_pids, &self.proc_root, 20_000)
                .unwrap_or_default()
        };

        for c in containers {
            let rt = c.runtime.trim().to_ascii_lowercase();
            let supported_rt = matches!(rt.as_str(), "incus" | "podman" | "runman");
            let inst_id = if !c.instance_id.is_empty() {
                c.instance_id.clone()
            } else {
                c.id.clone()
            };

            // 1. abuse_guard
            let abuse_res = if supported_rt {
                let target = abuse_guard::ContainerTarget {
                    runtime: rt.clone(),
                    runtime_bin: c.runtime_bin.clone(),
                    project: c.project.clone(),
                    name: c.name.clone(),
                    id: c.id.clone(),
                    pid: c.pid,
                    stable_id: c.stable_id.clone(),
                    instance_id: c.instance_id.clone(),
                };
                self.abuse_engine
                    .as_ref()
                    .map(|eng| eng.status(&target, Some(timestamp as f64)))
                    .unwrap_or_else(abuse_guard::AbuseCheckResult::pending_not_sampled)
            } else {
                abuse_guard::AbuseCheckResult::unsupported()
            };
            if let Some(ref alert) = abuse_res.alert {
                alert_jsons.push(alert.to_json());
            }
            let abuse_json = abuse_res.to_json();

            // 2. vmess_guard & trojan_guard (single-pass /proc batch lookup per container)
            let scoped_procs = c
                .pid
                .filter(|&p| p > 1)
                .and_then(|p| scoped_procs_by_pid.get(&p))
                .and_then(|r| r.as_ref().ok())
                .cloned()
                .unwrap_or_default();
            let (listeners, listener_inventory_complete, _) =
                extract_live_listeners_and_sockets_with_procs(c, &self.proc_root, &scoped_procs);
            let (configured_protocols, process_scan_states, scan_state) =
                extract_protocol_configs_with_procs(c, &self.proc_root, &scoped_procs);
            let ns_epoch = c
                .pid
                .filter(|&p| p > 1)
                .map(|p| protocol_guard::vmess::pid_epoch_from(&self.proc_root, p))
                .unwrap_or_default();

            let mut vmess_status = if supported_rt {
                let vmess_plan = protocol_guard::vmess::plan(
                    &rt,
                    &configured_protocols,
                    &listeners,
                    &[],
                    scan_state,
                    Some(&process_scan_states),
                    Some(listener_inventory_complete),
                    "vmess",
                );
                #[cfg(unix)]
                {
                    protocol_guard::vmess::apply_protocol_guard_plan(
                        &vmess_plan,
                        "vmess",
                        &rt,
                        &inst_id,
                        c.pid.unwrap_or(0),
                        &ns_epoch,
                        false,
                        true,
                        scan_state,
                        listener_inventory_complete,
                        &listeners,
                    )
                }
                #[cfg(not(unix))]
                {
                    vmess_plan
                }
            } else {
                protocol_guard::vmess::plan(
                    &rt,
                    &[],
                    &[],
                    &[],
                    "partial",
                    Some(&[]),
                    Some(false),
                    "vmess",
                )
            };
            protocol_guard::vmess::finalize_protocol_guard_evidence(&mut vmess_status);

            let mut trojan_status = if supported_rt {
                let trojan_plan = protocol_guard::vmess::plan(
                    &rt,
                    &configured_protocols,
                    &listeners,
                    &[],
                    scan_state,
                    Some(&process_scan_states),
                    Some(listener_inventory_complete),
                    "trojan",
                );
                #[cfg(unix)]
                {
                    protocol_guard::vmess::apply_protocol_guard_plan(
                        &trojan_plan,
                        "trojan",
                        &rt,
                        &inst_id,
                        c.pid.unwrap_or(0),
                        &ns_epoch,
                        false,
                        true,
                        scan_state,
                        listener_inventory_complete,
                        &listeners,
                    )
                }
                #[cfg(not(unix))]
                {
                    trojan_plan
                }
            } else {
                protocol_guard::vmess::plan(
                    &rt,
                    &[],
                    &[],
                    &[],
                    "partial",
                    Some(&[]),
                    Some(false),
                    "trojan",
                )
            };
            protocol_guard::vmess::finalize_protocol_guard_evidence(&mut trojan_status);

            let alert_ctx = protocol_guard::vmess::AlertContainerContext {
                runtime: rt.clone(),
                project: c.project.clone(),
                name: c.name.clone(),
                instance_id: inst_id.clone(),
                ..Default::default()
            };
            if let Some(alert) = protocol_guard::vmess::build_vmess_alert(&vmess_status, &[], &alert_ctx) {
                alert_jsons.push(alert.to_json());
            }
            if let Some(alert) = protocol_guard::vmess::build_trojan_alert(&trojan_status, &[], &alert_ctx) {
                alert_jsons.push(alert.to_json());
            }

            // 3. speedtest_guard (only when policy present and runtime supported)
            let speedtest_field = if let Some(ref pol) = speedtest_policy {
                if supported_rt {
                    let identity = format!("{rt}\0{}\0{}\0{inst_id}", c.project, c.name);
                    let st_input = protocol_guard::speedtest::SpeedtestContainerInput {
                        runtime: &rt,
                        name: &c.name,
                        project: &c.project,
                        identity: &identity,
                        pid: c.pid.unwrap_or(0),
                        namespace_epoch: &ns_epoch,
                        network_shared: false,
                        image: &c.image,
                        listeners: &listeners,
                        listener_inventory_complete,
                        policy: pol,
                        observed_at: Some(timestamp as i64),
                    };
                    #[cfg(unix)]
                    let st_status = {
                        let tools = net_guard::NetToolPaths::discover();
                        let mut host_runner = net_guard::LiveCommandRunner;
                        let mut epoch_fn = protocol_guard::vmess::pid_epoch;
                        let mut guest_runner = |script: &str| {
                            run_container_guest_script(
                                &rt,
                                &c.project,
                                &c.name,
                                &inst_id,
                                Some(c.runtime_bin.as_str()),
                                script,
                            )
                        };
                        protocol_guard::speedtest::reconcile_container_with(
                            &st_input,
                            Some(&mut guest_runner),
                            None,
                            &mut self.speedtest_caches,
                            &tools,
                            &mut host_runner,
                            &self.proc_root,
                            &mut epoch_fn,
                        )
                    };
                    #[cfg(not(unix))]
                    let st_status = {
                        let _ = st_input;
                        protocol_guard::speedtest::SpeedtestGuardStatus {
                            state: if pol.invalid { "unverified" } else { "not_detected" }.to_string(),
                            reason: if pol.invalid { "policy_invalid" } else { "" }.to_string(),
                            observed_at: timestamp as i64,
                            policy_revision: pol.revision,
                            services: pol.services.clone(),
                            ..Default::default()
                        }
                    };
                    if let Some(alert) = protocol_guard::speedtest::build_speedtest_attempt_blocked_alert(&st_status, &alert_ctx) {
                        alert_jsons.push(alert.to_json());
                    }
                    format!(",\"speedtest_guard\":{}", st_status.to_json())
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            // 4. sensitive_file_events
            let drops = if let Some(pid) = c.pid.filter(|&p| p > 1) {
                protocol_guard::file_drop::scan_container_sensitive_drops_from(
                    pid,
                    &rt,
                    &c.name,
                    &self.proc_root,
                )
            } else {
                Vec::new()
            };
            let drops_json = protocol_guard::file_drop::sensitive_file_events_to_json(&drops);

            // 5. microburst
            let (rx_bytes, tx_bytes, rx_packets, tx_packets) = extract_net_counters(c);
            let mb = self.microburst.detect_microburst(
                &rt,
                &c.name,
                rx_packets,
                tx_packets,
                rx_bytes,
                tx_bytes,
                timestamp as f64,
            );
            let mb_json = mb.to_json();

            // 6. udp_blackhole + auto-trigger / auto-release
            let pid = c.pid.unwrap_or(0);
            let mut bh_status = if supported_rt {
                net_guard::get_udp_blackhole_status(&rt, &c.name, pid).unwrap_or(
                    net_guard::UdpBlackholeStatus {
                        active: false,
                        allow_dns: true,
                        applied_at: None,
                        auto_triggered: false,
                        expires_at: None,
                        remaining_seconds: None,
                        reason: String::new(),
                    },
                )
            } else {
                net_guard::UdpBlackholeStatus {
                    active: false,
                    allow_dns: true,
                    applied_at: None,
                    auto_triggered: false,
                    expires_at: None,
                    remaining_seconds: None,
                    reason: String::new(),
                }
            };
            if supported_rt && pid > 1 && config.security_monitor_enabled {
                let bh_key = format!("{rt}:{}:{}", c.project, c.name);
                if bh_status.active {
                    if let Some(exp) = bh_status.expires_at.filter(|&e| e > 0 && timestamp >= e) {
                        let _ = exp;
                        let rel = net_guard::release_udp_blackhole(
                            &rt,
                            &c.name,
                            pid,
                            &inst_id,
                            &c.project,
                        );
                        if rel.ok {
                            self.udp_blackhole_auto_states.insert(bh_key.clone(), (0, 0));
                            if let Ok(refreshed) = net_guard::get_udp_blackhole_status(&rt, &c.name, pid) {
                                bh_status = refreshed;
                            }
                        }
                    }
                } else if auto_bh_enabled {
                    let udp_conns = c
                        .socket_tables_json
                        .as_deref()
                        .and_then(|s| actions::parse_json(s).ok())
                        .and_then(|v| v.get("udp_sockets").and_then(|u| u.as_u64()))
                        .unwrap_or(0) as usize;
                    if let Some(reason) = evaluate_udp_flood_candidate(&mb, 0.0, udp_conns) {
                        let entry = self
                            .udp_blackhole_auto_states
                            .entry(bh_key)
                            .or_insert((0, 0));
                        if entry.1 == 0 {
                            entry.1 = timestamp;
                        }
                        entry.0 = entry.0.saturating_add(1);
                        if mb.tx_pps >= 8000.0 || entry.0 >= 2 {
                            let mut req = net_guard::UdpBlackholeApply::new(&rt, &c.name, pid);
                            req.instance_id = inst_id.clone();
                            req.allow_dns = true;
                            req.project = if c.project.is_empty() {
                                "default".to_string()
                            } else {
                                c.project.clone()
                            };
                            req.auto_triggered = true;
                            req.duration = bh_duration;
                            req.reason = reason.clone();
                            let applied = net_guard::apply_udp_blackhole(&req);
                            if applied.ok {
                                if let Ok(refreshed) =
                                    net_guard::get_udp_blackhole_status(&rt, &c.name, pid)
                                {
                                    bh_status = refreshed;
                                }
                                alert_jsons.push(build_udp_flood_blackhole_alert_json(
                                    c,
                                    &reason,
                                    mb.tx_pps,
                                    bh_duration,
                                ));
                            }
                        }
                    } else {
                        self.udp_blackhole_auto_states.insert(bh_key, (0, 0));
                    }
                }
            }
            let bh_json = bh_status.to_json();

            // 7. anti_spoof
            let anti_spoof_json = if supported_rt {
                net_guard::get_anti_spoof_status_for_container(&rt, &c.name, "")
                    .map(|s| s.to_json())
                    .unwrap_or_else(|_| {
                        "{\"active\":false,\"veth\":\"\",\"v4_ips\":[],\"v6_ips\":[],\"applied_at\":null}".to_string()
                    })
            } else {
                "{\"active\":false,\"veth\":\"\",\"v4_ips\":[],\"v6_ips\":[],\"applied_at\":null}".to_string()
            };

            // 8. pasarguard alerts
            for pg_alert in self.pasarguard.alerts_at(&rt, &c.project, &c.name, timestamp as i64) {
                alert_jsons.push(pg_alert.to_json());
            }

            // 9. admission status + alerts
            let admission_field = if supported_rt {
                if let Some(ref ctrl) = self.admission_controller {
                    let desc = admission_guard::ContainerDescriptor {
                        runtime: rt.clone(),
                        project: c.project.clone(),
                        name: c.name.clone(),
                        id: c.id.clone(),
                        instance_id: c.instance_id.clone(),
                        pid: c.pid,
                        network_addresses: c.network_addresses.clone(),
                    };
                    for adm_alert in ctrl.guard.alerts_at(&desc, timestamp as i64) {
                        alert_jsons.push(net_guard::json_val_to_string(
                            &runtime_drivers::JsonVal::Obj(adm_alert),
                            false,
                        ));
                    }
                    let adm_status = ctrl.guard.status_at(&desc, timestamp as i64);
                    if adm_status.is_empty() {
                        String::new()
                    } else {
                        format!(
                            ",\"admission\":{}",
                            net_guard::json_val_to_string(
                                &runtime_drivers::JsonVal::Obj(adm_status),
                                false
                            )
                        )
                    }
                } else {
                    #[cfg(unix)]
                    if let Some(ref err) = self.admission_init_error {
                        format!(
                            ",\"admission\":{{\"state\":\"unverified\",\"reason\":\"{}\"}}",
                            json_escape(err)
                        )
                    } else {
                        String::new()
                    }
                    #[cfg(not(unix))]
                    {
                        String::new()
                    }
                }
            } else {
                String::new()
            };

            let motd_delivery_field = self
                .motd_deliveries
                .get(&(c.runtime.to_ascii_lowercase(), c.project.clone(), c.name.clone()))
                .map(|m| format!(",\"motd_delivery\":{}", m.to_json()))
                .unwrap_or_default();

            // 10. service config audit (sanitized metadata only, never secrets/raw config)
            let service_audit_field = if self.service_audit_enabled
                && supported_rt
                && c.status.eq_ignore_ascii_case("running")
            {
                let svc_audit = service_audit::audit_container_with_pid_ns_policy(
                    &self.proc_root,
                    &pid_ns_map,
                    c.pid,
                    self.sni_whitelist.as_deref(),
                    self.disallowed_protocols.as_deref(),
                );
                for item in svc_audit.alerts_to_json_items(&rt, &c.project, &c.name, &inst_id) {
                    alert_jsons.push(item);
                }
                if svc_audit.services.is_empty() {
                    String::new()
                } else {
                    format!(",\"service_audit\":{}", svc_audit.to_json())
                }
            } else {
                String::new()
            };

            let guard_key = container_guard_key(c);
            let cpu_guard_field = cpu_guard_status_by_key
                .get(&guard_key)
                .map(|s| format!(",\"cpu_guard\":{s}"))
                .unwrap_or_default();
            let mem_guard_field = mem_guard_status_by_key
                .get(&guard_key)
                .map(|s| format!(",\"memory_guard\":{s}"))
                .unwrap_or_default();
            let io_guard_field = io_guard_status_by_key
                .get(&guard_key)
                .map(|s| format!(",\"io_guard\":{s}"))
                .unwrap_or_default();

            let sec_json = format!(
                "{{\"abuse_guard\":{},\"vmess_guard\":{},\"trojan_guard\":{}{},\"sensitive_file_events\":{},\"microburst\":{},\"udp_blackhole\":{},\"anti_spoof\":{}{}{}{}{}{}{}}}",
                abuse_json,
                vmess_status.to_json(),
                trojan_status.to_json(),
                speedtest_field,
                drops_json,
                mb_json,
                bh_json,
                anti_spoof_json,
                admission_field,
                motd_delivery_field,
                service_audit_field,
                cpu_guard_field,
                mem_guard_field,
                io_guard_field,
            );
            security_jsons.push(sec_json);
        }

        let containers_json =
            serialize_containers_with_security_json(containers, &security_jsons, metrics_by_key);
        let alerts_json = format!("[{}]", alert_jsons.join(","));
        (containers_json, alerts_json)
    }

    pub fn run_security_guard_cycles(
        &mut self,
        config: &Config,
        client: &TransportClient,
        timestamp: u64,
    ) {
        #[cfg(not(unix))]
        {
            let _ = (config, client, timestamp);
        }
        #[cfg(unix)]
        {
            if !config.security_monitor_enabled || config.node_id.is_empty() {
                return;
            }
            let containers = self.last_containers.clone();
            if containers.is_empty() {
                return;
            }

            // 1. Bounded abuse_guard cycle
            let abuse_enabled = std::env::var("SECURITY_ABUSE_GUARD_ENABLED")
                .map(|v| parse_bool_flag(&v))
                .unwrap_or(true);
            if abuse_enabled {
                if let Some(ref engine) = self.abuse_engine {
                    let targets: Vec<abuse_guard::ContainerTarget> = containers
                        .iter()
                        .map(|c| abuse_guard::ContainerTarget {
                            runtime: c.runtime.to_ascii_lowercase(),
                            runtime_bin: c.runtime_bin.clone(),
                            project: c.project.clone(),
                            name: c.name.clone(),
                            id: c.id.clone(),
                            pid: c.pid,
                            stable_id: c.stable_id.clone(),
                            instance_id: c.instance_id.clone(),
                        })
                        .collect();
                    let sample_by_key: HashMap<(String, String, String), ContainerSample> = containers
                        .iter()
                        .map(|c| {
                            (
                                (
                                    c.runtime.to_ascii_lowercase(),
                                    c.project.clone(),
                                    c.name.clone(),
                                ),
                                c.clone(),
                            )
                        })
                        .collect();
                    let proc_root = self.proc_root.clone();
                    let cycle_init_pids: Vec<u32> = targets
                        .iter()
                        .filter_map(|t| t.pid.filter(|&p| p > 1))
                        .collect();
                    let batch_scoped_res = if cycle_init_pids.is_empty() {
                        Ok(HashMap::new())
                    } else {
                        abuse_guard::scoped_host_processes_batch(&cycle_init_pids, &proc_root, 20_000)
                    };
                    let transport_cfg = config.to_transport_config();
                    let host_id = config.host_id.clone();
                    let node_id = config.node_id.clone();
                    let agent_ver = resolved_agent_version();
                    let _ = engine.schedule(
                        &targets,
                        move |t| {
                            let pid = t.pid.filter(|&p| p > 1).ok_or_else(|| {
                                "container kernel process is unavailable".to_string()
                            })?;
                            let inst_id = if !t.instance_id.is_empty() {
                                t.instance_id.clone()
                            } else {
                                t.id.clone()
                            };
                            let scoped = match &batch_scoped_res {
                                Ok(map) => match map.get(&pid) {
                                    Some(Ok(list)) => list.clone(),
                                    Some(Err(err)) => return Err(err.clone()),
                                    None => abuse_guard::scoped_host_processes(pid, &proc_root, 20_000)?,
                                },
                                Err(err) => return Err(err.clone()),
                            };
                            let sockets = sample_by_key
                                .get(&(t.runtime.clone(), t.project.clone(), t.name.clone()))
                                .map(|s| {
                                    extract_live_listeners_and_sockets_with_procs(
                                        s,
                                        &proc_root,
                                        &scoped,
                                    )
                                    .2
                                })
                                .unwrap_or_default();
                            let procs = abuse_guard::collect_host(
                                &scoped,
                                &sockets,
                                t,
                                &mut |target, cmd| {
                                    run_container_guest_script(
                                        &target.runtime,
                                        &target.project,
                                        &target.name,
                                        &inst_id,
                                        Some(target.runtime_bin.as_str()),
                                        cmd,
                                    )
                                },
                            )?;
                            Ok((
                                inst_id.clone(),
                                abuse_guard::PlainIsolationDriver(
                                    LiveIsolationDriver::from_target(t, &inst_id),
                                ),
                                procs,
                                sockets,
                            ))
                        },
                        move |alert| {
                            let payload = abuse_guard::build_abuse_event_payload_json(
                                &host_id,
                                &node_id,
                                &agent_ver,
                                current_unix_ts(),
                                alert,
                            );
                            let tc = TransportClient::new(transport_cfg.clone())
                                .map_err(|e| e.to_string())?;
                            let resp = tc
                                .post_json_signed("/api/v1/abuse/events", payload.as_bytes())
                                .map_err(|e| e.to_string())?;
                            let text = String::from_utf8_lossy(&resp.body);
                            runtime_drivers::JsonVal::parse(text.trim())
                        },
                        4,
                    );
                }
            }

            let tools = net_guard::NetToolPaths::discover();
            let mut runtime_bins = std::collections::BTreeMap::new();
            if let Some(ref podman) = tools.podman_bin {
                runtime_bins.insert("podman".to_string(), podman.clone());
            }

            // 2. Bounded admission_guard cycle
            if let Some(ref ctrl) = self.admission_controller {
                let descriptors: Vec<admission_guard::ContainerDescriptor> = containers
                    .iter()
                    .map(|c| admission_guard::ContainerDescriptor {
                        runtime: c.runtime.to_ascii_lowercase(),
                        project: c.project.clone(),
                        name: c.name.clone(),
                        id: c.id.clone(),
                        instance_id: c.instance_id.clone(),
                        pid: c.pid,
                        network_addresses: c.network_addresses.clone(),
                    })
                    .collect();
                let mut runner = net_guard::LiveCommandRunner;
                ctrl.run_batch(
                    &descriptors,
                    |desc| admission_guard::snapshot(desc, &runtime_bins, &mut runner, true),
                    timestamp as i64,
                );
                let items = ctrl.collect_status_items(timestamp as i64);
                if !items.is_empty() {
                    let payload = admission_guard::build_status_payload_json(
                        &config.host_id,
                        &config.node_id,
                        timestamp as i64,
                        &items,
                    );
                    let _ = client.post_json_signed("/api/v1/admission/status", payload.as_bytes());
                }
                for (_, alert) in ctrl.collect_due_notifications(timestamp as i64) {
                    let payload = admission_guard::build_event_payload_json(
                        &config.host_id,
                        &config.node_id,
                        timestamp as i64,
                        &alert,
                    );
                    let _ = client.post_json_signed("/api/v1/admission/events", payload.as_bytes());
                }
            }

            // 3. Bounded pasarguard cycle
            if protocol_guard::pasarguard::PasarGuardMonitor::is_enabled_from_env() {
                let pg_targets: Vec<protocol_guard::pasarguard::PasarContainerTarget> = containers
                    .iter()
                    .map(|c| protocol_guard::pasarguard::PasarContainerTarget {
                        runtime: c.runtime.to_ascii_lowercase(),
                        project: c.project.clone(),
                        name: c.name.clone(),
                    })
                    .collect();
                let sample_by_key: HashMap<(String, String, String), ContainerSample> = containers
                    .iter()
                    .map(|c| {
                        (
                            (
                                c.runtime.to_ascii_lowercase(),
                                c.project.clone(),
                                c.name.clone(),
                            ),
                            c.clone(),
                        )
                    })
                    .collect();
                let runman_instance_ids: HashMap<String, String> = containers
                    .iter()
                    .filter(|c| c.runtime.eq_ignore_ascii_case("runman") && !c.instance_id.is_empty())
                    .map(|c| (c.name.clone(), c.instance_id.clone()))
                    .collect();
                let mut backend = LivePasarBackend {
                    client,
                    host_id: &config.host_id,
                    node_id: &config.node_id,
                    timestamp,
                    podman_bin: tools.podman_bin.clone(),
                    runtime_bins,
                    runman_instance_ids,
                    sample_by_key,
                };
                self.pasarguard
                    .scan_containers(&pg_targets, &mut backend, timestamp as i64);
            }

            // 4. Sync SSH pre-auth banner for runman containers
            self.sync_container_security_banners(config, &containers, timestamp);
        }
    }

    #[cfg(unix)]
    fn sync_container_security_banners(
        &mut self,
        config: &Config,
        containers: &[ContainerSample],
        timestamp: u64,
    ) {
        if !config.security_monitor_enabled {
            return;
        }
        let disabled = std::env::var("SECURITY_INJECT_MOTD_ALERT")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off" | "no"))
            .unwrap_or(false);
        if disabled {
            return;
        }
        let motd_states = self.motd_states.clone();
        let alerts = runtime_drivers::JsonVal::parse(self.last_alerts_json.trim())
            .ok()
            .and_then(|v| v.as_arr().map(|a| a.to_vec()))
            .unwrap_or_default();
        let mut opts = app_guard::security_banner::MotdRenderOptions::from_env();
        opts.color = false;
        opts.sampled_at = Some(timestamp as f64);

        for c in containers {
            let rt_lower = c.runtime.to_ascii_lowercase();
            if !matches!(rt_lower.as_str(), "runman" | "incus" | "podman") || c.name.is_empty() {
                continue;
            }
            let mut entries: Vec<app_guard::security_banner::MotdEntry> = Vec::new();
            let mut notice_ids: Vec<String> = Vec::new();
            for s in &motd_states {
                let stype = s.get("type").and_then(runtime_drivers::JsonVal::as_str).unwrap_or("");
                if stype != "user_notice" {
                    continue;
                }
                let s_rt = s.get("runtime").and_then(runtime_drivers::JsonVal::as_str).unwrap_or("");
                let s_proj = s.get("project").and_then(runtime_drivers::JsonVal::as_str).unwrap_or("");
                let s_name = s.get("name").and_then(runtime_drivers::JsonVal::as_str).unwrap_or("");
                if s_rt != rt_lower || s_proj != c.project || s_name != c.name {
                    continue;
                }
                let exp = s.get("expires_at").and_then(runtime_drivers::JsonVal::as_i64).unwrap_or(0);
                if exp <= timestamp as i64 {
                    continue;
                }
                if let Some(eid) = s.get("event_id").and_then(runtime_drivers::JsonVal::as_str) {
                    if !eid.is_empty() {
                        notice_ids.push(eid.to_string());
                    }
                }
                if let Some(entry) = app_guard::security_banner::MotdEntry::from_json(s) {
                    entries.push(entry);
                }
            }
            for a in &alerts {
                let a_rt = a.get("runtime").and_then(runtime_drivers::JsonVal::as_str).unwrap_or("");
                let a_proj = a.get("project").and_then(runtime_drivers::JsonVal::as_str).unwrap_or("");
                let a_name = a.get("container_name").and_then(runtime_drivers::JsonVal::as_str).unwrap_or("");
                if a_rt != rt_lower || a_proj != c.project || a_name != c.name {
                    continue;
                }
                if let Some(entry) = app_guard::security_banner::MotdEntry::from_json(a) {
                    entries.push(entry);
                }
            }
            let selected = app_guard::security_banner::select_motd_entries(&entries);
            let delivery_key = (rt_lower.clone(), c.project.clone(), c.name.clone());
            if selected.is_empty() && !self.motd_deliveries.contains_key(&delivery_key) {
                continue;
            }
            let banner_text = app_guard::security_banner::render_motd_banner_entries(
                &selected,
                &opts,
            );
            let banner_hash = fnv1a_hex(&banner_text, &notice_ids);
            if let Some(prev) = self.motd_deliveries.get(&delivery_key) {
                if prev.banner_hash == banner_hash
                    && prev.status == "written"
                    && (selected.is_empty() || timestamp.saturating_sub(prev.updated_at) < 300)
                {
                    continue;
                }
            }

            let podman_bin = (!c.runtime_bin.is_empty()).then_some(c.runtime_bin.as_str());
            let mut shell_delivery = "failed".to_string();
            let mut err_msg = String::new();
            if let Some(shell_script) = build_shell_banner_install_script(&banner_text) {
                let (ok, out) = run_container_guest_script(
                    &rt_lower,
                    &c.project,
                    &c.name,
                    &c.instance_id,
                    podman_bin,
                    &shell_script,
                );
                if ok && out.contains("NARWHAL_SHELL_OK:") {
                    shell_delivery = "installed".to_string();
                } else {
                    err_msg = "shell_banner_exec_failed".to_string();
                }
            }

            let mut ssh_banner_state = "not_applicable".to_string();
            if matches!(rt_lower.as_str(), "runman" | "incus") {
                if let Some(ssh_script) = build_ssh_banner_install_script(&banner_text) {
                    let (ok, out) = run_container_guest_script(
                        &rt_lower,
                        &c.project,
                        &c.name,
                        &c.instance_id,
                        podman_bin,
                        &ssh_script,
                    );
                    if let Some(parsed_state) = out
                        .lines()
                        .find_map(|l| l.trim().strip_prefix("NARWHAL_SSH_BANNER_STATE="))
                    {
                        ssh_banner_state = parsed_state.to_string();
                    } else if !ok {
                        ssh_banner_state = "failed".to_string();
                    }
                }
            }

            let status = if shell_delivery == "installed" || ssh_banner_state == "active" {
                "written".to_string()
            } else {
                "failed".to_string()
            };
            self.motd_deliveries.insert(
                delivery_key,
                MotdDeliveryState {
                    banner_hash,
                    status,
                    shell_delivery,
                    ssh_banner_state,
                    notice_ids,
                    error: err_msg,
                    updated_at: timestamp,
                },
            );
        }
    }
}

#[cfg(unix)]
struct LivePasarBackend<'a> {
    client: &'a TransportClient,
    host_id: &'a str,
    node_id: &'a str,
    timestamp: u64,
    podman_bin: Option<String>,
    runtime_bins: std::collections::BTreeMap<String, String>,
    runman_instance_ids: HashMap<String, String>,
    sample_by_key: HashMap<(String, String, String), ContainerSample>,
}

#[cfg(unix)]
impl<'a> protocol_guard::pasarguard::PasarGuardBackend for LivePasarBackend<'a> {
    fn snapshot(
        &mut self,
        container: &protocol_guard::pasarguard::PasarContainerTarget,
    ) -> Result<protocol_guard::pasarguard::PasarContainerSnapshot, String> {
        let key = (
            container.runtime.to_ascii_lowercase(),
            container.project.clone(),
            container.name.clone(),
        );
        if let Some(sample) = self.sample_by_key.get(&key) {
            if let Some(pid) = sample.pid.filter(|&p| p > 1) {
                let inst_id = if sample.runtime.eq_ignore_ascii_case("runman") {
                    sample.instance_id.clone()
                } else if !sample.stable_id.is_empty() {
                    sample.stable_id.clone()
                } else {
                    sample.id.clone()
                };
                if !inst_id.is_empty() {
                    if let Ok(epoch) = admission_guard::incarnation(pid) {
                        return Ok(protocol_guard::pasarguard::PasarContainerSnapshot {
                            instance_id: inst_id,
                            epoch,
                            pid,
                        });
                    }
                }
            }
        }
        let desc = admission_guard::ContainerDescriptor {
            runtime: container.runtime.clone(),
            project: container.project.clone(),
            name: container.name.clone(),
            id: String::new(),
            instance_id: self
                .runman_instance_ids
                .get(&container.name)
                .cloned()
                .unwrap_or_default(),
            pid: None,
            network_addresses: Vec::new(),
        };
        let mut runner = net_guard::LiveCommandRunner;
        let snap = admission_guard::snapshot(&desc, &self.runtime_bins, &mut runner, false)
            .map_err(|e| e.to_string())?;
        Ok(protocol_guard::pasarguard::PasarContainerSnapshot {
            instance_id: snap.instance_id,
            epoch: snap.epoch,
            pid: snap.pid.unwrap_or(0),
        })
    }

    fn podman_bin(&self) -> Option<String> {
        self.podman_bin.clone()
    }

    fn run_host(&mut self, args: &[String]) -> (bool, String) {
        use net_guard::CommandRunner as _;
        let mut runner = net_guard::LiveCommandRunner;
        runner.run(args, None)
    }

    fn guest_exec(
        &mut self,
        container: &protocol_guard::pasarguard::PasarContainerTarget,
        script: &str,
    ) -> (bool, String) {
        let inst_id = if container.runtime == "runman" {
            self.runman_instance_ids
                .get(&container.name)
                .cloned()
                .or_else(|| self.snapshot(container).ok().map(|s| s.instance_id))
                .unwrap_or_default()
        } else {
            String::new()
        };
        run_container_guest_script(
            &container.runtime,
            &container.project,
            &container.name,
            &inst_id,
            self.podman_bin.as_deref(),
            script,
        )
    }

    fn emit_event(
        &mut self,
        _container: &protocol_guard::pasarguard::PasarContainerTarget,
        alert: &protocol_guard::pasarguard::PasarAlert,
    ) {
        let payload = format!(
            "{{\"host_id\":\"{}\",\"node_id\":\"{}\",\"timestamp\":{},\"alert\":{}}}",
            json_escape(self.host_id),
            json_escape(self.node_id),
            self.timestamp,
            alert.to_json()
        );
        let _ = self
            .client
            .post_json_signed("/api/v1/admission/events", payload.as_bytes());
    }
}

fn serialize_suspicious_findings_json(
    findings: &[guard_core::security::SuspiciousProcFinding],
) -> String {
    if findings.is_empty() {
        return "[]".to_string();
    }
    let mut out = String::from("[");
    for (idx, item) in findings.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&item.to_json());
    }
    out.push(']');
    out
}

/// Checks whether IPv4 or IPv6 kernel routing is available without sending packets.
pub fn host_ip_family_available(ipv6: bool) -> bool {
    let (bind_addr, target_addr) = if ipv6 {
        ("[::]:0", "[2606:4700:4700::1111]:53")
    } else {
        ("0.0.0.0:0", "1.1.1.1:53")
    };
    let Ok(sock) = UdpSocket::bind(bind_addr) else {
        return false;
    };
    if sock.connect(target_addr).is_err() {
        return false;
    }
    match sock.local_addr() {
        Ok(addr) => !addr.ip().is_unspecified(),
        Err(_) => false,
    }
}

fn binary_exists_in_path(bin: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path_var).any(|dir| {
        let candidate = dir.join(bin);
        candidate.is_file()
    })
}

/// Builds the `operations.runtime_inventory` snapshot matching the Python agent contract.
pub fn detect_runtime_inventory_json(containers: &[ContainerSample]) -> String {
    detect_runtime_inventory_with_empty(containers).0
}

fn detect_runtime_inventory_with_empty(containers: &[ContainerSample]) -> (String, bool) {
    let mut runtimes = BTreeSet::new();
    if Path::new("/run/narwhal-agent/connlimit.sock").exists() || binary_exists_in_path("runman") {
        runtimes.insert("runman".to_string());
    }
    for name in ["podman", "docker", "incus"] {
        if binary_exists_in_path(name) {
            runtimes.insert(name.to_string());
        }
    }
    for container in containers {
        let rt = container.runtime.trim().to_ascii_lowercase();
        if !rt.is_empty() {
            runtimes.insert(rt);
        }
    }
    let is_empty = runtimes.is_empty();
    let state = if is_empty {
        "empty"
    } else {
        "available"
    };
    let mut runtimes_json = String::from("[");
    for (idx, rt) in runtimes.iter().take(8).enumerate() {
        if idx > 0 {
            runtimes_json.push(',');
        }
        let _ = write!(runtimes_json, "\"{}\"", json_escape(rt));
    }
    runtimes_json.push(']');
    (
        format!(
            "{{\"state\":\"{}\",\"runtimes\":{},\"container_count\":{}}}",
            state,
            runtimes_json,
            containers.len()
        ),
        is_empty,
    )
}

/// Generates `security.alerts` entries from Rust socket abuse and suspicious process verdicts.
pub fn build_security_alerts_json(
    socket_verdict: &SocketAbuseVerdict,
    suspicious_findings: &[SuspiciousProcFinding],
) -> String {
    let mut items: Vec<String> = Vec::new();
    if socket_verdict.suspected {
        let cat_titles: Vec<&str> = socket_verdict
            .categories
            .iter()
            .map(|c| c.title.as_str())
            .filter(|t| !t.is_empty())
            .collect();
        let cat_summary = if cat_titles.is_empty() {
            "异常连接特征".to_string()
        } else {
            cat_titles.join("、")
        };
        let primary = socket_verdict.categories.first();
        let value = primary.map(|c| c.value).unwrap_or(socket_verdict.total_sockets.max(1));
        let threshold = primary.map(|c| c.threshold).unwrap_or(1);
        let reason = primary
            .map(|c| c.reason.as_str())
            .unwrap_or(socket_verdict.verdict_label.as_str());
        let title = format!("疑似 Socket / 代理连接滥用（待人工复核：{}）", cat_summary);
        let message = format!("{} {}", socket_verdict.verdict_label, reason).trim().to_string();
        items.push(format!(
            "{{\"type\":\"socket_abuse_suspected\",\"severity\":\"{}\",\"title\":\"{}\",\"message\":\"{}\",\"value\":{},\"threshold\":{},\"protection_only\":true,\"auto_stop_eligible\":false}}",
            json_escape(if socket_verdict.severity.is_empty() { "warning" } else { &socket_verdict.severity }),
            json_escape(&title),
            json_escape(&message),
            value,
            threshold,
        ));
    }
    if let Some(first) = suspicious_findings.first() {
        let sev = if first.severity.is_empty() {
            "critical"
        } else {
            first.severity.as_str()
        };
        let title = format!(
            "发现疑似恶意/代理进程：{} (PID {})",
            first.process, first.pid
        );
        let message = format!(
            "类别={} 匹配={} 命令={}",
            first.category, first.pattern, first.redacted_command
        );
        items.push(format!(
            "{{\"type\":\"suspicious_process\",\"severity\":\"{}\",\"title\":\"{}\",\"message\":\"{}\",\"value\":{},\"threshold\":1,\"pid\":{},\"process\":\"{}\",\"category\":\"{}\",\"pattern\":\"{}\"}}",
            json_escape(sev),
            json_escape(&title),
            json_escape(&message),
            suspicious_findings.len(),
            first.pid,
            json_escape(&first.process),
            json_escape(&first.category),
            json_escape(&first.pattern),
        ));
    }
    format!("[{}]", items.join(","))
}

fn parse_csv_items(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_csv_lowercase(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessLogEvent {
    pub ip: String,
    pub status: u16,
    pub method: String,
    pub uri: String,
}

#[derive(Debug, Clone, Default)]
pub struct AccessLogSummary {
    pub enabled: bool,
    pub configured_files: usize,
    pub readable_files: usize,
    pub missing_files: usize,
    pub unreadable_files: usize,
    pub requests: u64,
    pub requests_per_second: f64,
    pub unique_ips: usize,
    pub top_ip: String,
    pub top_ip_requests: u64,
    pub top_ip_requests_per_second: f64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub top_ip_4xx: String,
    pub top_ip_4xx_requests: u64,
    pub suspicious_requests: u64,
    pub suspicious_unique_paths: usize,
    pub top_scanner_ip: String,
    pub top_scanner_requests: u64,
    pub parse_errors: u64,
}

impl AccessLogSummary {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"enabled\":{},\"configured_files\":{},\"readable_files\":{},\"missing_files\":{},\"unreadable_files\":{},\"requests\":{},\"requests_per_second\":{:.6},\"unique_ips\":{},\"top_ip\":\"{}\",\"top_ip_requests\":{},\"top_ip_requests_per_second\":{:.6},\"status_4xx\":{},\"status_5xx\":{},\"top_ip_4xx\":\"{}\",\"top_ip_4xx_requests\":{},\"suspicious_requests\":{},\"suspicious_unique_paths\":{},\"top_scanner_ip\":\"{}\",\"top_scanner_requests\":{},\"parse_errors\":{}}}",
            self.enabled,
            self.configured_files,
            self.readable_files,
            self.missing_files,
            self.unreadable_files,
            self.requests,
            self.requests_per_second,
            self.unique_ips,
            json_escape(&self.top_ip),
            self.top_ip_requests,
            self.top_ip_requests_per_second,
            self.status_4xx,
            self.status_5xx,
            json_escape(&self.top_ip_4xx),
            self.top_ip_4xx_requests,
            self.suspicious_requests,
            self.suspicious_unique_paths,
            json_escape(&self.top_scanner_ip),
            self.top_scanner_requests,
            self.parse_errors,
        )
    }

    pub fn to_sources_json(&self) -> String {
        if !self.enabled {
            return "[]".to_string();
        }
        format!(
            "[{{\"label\":\"宿主机 HTTP 日志\",\"enabled\":true,\"configured_files\":{},\"readable_files\":{},\"missing_files\":{},\"unreadable_files\":{},\"requests\":{},\"requests_per_second\":{:.6},\"unique_ips\":{},\"top_ip\":\"{}\",\"top_ip_requests\":{},\"top_ip_requests_per_second\":{:.6},\"status_4xx\":{},\"status_5xx\":{},\"top_ip_4xx\":\"{}\",\"top_ip_4xx_requests\":{},\"suspicious_requests\":{},\"suspicious_unique_paths\":{},\"top_scanner_ip\":\"{}\",\"top_scanner_requests\":{},\"parse_errors\":{}}}]",
            self.configured_files,
            self.readable_files,
            self.missing_files,
            self.unreadable_files,
            self.requests,
            self.requests_per_second,
            self.unique_ips,
            json_escape(&self.top_ip),
            self.top_ip_requests,
            self.top_ip_requests_per_second,
            self.status_4xx,
            self.status_5xx,
            json_escape(&self.top_ip_4xx),
            self.top_ip_4xx_requests,
            self.suspicious_requests,
            self.suspicious_unique_paths,
            json_escape(&self.top_scanner_ip),
            self.top_scanner_requests,
            self.parse_errors,
        )
    }
}

/// Parses either JSON (Caddy/Nginx JSON) or Combined/Common HTTP access log lines.
pub fn parse_access_log_line(line: &str) -> Option<AccessLogEvent> {
    let text = line.trim();
    if text.is_empty() {
        return None;
    }
    if text.starts_with('{') {
        if let Ok(root) = actions::parse_json(text) {
            let req = root
                .get("request")
                .filter(|v| v.as_object().is_some())
                .unwrap_or(&root);
            let remote_ip = req
                .get("client_ip")
                .and_then(|v| v.as_str())
                .or_else(|| req.get("remote_ip").and_then(|v| v.as_str()))
                .or_else(|| req.get("remote_addr").and_then(|v| v.as_str()))
                .or_else(|| root.get("remote_addr").and_then(|v| v.as_str()))
                .unwrap_or("")
                .trim();
            let status_u64 = root
                .get("status")
                .and_then(|v| v.as_u64())
                .or_else(|| req.get("status").and_then(|v| v.as_u64()))
                .unwrap_or(0);
            if !remote_ip.is_empty() && (100..=599).contains(&status_u64) {
                let method = req
                    .get("method")
                    .and_then(|v| v.as_str())
                    .or_else(|| root.get("request_method").and_then(|v| v.as_str()))
                    .unwrap_or("")
                    .to_string();
                let uri = req
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .or_else(|| root.get("request_uri").and_then(|v| v.as_str()))
                    .unwrap_or("")
                    .to_string();
                return Some(AccessLogEvent {
                    ip: remote_ip.to_string(),
                    status: status_u64 as u16,
                    method,
                    uri,
                });
            }
        }
        return None;
    }

    let first_ws = text.find(|c: char| c.is_ascii_whitespace())?;
    let remote_ip = &text[..first_ws];
    if remote_ip.is_empty() {
        return None;
    }
    let q1 = text[first_ws..].find('"')? + first_ws;
    let rest_after_q1 = &text[q1 + 1..];
    let q2_rel = rest_after_q1.find('"')?;
    let request_line = &rest_after_q1[..q2_rel];
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let uri = parts.next()?;
    let _proto = parts.next()?;
    let after_q2 = rest_after_q1[q2_rel + 1..].trim_start();
    let status_token = after_q2.split_whitespace().next()?;
    if status_token.len() != 3 || !status_token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let status: u16 = status_token.parse().ok()?;
    if !(100..=599).contains(&status) {
        return None;
    }
    Some(AccessLogEvent {
        ip: remote_ip.to_string(),
        status,
        method: method.to_string(),
        uri: uri.to_string(),
    })
}

fn wildcard_matches(pattern: &str, candidate: &str) -> bool {
    let p = pattern.as_bytes();
    let s = candidate.as_bytes();
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star_idx, mut match_idx) = (None, 0usize);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_idx = Some(pi);
            match_idx = si;
            pi += 1;
        } else if let Some(star) = star_idx {
            pi = star + 1;
            match_idx += 1;
            si = match_idx;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

fn expand_access_log_globs(patterns: &[String]) -> (Vec<String>, usize) {
    let mut expanded = Vec::new();
    let mut missing = 0usize;
    for raw in patterns {
        if raw.contains('*') || raw.contains('?') {
            let p = Path::new(raw);
            let Some(parent) = p.parent() else {
                missing += 1;
                continue;
            };
            let Some(file_pat) = p.file_name().and_then(|s| s.to_str()) else {
                missing += 1;
                continue;
            };
            let Ok(entries) = fs::read_dir(parent) else {
                missing += 1;
                continue;
            };
            let mut matched: Vec<String> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let name = e.file_name();
                    let name_str = name.to_str()?;
                    if wildcard_matches(file_pat, name_str) && e.path().is_file() {
                        Some(e.path().to_string_lossy().into_owned())
                    } else {
                        None
                    }
                })
                .collect();
            matched.sort();
            if matched.is_empty() {
                missing += 1;
            } else {
                expanded.extend(matched);
            }
        } else {
            expanded.push(raw.clone());
        }
    }
    (expanded, missing)
}

#[cfg(unix)]
fn file_inode(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(not(unix))]
fn file_inode(_meta: &fs::Metadata) -> u64 {
    0
}

fn increment_count(map: &mut HashMap<String, u64>, key: &str) {
    if let Some(v) = map.get_mut(key) {
        *v += 1;
    } else {
        map.insert(key.to_string(), 1);
    }
}

fn top_entry(map: &HashMap<String, u64>) -> (String, u64) {
    let mut best_k = String::new();
    let mut best_v = 0u64;
    for (k, &v) in map {
        if v > best_v {
            best_k = k.clone();
            best_v = v;
        }
    }
    (best_k, best_v)
}

/// Incrementally tails configured HTTP access logs while tracking inodes and byte offsets.
pub fn collect_access_log_stats(
    paths: &[String],
    max_bytes: usize,
    scan_patterns: &[String],
    interval_seconds: f64,
    states: &mut HashMap<String, AccessLogCursor>,
) -> AccessLogSummary {
    let mut summary = AccessLogSummary {
        enabled: !paths.is_empty(),
        configured_files: paths.len(),
        ..AccessLogSummary::default()
    };
    if paths.is_empty() {
        return summary;
    }

    let (expanded_paths, glob_missing) = expand_access_log_globs(paths);
    if !expanded_paths.is_empty() {
        summary.configured_files = expanded_paths.len();
    }
    summary.missing_files += glob_missing;

    let mut ip_counts: HashMap<String, u64> = HashMap::new();
    let mut ip_4xx_counts: HashMap<String, u64> = HashMap::new();
    let mut scanner_ip_counts: HashMap<String, u64> = HashMap::new();
    let mut suspicious_paths_seen: BTreeSet<String> = BTreeSet::new();
    let mut tail_lines: Vec<String> = Vec::new();
    let cap_bytes = max_bytes.max(MIN_ACCESS_LOG_MAX_BYTES) as u64;

    for path in expanded_paths {
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                summary.missing_files += 1;
                continue;
            }
            Err(_) => {
                summary.unreadable_files += 1;
                continue;
            }
        };
        let inode = file_inode(&meta);
        let file_size = meta.len();
        let Some(prev) = states.get(&path).copied() else {
            states.insert(
                path,
                AccessLogCursor {
                    inode,
                    offset: file_size,
                },
            );
            summary.readable_files += 1;
            continue;
        };

        let mut prev_offset = prev.offset;
        if prev.inode != inode || prev_offset > file_size {
            prev_offset = 0;
        }
        let start = prev_offset.max(file_size.saturating_sub(cap_bytes));
        let skip_partial = start > prev_offset;

        let Ok(mut file) = File::open(&path) else {
            summary.unreadable_files += 1;
            continue;
        };
        if file.seek(SeekFrom::Start(start)).is_err() {
            summary.unreadable_files += 1;
            continue;
        }
        let mut reader = BufReader::new(file);
        if skip_partial {
            let mut discard = String::new();
            let _ = reader.read_line(&mut discard);
        }
        tail_lines.clear();
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if tail_lines.len() >= 20_000 {
                        tail_lines.remove(0);
                    }
                    tail_lines.push(line.clone());
                }
                Err(_) => break,
            }
        }
        let new_offset = reader.stream_position().unwrap_or(file_size);
        states.insert(
            path,
            AccessLogCursor {
                inode,
                offset: new_offset,
            },
        );
        summary.readable_files += 1;

        for raw_line in &tail_lines {
            let Some(event) = parse_access_log_line(raw_line) else {
                summary.parse_errors += 1;
                continue;
            };
            summary.requests += 1;
            if !event.ip.is_empty() {
                increment_count(&mut ip_counts, &event.ip);
            }
            if (400..500).contains(&event.status) {
                summary.status_4xx += 1;
                if !event.ip.is_empty() && matches!(event.status, 401 | 403 | 429) {
                    increment_count(&mut ip_4xx_counts, &event.ip);
                }
            } else if event.status >= 500 {
                summary.status_5xx += 1;
            }
            if !event.uri.is_empty() {
                let uri_lower = event.uri.to_ascii_lowercase();
                if scan_patterns.iter().any(|p| uri_lower.contains(p.as_str())) {
                    let clean_path = event.uri.split('?').next().unwrap_or("");
                    let truncated: String = clean_path.chars().take(500).collect();
                    suspicious_paths_seen.insert(truncated);
                    if !event.ip.is_empty() {
                        increment_count(&mut scanner_ip_counts, &event.ip);
                    }
                }
            }
        }
    }

    let (top_ip, top_ip_requests) = top_entry(&ip_counts);
    let (top_ip_4xx, top_ip_4xx_requests) = top_entry(&ip_4xx_counts);
    let (top_scanner_ip, top_scanner_requests) = top_entry(&scanner_ip_counts);
    let interval = interval_seconds.max(1.0);

    summary.requests_per_second = summary.requests as f64 / interval;
    summary.unique_ips = ip_counts.len();
    summary.top_ip = top_ip;
    summary.top_ip_requests = top_ip_requests;
    summary.top_ip_requests_per_second = top_ip_requests as f64 / interval;
    summary.top_ip_4xx = top_ip_4xx;
    summary.top_ip_4xx_requests = top_ip_4xx_requests;
    summary.suspicious_requests = scanner_ip_counts.values().copied().sum();
    summary.suspicious_unique_paths = suspicious_paths_seen.len();
    summary.top_scanner_ip = top_scanner_ip;
    summary.top_scanner_requests = top_scanner_requests;
    summary
}

fn normalize_arch(arch: &str) -> &str {
    match arch {
        "x86_64" | "amd64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        other => other,
    }
}

fn read_managed_upgrade_result_json(path: &Path) -> String {
    let Ok(raw) = fs::read_to_string(path) else {
        return "{}".to_string();
    };
    let trimmed = raw.trim();
    if trimmed.starts_with('{') && actions::parse_json(trimmed).is_ok() {
        trimmed.to_string()
    } else {
        "{}".to_string()
    }
}

fn build_operations_health_json(
    security_enabled: bool,
    runtime_empty: bool,
    container_count: usize,
    access: &AccessLogSummary,
) -> String {
    let log_status = if access.readable_files == 0 {
        if !access.enabled {
            "not_configured"
        } else {
            "missing"
        }
    } else if access.parse_errors > 0 && access.requests == 0 {
        "parse_error"
    } else if access.requests > 0 {
        "healthy"
    } else {
        "idle"
    };
    let net_status = if container_count > 0 { "healthy" } else { "idle" };
    let sec_status = if security_enabled {
        "healthy"
    } else if runtime_empty && container_count == 0 {
        "not_applicable"
    } else {
        "disabled"
    };
    format!(
        "[{{\"source\":\"http_logs\",\"status\":\"{}\",\"details\":{{\"readable_files\":{},\"missing_files\":{},\"unreadable_files\":{},\"parse_errors\":{},\"requests\":{}}},\"guidance\":\"使用日志向导发现路径，确认 JSON/combined 格式和 Agent 读取权限\"}},{{\"source\":\"network_counters\",\"status\":\"{}\",\"details\":{{\"containers\":{},\"available\":{},\"notice_only\":0}},\"guidance\":\"检查运行时统计接口、/proc 网络命名空间权限；首采样不产生速率\"}},{{\"source\":\"security\",\"status\":\"{}\",\"guidance\":\"无容器运行时的探针节点不适用容器安全采样；其他节点请启用 SECURITY_MONITOR_ENABLED\"}}]",
        log_status,
        access.readable_files,
        access.missing_files,
        access.unreadable_files,
        access.parse_errors,
        access.requests,
        net_status,
        container_count,
        container_count,
        sec_status,
    )
}

fn parse_service_target(kind: &str, target: &str) -> Result<(String, u16, String, String), &'static str> {
    if target.is_empty() || target.len() > 512 {
        return Err("invalid probe target");
    }
    let Some((scheme_raw, rest)) = target.split_once("://") else {
        return Err("invalid probe target");
    };
    let scheme = scheme_raw.to_ascii_lowercase();
    if !matches!((kind, scheme.as_str()), ("tcp", "tcp") | ("http", "http") | ("http", "https")) {
        return Err("invalid probe target");
    }
    let (authority, path_part) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    if authority.contains('@') || authority.is_empty() {
        return Err("invalid probe target");
    }
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let Some((h, after)) = stripped.split_once(']') else {
            return Err("invalid probe target");
        };
        let port = if let Some(pstr) = after.strip_prefix(':') {
            pstr.parse::<u16>().map_err(|_| "invalid probe target")?
        } else {
            default_scheme_port(&scheme)
        };
        (h.to_string(), port)
    } else if let Some((h, pstr)) = authority.rsplit_once(':') {
        let port = pstr.parse::<u16>().map_err(|_| "invalid probe target")?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), default_scheme_port(&scheme))
    };
    if host.is_empty() || port == 0 {
        return Err("invalid probe target");
    }
    Ok((host, port, scheme, path_part.to_string()))
}

fn default_scheme_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "http" => 80,
        _ => 0,
    }
}

pub fn probe_operations_services_json(services: &[ServiceProbeSpec], checked_at: u64) -> String {
    if services.is_empty() {
        return "[]".to_string();
    }
    let mut results = Vec::with_capacity(services.len().min(20));
    for svc in services.iter().take(20) {
        let started = Instant::now();
        let probe_res: Result<(Option<u16>, f64), String> = (|| {
            let (host, port, scheme, path) =
                parse_service_target(&svc.kind, &svc.target).map_err(|e| e.to_string())?;
            let addrs: Vec<_> = (host.as_str(), port)
                .to_socket_addrs()
                .map_err(|e| format!("resolve error: {e}"))?
                .collect();
            let addr = addrs.into_iter().next().ok_or_else(|| "resolve empty".to_string())?;
            let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("connect error: {e}"))?;
            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
            let mut http_status: Option<u16> = None;
            if svc.kind == "http" && scheme == "http" {
                let req_str = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Narwhal-Agent-Rust/1.0\r\nConnection: close\r\n\r\n",
                    path, host
                );
                let _ = stream.write_all(req_str.as_bytes());
                let mut buf = [0u8; 256];
                if let Ok(n) = std::io::Read::read(&mut stream, &mut buf) {
                    let head = String::from_utf8_lossy(&buf[..n]);
                    if let Some(code_str) = head
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                    {
                        if let Ok(code) = code_str.parse::<u16>() {
                            http_status = Some(code);
                            if !(200..400).contains(&code) {
                                return Err(format!("HTTP {code}"));
                            }
                        }
                    }
                }
            }
            let ms = (started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
            Ok((http_status, ms))
        })();

        match probe_res {
            Ok((http_status, latency_ms)) => {
                let warn_ms = svc.latency_warning_ms.max(1) as f64;
                let status = if latency_ms >= warn_ms {
                    "warning"
                } else {
                    "healthy"
                };
                let http_field = match http_status {
                    Some(code) => format!(",\"http_status\":{code}"),
                    None => String::new(),
                };
                results.push(format!(
                    "{{\"id\":\"{}\",\"status\":\"{}\",\"latency_ms\":{:.1},\"checked_at\":{}{}}}",
                    json_escape(&svc.id),
                    status,
                    latency_ms,
                    checked_at,
                    http_field
                ));
            }
            Err(err_msg) => {
                let truncated: String = err_msg.chars().take(150).collect();
                results.push(format!(
                    "{{\"id\":\"{}\",\"status\":\"failed\",\"latency_ms\":null,\"checked_at\":{},\"error\":\"{}\"}}",
                    json_escape(&svc.id),
                    checked_at,
                    json_escape(&truncated)
                ));
            }
        }
    }
    format!("[{}]", results.join(","))
}

impl AgentState {
    pub fn configure_operations_services(&mut self, poll_body: &str) {
        let Ok(root) = actions::parse_json(poll_body) else {
            return;
        };
        let Some(services) = root
            .get("operations")
            .and_then(|o| o.get("services"))
            .and_then(|v| v.as_array())
        else {
            return;
        };
        let mut parsed = Vec::new();
        for svc in services.iter().take(20) {
            let Some(id) = svc.get("id").and_then(|v| v.as_str()) else {
                continue;
            };
            let kind = svc.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let target = svc.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let warn = svc
                .get("latency_warning_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(1000);
            parsed.push(ServiceProbeSpec {
                id: id.to_string(),
                kind: kind.to_string(),
                target: target.to_string(),
                latency_warning_ms: warn,
            });
        }
        self.operations_services = parsed;
    }

    pub fn configure_operations_bandwidth_and_cleanup(
        &mut self,
        poll_body: &str,
        config: &Config,
    ) {
        let Ok(root) = actions::parse_json(poll_body) else {
            return;
        };
        let Some(ops) = root.get("operations").and_then(actions::JsonValue::as_object) else {
            return;
        };
        if let Some(dc_val) = ops.get("disk_cleanup") {
            if let Ok(policy) = app_guard::disk_cleanup::validate_cleanup_policy(
                &dc_val.to_json(),
                Some(config.node_id.as_str()),
            ) {
                self.cleanup_policy = policy;
            }
        }
        if let Some(bw_val) = ops.get("bandwidth_limits") {
            if let Some(bw_obj) = bw_val.as_object() {
                let now = current_unix_ts();
                let rev = bw_obj
                    .get("revision")
                    .and_then(actions::JsonValue::as_i64)
                    .unwrap_or(0);
                let limits_empty = bw_obj
                    .get("limits")
                    .and_then(actions::JsonValue::as_array)
                    .is_none_or(|a| a.is_empty());
                let auto_enabled = bw_obj
                    .get("auto_throttle")
                    .and_then(actions::JsonValue::as_object)
                    .and_then(|o| o.get("enabled"))
                    .and_then(actions::JsonValue::as_bool)
                    .unwrap_or(false);
                let rev_changed = rev != self.last_bandwidth_revision;
                let should_reconcile = if rev_changed {
                    true
                } else if limits_empty && !auto_enabled {
                    let persisted = tc_guard::read_state(&self.bandwidth_state_path);
                    !persisted.entries.is_empty()
                } else {
                    now.saturating_sub(self.last_bandwidth_reconcile_ts) >= 60
                };
                if should_reconcile {
                    let bridge_inventory = if limits_empty && !auto_enabled {
                        Vec::new()
                    } else {
                        collect_tc_bridge_inventory(now, &self.last_containers)
                    };
                    let _ = tc_guard::reconcile_live_samples(
                        &bw_val.to_json(),
                        &config.host_id,
                        &config.node_id,
                        &self.last_containers,
                        &self.bandwidth_state_path,
                        &self.last_traffic_samples,
                        now,
                        self.last_sample_interval_secs.max(1),
                        &bridge_inventory,
                    );
                    self.last_bandwidth_revision = rev;
                    self.last_bandwidth_reconcile_ts = now;
                }
            }
        }
    }

    fn build_disk_cleanup_summary_json(&self, _timestamp: u64) -> String {
        let available = app_guard::disk_cleanup::live_disk_cleanup_available();
        let disk_json = if available {
            app_guard::disk_cleanup::host_disk_usage_json(Path::new("/"))
        } else {
            "{}".to_string()
        };
        let running = self.disk_cleanup_running.load(Ordering::SeqCst);
        let runs_json = if available || self.cleanup_journal_path != Path::new(app_guard::disk_cleanup::DEFAULT_STATE_PATH) {
            match app_guard::disk_cleanup::read_cleanup_journal_readonly(&self.cleanup_journal_path)
            {
                Ok(journal) => {
                    let start = journal.runs.len().saturating_sub(10);
                    let encoded: Vec<String> = journal.runs[start..]
                        .iter()
                        .map(app_guard::disk_cleanup::CleanupRunRecord::to_json)
                        .collect();
                    format!("[{}]", encoded.join(","))
                }
                Err(_) => "[]".to_string(),
            }
        } else {
            "[]".to_string()
        };
        format!(
            "{{\"available\":{},\"policy\":{},\"disk\":{},\"running\":{},\"runs\":{}}}",
            available,
            self.cleanup_policy.to_json(),
            disk_json,
            running,
            runs_json
        )
    }
}

fn collect_tc_bridge_inventory(
    timestamp: u64,
    containers: &[ContainerSample],
) -> Vec<tc_guard::BridgeInterfaceInput> {
    let raw = host_audit::collect_interface_inventory_json(timestamp, containers);
    let Ok(val) = actions::parse_json(&raw) else {
        return Vec::new();
    };
    let Some(ifaces) = val.get("interfaces").and_then(actions::JsonValue::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(ifaces.len());
    for item in ifaces {
        let Some(name) = item.get("name").and_then(actions::JsonValue::as_str) else {
            continue;
        };
        let kind = item
            .get("kind")
            .and_then(actions::JsonValue::as_str)
            .unwrap_or("")
            .to_string();
        let runtimes = item
            .get("runtimes")
            .and_then(actions::JsonValue::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        out.push(tc_guard::BridgeInterfaceInput {
            name: name.to_string(),
            kind,
            runtimes,
        });
    }
    out
}

fn collect_incus_runtime_health(
    config: &Config,
    timestamp: u64,
) -> Option<app_guard::incus_health::IncusSnapshotReport> {
    let runtimes_lower = config.container_runtimes.trim().to_ascii_lowercase();
    let requested: BTreeSet<&str> = runtimes_lower
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let incus_enabled = requested.is_empty()
        || requested.contains("auto")
        || requested.contains("incus");
    if !incus_enabled {
        return None;
    }
    let auto_only = requested.is_empty() || requested.contains("auto");
    if auto_only && !binary_exists_in_path("incus") {
        return None;
    }
    let proj = if config.incus_project.trim().is_empty() {
        "all"
    } else {
        config.incus_project.trim()
    };
    let all_projects = matches!(proj.to_ascii_lowercase().as_str(), "all" | "*");
    let inst_args: &[&str] = if all_projects {
        &["list", "--all-projects", "type=container", "--format=json"]
    } else {
        &["list", "type=container", "--format=json"]
    };
    let op_args: &[&str] = if all_projects {
        &["operation", "list", "--all-projects", "--format=json"]
    } else {
        &["operation", "list", "--format=json"]
    };
    let cfg = app_guard::incus_health::IncusHealthConfig::from_env();
    let inst_scan = actions::run_incus_cli_scan(proj, inst_args, cfg.command_timeout_seconds);
    let op_scan = actions::run_incus_cli_scan(proj, op_args, cfg.command_timeout_seconds);
    Some(app_guard::incus_health::build_incus_snapshot(
        &inst_scan,
        &op_scan,
        proj,
        timestamp as f64,
        &cfg,
    ))
}

fn strip_json_array_inner(arr_json: &str) -> &str {
    let trimmed = arr_json.trim();
    if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
        trimmed[1..trimmed.len() - 1].trim()
    } else {
        ""
    }
}

fn merge_json_arrays(first: &str, second: &str) -> String {
    let a = strip_json_array_inner(first);
    let b = strip_json_array_inner(second);
    match (a.is_empty(), b.is_empty()) {
        (true, true) => "[]".to_string(),
        (false, true) => format!("[{a}]"),
        (true, false) => format!("[{b}]"),
        (false, false) => format!("[{a},{b}]"),
    }
}

fn append_json_object_to_array(arr_json: &str, obj_json: &str) -> String {
    let inner = strip_json_array_inner(arr_json);
    let item = obj_json.trim();
    if item.is_empty() {
        return if inner.is_empty() {
            "[]".to_string()
        } else {
            format!("[{inner}]")
        };
    }
    if inner.is_empty() {
        format!("[{item}]")
    } else {
        format!("[{inner},{item}]")
    }
}

pub fn extract_proc_infos_from_snapshot(proc_snapshot_json: &str) -> Vec<ProcInfo> {
    let Ok(root) = actions::parse_json(proc_snapshot_json) else {
        return Vec::new();
    };
    let Some(items) = root.get("items").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(pid) = item
            .get("pid")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
        else {
            continue;
        };
        let ppid = item
            .get("ppid")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(0);
        let cpu_percent = item
            .get("cpu_percent")
            .and_then(|v| v.as_f64())
            .or_else(|| item.get("lifetime_cpu_percent").and_then(|v| v.as_f64()))
            .unwrap_or(0.0);
        let rss_bytes = item.get("rss_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let process = item
            .get("process")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let command = item
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        out.push(ProcInfo {
            pid,
            ppid,
            cpu_percent,
            rss_bytes,
            process,
            command,
        });
    }
    out
}

pub(crate) fn container_guard_key(container: &ContainerSample) -> String {
    if !container.stable_id.is_empty() {
        container.stable_id.clone()
    } else if !container.id.is_empty() {
        container.id.clone()
    } else {
        container.name.clone()
    }
}

#[cfg(test)]
fn extract_container_guard_samples(
    containers: &[ContainerSample],
    logical_cpus: u32,
) -> (Vec<MemoryContainerSample>, Vec<CpuContainerSample>) {
    let mut empty_prev = HashMap::new();
    extract_container_guard_samples_with_cpu_delta(&mut empty_prev, containers, 0, logical_cpus)
}

#[cfg(test)]
fn extract_container_guard_samples_with_cpu_delta(
    prev_container_cpu: &mut HashMap<String, (u64, u64)>,
    containers: &[ContainerSample],
    timestamp: u64,
    logical_cpus: u32,
) -> (Vec<MemoryContainerSample>, Vec<CpuContainerSample>) {
    let (mem_samples, cpu_samples, _) = extract_container_guard_samples_and_metrics(
        prev_container_cpu,
        containers,
        timestamp,
        logical_cpus,
        None,
    );
    (mem_samples, cpu_samples)
}

fn extract_container_guard_samples_and_metrics(
    prev_container_cpu: &mut HashMap<String, (u64, u64)>,
    containers: &[ContainerSample],
    timestamp: u64,
    logical_cpus: u32,
    psi_roots: Option<(&Path, &Path)>,
) -> (
    Vec<MemoryContainerSample>,
    Vec<CpuContainerSample>,
    HashMap<String, ContainerMetricsSummary>,
) {
    let default_cpus = logical_cpus.max(1) as f64;
    let mut mem_samples = Vec::new();
    let mut cpu_samples = Vec::new();
    let mut metrics_by_key = HashMap::with_capacity(containers.len());
    let mut next_cpu: HashMap<String, (u64, u64)> = HashMap::with_capacity(containers.len());

    for c in containers {
        let key = container_guard_key(c);
        if key.is_empty() {
            continue;
        }
        let cg_val = c
            .cgroup_metrics_json
            .as_deref()
            .and_then(|s| actions::parse_json(s).ok());
        let pm_val = c
            .pid_metrics_json
            .as_deref()
            .and_then(|s| actions::parse_json(s).ok());
        let st_val = c
            .socket_tables_json
            .as_deref()
            .and_then(|s| actions::parse_json(s).ok());

        let cg_mem = cg_val.as_ref().and_then(|v| v.get("memory"));
        let cg_current = cg_mem
            .and_then(|m| m.get("current_bytes").or_else(|| m.get("current")))
            .and_then(|v| v.as_u64());
        let cg_max = cg_mem
            .and_then(|m| m.get("max_bytes").or_else(|| m.get("max")))
            .and_then(|v| v.as_u64());
        let pm_mem = pm_val
            .as_ref()
            .and_then(|v| v.get("mem_bytes"))
            .and_then(|v| v.as_u64());

        let mem_bytes = cg_current.or(pm_mem).unwrap_or(0);
        let mem_limit_bytes = cg_max.unwrap_or(0);
        let mem_percent = if mem_limit_bytes > 0 {
            (mem_bytes as f64 * 100.0) / mem_limit_bytes as f64
        } else {
            0.0
        };

        if let Some(current_bytes) = cg_current.or(pm_mem) {
            let (original_high_bytes, container_psi) = match psi_roots {
                Some((proc_root, cgroup_root)) => (
                    resource_guard_exec::read_container_memory_high(proc_root, cgroup_root, c),
                    resource_guard_exec::read_container_memory_psi(proc_root, cgroup_root, c),
                ),
                None => (None, PsiSample::default()),
            };
            mem_samples.push(MemoryContainerSample {
                key: key.clone(),
                current_bytes,
                max_bytes: cg_max,
                original_high_bytes,
                container_psi,
            });
        }

        let quota_cpus = cg_val
            .as_ref()
            .and_then(|v| v.get("quota_cpus").and_then(|q| q.as_f64()))
            .or_else(|| {
                let cpu_max = cg_val.as_ref()?.get("cpu_max")?;
                let quota = cpu_max.get("quota_usec")?.as_u64()?;
                let period = cpu_max.get("period_usec")?.as_u64()?;
                if quota > 0 && period > 0 {
                    Some(quota as f64 / period as f64)
                } else {
                    None
                }
            })
            .filter(|q| q.is_finite() && *q > 0.0);

        let usage_usec = cg_val
            .as_ref()
            .and_then(|v| v.get("cpu_stat").or_else(|| v.get("cpu")))
            .and_then(|s| s.get("usage_usec"))
            .and_then(|u| u.as_u64());

        let delta_cpu_percent = usage_usec.and_then(|curr_usec| {
            next_cpu.insert(key.clone(), (timestamp, curr_usec));
            let &(prev_ts, prev_usec) = prev_container_cpu.get(&key)?;
            if timestamp > prev_ts && curr_usec >= prev_usec {
                let dt_usec = (timestamp - prev_ts) as f64 * 1_000_000.0;
                Some(((curr_usec - prev_usec) as f64 / dt_usec) * 100.0)
            } else {
                None
            }
        });

        let cpu_percent = delta_cpu_percent
            .or_else(|| {
                pm_val
                    .as_ref()
                    .and_then(|v| v.get("cpu_percent"))
                    .and_then(|v| v.as_f64())
            })
            .or_else(|| {
                cg_val
                    .as_ref()
                    .and_then(|v| v.get("cpu_percent"))
                    .and_then(|v| v.as_f64())
            });

        let effective_cpus = quota_cpus.unwrap_or(default_cpus);
        let cgroup_cpu_psi = psi_roots.and_then(|(proc_root, cgroup_root)| {
            cpu_guard_exec::read_container_cpu_psi_avg10(proc_root, cgroup_root, c)
        });
        let conn_count = st_val
            .as_ref()
            .map(|st| {
                st.get("tcp_established").and_then(|v| v.as_u64()).unwrap_or(0)
                    + st.get("tcp_time_wait").and_then(|v| v.as_u64()).unwrap_or(0)
                    + st.get("syn_sent_count").and_then(|v| v.as_u64()).unwrap_or(0)
                    + st.get("syn_recv_count").and_then(|v| v.as_u64()).unwrap_or(0)
            })
            .unwrap_or(0);

        metrics_by_key.insert(
            key.clone(),
            ContainerMetricsSummary {
                cpu_percent: cpu_percent.filter(|v| v.is_finite() && *v >= 0.0).unwrap_or(0.0),
                cpu_effective_cpus: effective_cpus,
                mem_bytes,
                mem_limit_bytes,
                mem_percent,
                net_rx_bps: 0.0,
                net_tx_bps: 0.0,
                conn_count,
            },
        );

        cpu_samples.push(CpuContainerSample {
            key,
            cpu_percent,
            effective_cpus,
            cgroup_cpu_psi_some_avg10: cgroup_cpu_psi,
        });
    }

    *prev_container_cpu = next_cpu;
    (mem_samples, cpu_samples, metrics_by_key)
}

pub fn aggregate_socket_abuse_from_containers(
    containers: &[ContainerSample],
    evaluated_at: u64,
) -> SocketAbuseInput {
    let mut input = SocketAbuseInput {
        evaluated_at,
        ..SocketAbuseInput::default()
    };
    for c in containers {
        let Some(ref raw) = c.socket_tables_json else {
            continue;
        };
        let Ok(st) = actions::parse_json(raw) else {
            continue;
        };
        let est = st
            .get("tcp_established")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let tw = st
            .get("tcp_time_wait")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let syn_sent = st
            .get("tcp_syn_sent")
            .or_else(|| st.get("syn_sent_count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let syn_recv = st
            .get("tcp_syn_recv")
            .or_else(|| st.get("syn_recv_count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let udp = st
            .get("udp_sockets")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let conn = st
            .get("conn_count")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| {
                est.saturating_add(tw)
                    .saturating_add(syn_sent)
                    .saturating_add(syn_recv)
                    .saturating_add(udp)
            });

        input.tcp_established = input.tcp_established.saturating_add(est);
        input.tcp_time_wait = input.tcp_time_wait.saturating_add(tw);
        input.tcp_syn_sent = input.tcp_syn_sent.saturating_add(syn_sent);
        input.tcp_syn_recv = input.tcp_syn_recv.saturating_add(syn_recv);
        input.udp_sockets = input.udp_sockets.saturating_add(udp);
        input.conn_count = input.conn_count.saturating_add(conn);

        if st.get("available").and_then(|v| v.as_bool()) == Some(true)
            || est > 0
            || tw > 0
            || syn_sent > 0
            || syn_recv > 0
        {
            input.has_tcp_states = true;
        }
    }
    input
}

fn read_psi_sample(path: &Path) -> PsiSample {
    match read_psi(path) {
        PsiStatus::Ready { some: Some(s), .. } => PsiSample::new(Some(s.avg10), s.avg60),
        _ => PsiSample::default(),
    }
}

pub fn current_unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolledAction {
    pub id: i64,
    pub action_type: String,
}

/// Extract `{"id": ..., "action_type": "..."}` entries from `/api/v1/actions/poll` JSON response.
pub fn extract_polled_actions(body: &str) -> Vec<PolledAction> {
    let mut actions = Vec::new();
    let Some(actions_key) = body.find("\"actions\"") else {
        return actions;
    };
    let rest = &body[actions_key + "\"actions\"".len()..];
    let Some(bracket_start) = rest.find('[') else {
        return actions;
    };
    let arr_slice = &rest[bracket_start + 1..];
    let mut depth = 0usize;
    let mut obj_start: Option<usize> = None;
    let mut in_string = false;
    let mut escaped = false;

    for (idx, ch) in arr_slice.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '[' if depth == 0 => {}
            ']' if depth == 0 => break,
            '{' => {
                if depth == 0 {
                    obj_start = Some(idx);
                }
                depth += 1;
            }
            '}' => {
                if depth > 0 {
                    depth -= 1;
                    if depth == 0 {
                        if let Some(start) = obj_start.take() {
                            let obj = &arr_slice[start..=idx];
                            if let Some(id) = extract_json_i64(obj, "id") {
                                let action_type = extract_json_string(obj, "action_type")
                                    .unwrap_or_default();
                                actions.push(PolledAction { id, action_type });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    actions
}

fn extract_json_i64(obj: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{key}\"");
    let pos = obj.find(&pattern)?;
    let after_key = obj[pos + pattern.len()..].trim_start();
    let after_colon = after_key.strip_prefix(':')?.trim_start();
    let end = after_colon
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(after_colon.len());
    after_colon[..end].parse::<i64>().ok()
}

fn extract_json_string(obj: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let pos = obj.find(&pattern)?;
    let after_key = obj[pos + pattern.len()..].trim_start();
    let after_colon = after_key.strip_prefix(':')?.trim_start();
    let rest = after_colon.strip_prefix('"')?;
    let mut out = String::new();
    let mut escaped = false;
    for ch in rest.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(out);
        } else {
            out.push(ch);
        }
    }
    None
}

pub fn poll_actions_once(
    client: &TransportClient,
    config: &Config,
) -> Result<usize, TransportError> {
    let mut state = AgentState::new(config);
    let (count, _, _) = poll_actions_with_state(client, config, &mut state)?;
    Ok(count)
}

pub fn poll_actions_with_state(
    client: &TransportClient,
    config: &Config,
    state: &mut AgentState,
) -> Result<(usize, bool, bool), TransportError> {
    let gfw_caps = gfw_probe::route_capabilities_json(&state.proc_root);
    let poll_body = format!(
        "{{\"host_id\":\"{}\",\"node_id\":\"{}\",\"gfw_probe_capabilities\":{}}}",
        json_escape(&config.host_id),
        json_escape(&config.node_id),
        gfw_caps
    );
    let resp = client.post_json_signed_verified("/api/v1/actions/poll", poll_body.as_bytes())?;
    let body_str = String::from_utf8_lossy(&resp.body);
    state.configure_operations_services(&body_str);
    state.configure_operations_bandwidth_and_cleanup(&body_str, config);
    gfw_probe::handle_poll_gfw_probe(&body_str, &config.host_id, &config.node_id, client);

    if !state.disk_cleanup_recovered
        && app_guard::disk_cleanup::live_disk_cleanup_available()
        && !state.disk_cleanup_running.load(Ordering::SeqCst)
    {
        state.disk_cleanup_recovered = true;
        if let Ok(mut recovered) = app_guard::disk_cleanup::load_cleanup_journal(
            &state.cleanup_journal_path,
            current_unix_ts() as i64,
        ) {
            let _ = app_guard::disk_cleanup::save_cleanup_journal(
                &state.cleanup_journal_path,
                &mut recovered,
            );
        }
    }

    let requests = match actions::parse_poll_actions(&body_str) {
        Ok(reqs) => reqs,
        Err(_) => {
            deliver_finished_cleanup_runs(client, config, state)?;
            return Ok((0, false, false));
        }
    };
    let count = requests.len();
    let env_path = std::env::var("NARWHAL_CLIENT_ENV_FILE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ENV_FILE));
    let cleanup_containers: Vec<app_guard::disk_cleanup::CleanupContainerCandidate> = state
        .last_containers
        .iter()
        .map(|c| {
            let pid_start_ticks = c
                .pid
                .filter(|&p| p > 1)
                .and_then(|p| read_proc_start_ticks(&state.proc_root, p))
                .unwrap_or_default();
            app_guard::disk_cleanup::CleanupContainerCandidate {
                runtime: c.runtime.clone(),
                runtime_bin: c.runtime_bin.clone(),
                project: c.project.clone(),
                name: c.name.clone(),
                id: c.id.clone(),
                stable_id: c.stable_id.clone(),
                instance_id: c.instance_id.clone(),
                pid: c.pid.map(|p| p.to_string()).unwrap_or_default(),
                pid_start_ticks,
            }
        })
        .collect();
    let mut ctx = actions::ActionContext {
        node_id: config.node_id.clone(),
        env_file: env_path,
        configured_access_logs: config.security_access_log_paths.clone(),
        rescan_requested: false,
        restart_required: false,
        cleanup_journal_path: state.cleanup_journal_path.clone(),
        cleanup_policy: state.cleanup_policy,
        cleanup_containers,
        abuse_engine: state.abuse_engine.clone(),
        disk_cleanup_running: state.disk_cleanup_running.clone(),
        ..Default::default()
    };

    for req in &requests {
        let receipt = actions::execute_action_with_context(req, &mut ctx);
        let _ = actions::submit_action_receipt(client, &config.host_id, &config.node_id, &receipt)?;
    }
    deliver_finished_cleanup_runs(client, config, state)?;
    maybe_schedule_automatic_disk_cleanup(config, state, &ctx.cleanup_containers);
    if ctx.rescan_requested {
        state.host_audit_state.rescan_requested_at = current_unix_ts();
    }
    Ok((count, ctx.rescan_requested, ctx.restart_required))
}

fn maybe_schedule_automatic_disk_cleanup(
    config: &Config,
    state: &AgentState,
    containers: &[app_guard::disk_cleanup::CleanupContainerCandidate],
) {
    if !state.cleanup_policy.enabled
        || config.node_id.is_empty()
        || !app_guard::disk_cleanup::live_disk_cleanup_available()
        || state.disk_cleanup_running.load(Ordering::SeqCst)
    {
        return;
    }
    let Ok(quarantined) = actions::read_quarantined_identities(None) else {
        return;
    };
    let now_epoch = current_unix_ts() as i64;
    let Ok(Some(run_id)) = app_guard::disk_cleanup::stage_automatic_cleanup(
        &state.cleanup_journal_path,
        &state.cleanup_policy,
        &config.node_id,
        containers,
        &quarantined,
        now_epoch,
    ) else {
        return;
    };
    let journal_path = state.cleanup_journal_path.clone();
    let policy = state.cleanup_policy;
    let flag = state.disk_cleanup_running.clone();
    flag.store(true, Ordering::SeqCst);
    thread::spawn(move || {
        let _ = app_guard::disk_cleanup::execute_and_finalize_cleanup_run(
            &journal_path,
            &run_id,
            &policy,
            None,
            now_epoch,
        );
        flag.store(false, Ordering::SeqCst);
    });
}

fn read_proc_start_ticks(proc_root: &Path, pid: u32) -> Option<String> {
    let raw = fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let (_, after) = raw.rsplit_once(')')?;
    after.split_whitespace().nth(19).map(str::to_string)
}

fn deliver_finished_cleanup_runs(
    client: &TransportClient,
    config: &Config,
    state: &AgentState,
) -> Result<(), TransportError> {
    let custom_journal =
        state.cleanup_journal_path != Path::new(app_guard::disk_cleanup::DEFAULT_STATE_PATH);
    if !app_guard::disk_cleanup::live_disk_cleanup_available() && !custom_journal {
        return Ok(());
    }
    let Ok(journal) = app_guard::disk_cleanup::read_cleanup_journal_readonly(&state.cleanup_journal_path)
    else {
        return Ok(());
    };
    for run in &journal.runs {
        if run.action_id > 0
            && !run.delivered
            && run.node_id == config.node_id
            && run.status != "running"
        {
            let action_type = if run.mode == "clean" {
                "disk_cleanup_execute"
            } else {
                "disk_cleanup_scan"
            };
            let deleted: usize = run.items.iter().map(|i| i.deleted_files).sum();
            let msg = format!(
                "{{\"run_id\":\"{}\",\"status\":\"{}\",\"targets\":{},\"deleted_files\":{}}}",
                json_escape(&run.run_id),
                json_escape(&run.status),
                run.items.len(),
                deleted
            );
            let mut receipt = if matches!(run.status.as_str(), "scanned" | "succeeded") {
                actions::ActionReceipt::succeeded(run.action_id, action_type, msg)
            } else {
                actions::ActionReceipt::failed(run.action_id, action_type, msg)
            };
            receipt = receipt.with_cleanup_run(run.to_json());
            let _ = actions::submit_action_receipt(client, &config.host_id, &config.node_id, &receipt)?;
            let _ = app_guard::disk_cleanup::mark_cleanup_run_delivered(
                &state.cleanup_journal_path,
                &run.run_id,
            );
            break;
        }
    }
    Ok(())
}

pub fn deterministic_jitter_secs(node_id: &str, host_id: &str, max_jitter: u64) -> u64 {
    if max_jitter == 0 {
        return 0;
    }
    let key = if !node_id.is_empty() { node_id } else { host_id };
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in key.as_bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash % (max_jitter + 1)
}

impl AgentState {
    /// Lightweight fast-tick guard sampling (CPU/Memory/IO + delta baselines) without HTTP report serialization.
    pub fn sample_guards_tick(&mut self, config: &Config, timestamp: u64) -> (usize, usize, usize) {
        let dt = match self.last_sample_ts {
            Some(prev) if timestamp > prev => Some((timestamp - prev) as f64),
            _ => None,
        };
        self.last_sample_ts = Some(timestamp);

        let host_cpu_sample = self.sample_host_cpu();
        let host_mem_psi = read_psi_sample(&self.proc_root.join("pressure").join("memory"));
        let host_io_psi = read_psi_sample(&self.proc_root.join("pressure").join("io"))
            .effective_avg();
        let containers = discover_and_sample_containers(&config.container_runtimes);
        let (mem_samples, cpu_samples, _) = extract_container_guard_samples_and_metrics(
            &mut self.prev_container_cpu,
            &containers,
            timestamp,
            host_cpu_sample.logical_cpus,
            Some((&self.proc_root, &self.cgroup_root)),
        );
        let host_devices = self.sample_host_disks(dt);
        let io_samples = self.extract_container_io_samples(&containers, dt);
        let _ = self.compute_container_net_rates(&containers, dt);
        self.last_containers = containers.clone();

        let allow_new_limits = config.security_monitor_enabled;
        let allow_cpu_limits = allow_new_limits && cpu_guard_exec::cpu_auto_limit_enabled_from_env();
        let allow_mem_limits =
            allow_new_limits && resource_guard_exec::memory_auto_limit_enabled_from_env();
        let allow_io_limits =
            allow_new_limits && resource_guard_exec::io_auto_limit_enabled_from_env();
        let cpu_out = self
            .cpu_guard
            .observe(timestamp, &host_cpu_sample, &cpu_samples, allow_cpu_limits);
        self.cpu_guard_enforcer.execute_actions(
            &containers,
            &cpu_out.actions,
            &self.proc_root,
            &self.cgroup_root,
            timestamp,
        );
        let (_, mem_actions) =
            self.memory_guard
                .observe(timestamp, host_mem_psi, &mem_samples, allow_mem_limits);
        self.memory_guard_enforcer.execute_actions(
            &containers,
            &mem_actions,
            &self.proc_root,
            &self.cgroup_root,
            timestamp,
        );
        let (_, io_actions) = self.io_guard.observe(
            timestamp,
            host_cpu_sample.ready,
            &host_devices,
            host_io_psi,
            &io_samples,
            allow_io_limits,
        );
        self.io_guard_enforcer.execute_actions(
            &containers,
            &io_actions,
            &self.proc_root,
            &self.cgroup_root,
            timestamp,
        );
        (cpu_out.actions.len(), mem_actions.len(), io_actions.len())
    }
}

pub fn run_with_config(
    config: &Config,
    state: &mut AgentState,
    out: &mut dyn Write,
    stop: &AtomicBool,
) -> Result<i32, String> {
    if config.check_config {
        writeln!(out, "{}", config.sanitized_summary()).map_err(|e| e.to_string())?;
        return Ok(0);
    }

    if config.dry_run {
        let payload = state.build_report_json(config, current_unix_ts());
        writeln!(out, "{payload}").map_err(|e| e.to_string())?;
        return Ok(0);
    }

    let client = TransportClient::new(config.to_transport_config()).map_err(|e| e.to_string())?;

    if config.once {
        let payload = state.build_report_json(config, current_unix_ts());
        client
            .post_json_signed("/api/v1/report", payload.as_bytes())
            .map_err(|e| e.to_string())?;
        return Ok(0);
    }

    let report_delay = Duration::from_secs(config.report_interval.max(MIN_REPORT_INTERVAL));
    let poll_delay = Duration::from_secs(config.action_poll_interval.max(MIN_ACTION_POLL_INTERVAL));
    let guard_delay = Duration::from_secs(config.guard_interval.max(MIN_GUARD_INTERVAL));

    let max_jitter = (report_delay.as_secs() / 4).min(30);
    let jitter = Duration::from_secs(deterministic_jitter_secs(
        &config.node_id,
        &config.host_id,
        max_jitter,
    ));

    let now = Instant::now();
    let mut next_report = now + jitter;
    let mut next_action_poll = now + poll_delay;
    let mut next_guard_tick = now + guard_delay;

    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= next_report {
            let ts = current_unix_ts();
            let payload = state.build_report_json(config, ts);
            match client.post_json_signed("/api/v1/report", payload.as_bytes()) {
                Ok(resp) => {
                    let body_str = String::from_utf8_lossy(&resp.body);
                    if let Ok(parsed) = runtime_drivers::JsonVal::parse(body_str.trim()) {
                        if let Some(arr) = parsed.get("motd_states").and_then(|v| v.as_arr()) {
                            state.motd_states = arr.to_vec();
                        }
                        if let Some(sp) = parsed.get("security_policy") {
                            state.apply_dynamic_security_policy(sp);
                        }
                    }
                }
                Err(err) => {
                    let _ = writeln!(out, "report failed: {err}");
                }
            }
            state.run_security_guard_cycles(config, &client, ts);
            next_report = advance_deadline(next_report, report_delay, now);
            next_guard_tick = advance_deadline(now, guard_delay, now);
        } else if now >= next_guard_tick {
            let ts = current_unix_ts();
            let _ = state.sample_guards_tick(config, ts);
            state.run_security_guard_cycles(config, &client, ts);
            next_guard_tick = advance_deadline(next_guard_tick, guard_delay, now);
        }

        if now >= next_action_poll {
            match poll_actions_with_state(&client, config, state) {
                Ok((_, rescan_requested, restart_required)) => {
                    if restart_required {
                        return Ok(0);
                    }
                    if rescan_requested {
                        next_report = Instant::now();
                    }
                }
                Err(err) => {
                    let _ = writeln!(out, "action poll failed: {err}");
                }
            }
            next_action_poll = advance_deadline(next_action_poll, poll_delay, now);
        }

        if stop.load(Ordering::Relaxed) {
            break;
        }
        let earliest = next_report.min(next_action_poll).min(next_guard_tick);
        let sleep_for = earliest
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(1));
        if !sleep_for.is_zero() {
            thread::sleep(sleep_for);
        }
    }

    Ok(0)
}

fn advance_deadline(prev: Instant, period: Duration, now: Instant) -> Instant {
    let mut next = prev + period;
    if next <= now {
        next = now + period;
    }
    next
}

#[cfg(test)]
mod tests;
