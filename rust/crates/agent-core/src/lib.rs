#![forbid(unsafe_code)]

pub mod actions;

use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cgroup_probe::{collect_psi_snapshot, read_psi, PsiStatus};
use geoip_probe::lookup_countries;
use guard_core::security::{
    detect_suspicious_processes, evaluate_socket_abuse, ProcInfo, SocketAbuseInput,
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
use proc_probe::{collect_proc_snapshot_from_root, json_escape};
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
pub const DEFAULT_CONTAINER_RUNTIMES: &str = "auto";
pub const DEFAULT_DOCKER_MONITOR_MODE: &str = "notice";
pub const DEFAULT_INCUS_PROJECT: &str = "all";
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

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
    pub host_id: String,
    pub node_id: String,
    pub server_tls_ca_file: Option<PathBuf>,
    pub container_runtimes: String,
    pub docker_monitor_mode: String,
    pub incus_project: String,
    pub security_monitor_enabled: bool,
    pub once: bool,
    pub dry_run: bool,
    pub check_config: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: DEFAULT_SERVER_URL.to_string(),
            shared_secret: DEFAULT_SHARED_SECRET.to_string(),
            report_interval: DEFAULT_REPORT_INTERVAL,
            action_poll_interval: DEFAULT_ACTION_POLL_INTERVAL,
            host_id: detect_default_host_id(),
            node_id: String::new(),
            server_tls_ca_file: None,
            container_runtimes: DEFAULT_CONTAINER_RUNTIMES.to_string(),
            docker_monitor_mode: DEFAULT_DOCKER_MONITOR_MODE.to_string(),
            incus_project: DEFAULT_INCUS_PROJECT.to_string(),
            security_monitor_enabled: true,
            once: false,
            dry_run: false,
            check_config: false,
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
            json_escape(AGENT_VERSION),
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
    conntrack_path: PathBuf,
    geoip_db_path: Option<PathBuf>,
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
        let cpu_cfg = CpuGuardConfig {
            interval_seconds: interval,
            ..CpuGuardConfig::default()
        };
        let mem_cfg = MemoryGuardConfig {
            interval_seconds: interval,
            ..MemoryGuardConfig::default()
        };
        let io_cfg = IoGuardConfig {
            interval_seconds: interval,
            ..IoGuardConfig::default()
        };
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
            conntrack_path,
            geoip_db_path: None,
        }
    }

    pub fn with_geoip_db(mut self, db_path: Option<PathBuf>) -> Self {
        self.geoip_db_path = db_path;
        self
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
            collect_proc_snapshot_from_root(&self.proc_root, 1, 20_000, 100.0);

        let host_cpu_sample = self.sample_host_cpu();
        let host_mem_psi = read_psi_sample(&self.proc_root.join("pressure").join("memory"));
        let host_io_psi = read_psi_sample(&self.proc_root.join("pressure").join("io"))
            .effective_avg();
        let host_devices = self.sample_host_disks(dt);

        let containers_json = serialize_containers_json(containers);
        let (mem_samples, cpu_samples) = extract_container_guard_samples_with_cpu_delta(
            &mut self.prev_container_cpu,
            containers,
            timestamp,
            host_cpu_sample.logical_cpus,
        );
        let io_samples = self.extract_container_io_samples(containers, dt);
        let (total_rx_bps, total_tx_bps, total_rx_pps, total_tx_pps) =
            self.compute_container_net_rates(containers, dt);

        let allow_new_limits = config.security_monitor_enabled;
        let cpu_out = self
            .cpu_guard
            .observe(timestamp, &host_cpu_sample, &cpu_samples, allow_new_limits);
        let (mem_decisions, mem_actions) = self.memory_guard.observe(
            timestamp,
            host_mem_psi,
            &mem_samples,
            allow_new_limits,
        );
        let (io_decisions, io_actions) = self.io_guard.observe(
            timestamp,
            host_cpu_sample.ready,
            &host_devices,
            host_io_psi,
            &io_samples,
            allow_new_limits,
        );

        let suspicious_findings = if config.security_monitor_enabled {
            let proc_infos = extract_proc_infos_from_snapshot(&proc_snapshot_json);
            detect_suspicious_processes(&proc_infos)
        } else {
            Vec::new()
        };
        let suspicious_json = serialize_suspicious_findings_json(&suspicious_findings);
        let socket_abuse_input = aggregate_socket_abuse_from_containers(containers, timestamp);
        let socket_abuse_json = evaluate_socket_abuse(&socket_abuse_input).to_json();

        let mut out = String::with_capacity(4096);
        let _ = write!(
            out,
            "{{\"host_id\":\"{}\",\"node_id\":\"{}\",\"client_config\":{{\"host_id\":\"{}\",\"report_interval\":{},\"action_poll_interval\":{},\"container_runtimes\":\"{}\",\"docker_monitor_mode\":\"{}\",\"incus_project\":\"{}\",\"security_monitor_enabled\":{}}},\"agent_version\":\"{}\",\"timestamp\":{},\"container_network\":{{\"ipv4_ok\":true,\"ipv6_ok\":false}},\"podman_network\":{{\"ipv4_ok\":true,\"ipv6_ok\":false}},\"containers\":{},\"security\":{{\"enabled\":{},\"interval_seconds\":{:.3},\"total_rx_bps\":{:.3},\"total_tx_bps\":{:.3},\"total_rx_pps\":{:.3},\"total_tx_pps\":{:.3},\"syn_recv_count\":{},\"access_log\":{{\"enabled\":false,\"readable_files\":0}},\"access_sources\":[],\"alerts\":[],\"suspicious_processes\":{},\"socket_abuse\":{},\"host_firewall\":{{\"available\":false}},\"conntrack\":{},\"psi_snapshot\":{},\"cpu_guard\":{{\"multi_container_contention\":{},\"decisions\":{},\"actions\":{}}},\"memory_guard\":{{\"decisions\":{},\"actions\":{}}},\"io_guard\":{{\"decisions\":{},\"actions\":{}}}}},\"operations\":{{\"host_metrics\":{},\"psi_snapshot\":{},\"proc_snapshot\":{},\"runtime_inventory\":[],\"guard_actions\":{{\"cpu\":{},\"memory\":{},\"io\":{}}}}}}}",
            json_escape(&config.host_id),
            json_escape(&config.node_id),
            json_escape(&config.host_id),
            config.report_interval,
            config.action_poll_interval,
            json_escape(&config.container_runtimes),
            json_escape(&config.docker_monitor_mode),
            json_escape(&config.incus_project),
            config.security_monitor_enabled,
            json_escape(AGENT_VERSION),
            timestamp,
            containers_json,
            config.security_monitor_enabled,
            interval_secs.max(1.0),
            total_rx_bps,
            total_tx_bps,
            total_rx_pps,
            total_tx_pps,
            socket_abuse_input.tcp_syn_recv,
            suspicious_json,
            socket_abuse_json,
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
            cpu_out.actions.len(),
            mem_actions.len(),
            io_actions.len(),
        );
        out
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
            (None, Some(_)) => (true, 0.0),
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
                samples.push(IoContainerSample {
                    key: key.clone(),
                    device_rates,
                    original_limits: HashMap::new(),
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
        let mut total_rx_bps = 0.0;
        let mut total_tx_bps = 0.0;
        let mut total_rx_pps = 0.0;
        let mut total_tx_pps = 0.0;
        let mut next_net: HashMap<String, (u64, u64, u64, u64)> =
            HashMap::with_capacity(containers.len());

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

            if let Some(dt_secs) = dt.filter(|d| *d > 0.0) {
                if let Some(&(p_rb, p_tb, p_rp, p_tp)) = self.prev_container_net.get(&key) {
                    total_rx_bps += rx_bytes.saturating_sub(p_rb) as f64 / dt_secs;
                    total_tx_bps += tx_bytes.saturating_sub(p_tb) as f64 / dt_secs;
                    total_rx_pps += rx_packets.saturating_sub(p_rp) as f64 / dt_secs;
                    total_tx_pps += tx_packets.saturating_sub(p_tp) as f64 / dt_secs;
                }
            }
            next_net.insert(key, (rx_bytes, tx_bytes, rx_packets, tx_packets));
        }

        self.prev_container_net = next_net;
        (total_rx_bps, total_tx_bps, total_rx_pps, total_tx_pps)
    }
}

fn serialize_containers_json(containers: &[ContainerSample]) -> String {
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

        let _ = write!(
            out,
            "{{\"id\":\"{}\",\"stable_id\":\"{}\",\"name\":\"{}\",\"image\":\"{}\",\"runtime\":\"{}\",\"runtime_bin\":\"{}\",\"project\":\"{}\",\"pid\":{},\"status\":\"{}\",\"instance_id\":\"{}\",\"network_addresses\":{}",
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
        out.push('}');
    }
    out.push(']');
    out
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

fn container_guard_key(container: &ContainerSample) -> String {
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

fn extract_container_guard_samples_with_cpu_delta(
    prev_container_cpu: &mut HashMap<String, (u64, u64)>,
    containers: &[ContainerSample],
    timestamp: u64,
    logical_cpus: u32,
) -> (Vec<MemoryContainerSample>, Vec<CpuContainerSample>) {
    let default_cpus = logical_cpus.max(1) as f64;
    let mut mem_samples = Vec::new();
    let mut cpu_samples = Vec::new();
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

        if let Some(current_bytes) = cg_current.or(pm_mem) {
            mem_samples.push(MemoryContainerSample {
                key: key.clone(),
                current_bytes,
                max_bytes: cg_max,
                original_high_bytes: None,
                container_psi: PsiSample::default(),
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

        cpu_samples.push(CpuContainerSample {
            key,
            cpu_percent,
            effective_cpus: quota_cpus.unwrap_or(default_cpus),
            cgroup_cpu_psi_some_avg10: None,
        });
    }

    *prev_container_cpu = next_cpu;
    (mem_samples, cpu_samples)
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
    let poll_body = format!(
        "{{\"host_id\":\"{}\",\"node_id\":\"{}\"}}",
        json_escape(&config.host_id),
        json_escape(&config.node_id)
    );
    let resp = client.post_json_signed_verified("/api/v1/actions/poll", poll_body.as_bytes())?;
    let body_str = String::from_utf8_lossy(&resp.body);
    let requests = match actions::parse_poll_actions(&body_str) {
        Ok(reqs) => reqs,
        Err(_) => return Ok(0),
    };
    let count = requests.len();

    for req in &requests {
        let receipt = actions::execute_action(req);
        let _ = actions::submit_action_receipt(client, &config.host_id, &config.node_id, &receipt)?;
    }
    Ok(count)
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

    while !stop.load(Ordering::Relaxed) {
        let payload = state.build_report_json(config, current_unix_ts());
        if let Err(err) = client.post_json_signed("/api/v1/report", payload.as_bytes()) {
            let _ = writeln!(out, "report failed: {err}");
        }

        let deadline = Instant::now() + report_delay;
        while !stop.load(Ordering::Relaxed) {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let sleep_for = poll_delay.min(deadline - now);
            thread::sleep(sleep_for);
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if let Err(err) = poll_actions_once(&client, config) {
                let _ = writeln!(out, "action poll failed: {err}");
            }
        }
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write as IoWrite};
    use std::net::TcpListener;
    use transport::{sign_payload, HEADER_RESPONSE_SIGNATURE, HEADER_TIMESTAMP};

    fn make_temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "narwhal_agent_core_{}_{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn test_config_from_env_file_env_and_cli_precedence() {
        let dir = make_temp_dir("cfg_precedence");
        let env_file = dir.join("client.env");
        fs::write(
            &env_file,
            r#"
# comment line
SERVER_URL="https://env-file.example.com:8443"
SHARED_SECRET='file-secret'
REPORT_INTERVAL=120
ACTION_POLL_INTERVAL=3
HOST_ID=file-host
NODE_ID=node-from-file
CONTAINER_RUNTIMES=podman
DOCKER_MONITOR_MODE=ignore
INCUS_PROJECT=default
SECURITY_MONITOR_ENABLED=false
"#,
        )
        .expect("write env file");

        let mut proc_env = HashMap::new();
        proc_env.insert(
            "SERVER_URL".to_string(),
            "https://proc-env.example.com".to_string(),
        );
        proc_env.insert("REPORT_INTERVAL".to_string(), "30".to_string()); // clamped to 60

        let args = vec![
            "--host-id".to_string(),
            "cli-host".to_string(),
            "--secret".to_string(),
            "cli-secret".to_string(),
            "--once".to_string(),
            "--dry-run".to_string(),
        ];

        let cfg = Config::from_sources(Some(&env_file), &proc_env, &args).expect("parse config");
        assert_eq!(cfg.server_url, "https://proc-env.example.com");
        assert_eq!(cfg.shared_secret, "cli-secret");
        assert_eq!(cfg.report_interval, 60);
        assert_eq!(cfg.action_poll_interval, 5); // clamped from 3 to 5
        assert_eq!(cfg.host_id, "cli-host");
        assert_eq!(cfg.node_id, "node-from-file");
        assert_eq!(cfg.container_runtimes, "podman");
        assert_eq!(cfg.docker_monitor_mode, "ignore");
        assert_eq!(cfg.incus_project, "default");
        assert!(!cfg.security_monitor_enabled);
        assert!(cfg.once);
        assert!(cfg.dry_run);
        assert!(!cfg.check_config);

        let summary = cfg.sanitized_summary();
        assert!(!summary.contains("cli-secret"));
        assert!(summary.contains("configured(redacted)"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_config_cli_errors() {
        let env = HashMap::new();
        let err = Config::from_sources(None, &env, &["--unknown".to_string()]).unwrap_err();
        assert_eq!(err, ConfigError::InvalidFlag("--unknown".to_string()));

        let err = Config::from_sources(None, &env, &["--server".to_string()]).unwrap_err();
        assert_eq!(err, ConfigError::MissingFlagValue("--server".to_string()));

        let err = Config::from_sources(
            None,
            &env,
            &["--interval".to_string(), "not-a-num".to_string()],
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConfigError::InvalidInt {
                flag: "--interval".to_string(),
                value: "not-a-num".to_string()
            }
        );
    }

    #[test]
    fn test_report_json_structure_with_mock_proc() {
        let dir = make_temp_dir("report_mock");
        let proc_root = dir.join("proc");
        fs::create_dir_all(proc_root.join("net")).unwrap();
        fs::create_dir_all(proc_root.join("pressure")).unwrap();
        fs::write(proc_root.join("uptime"), "1234.56 789.01\n").unwrap();
        fs::write(proc_root.join("loadavg"), "0.25 0.30 0.40 1/120 1234\n").unwrap();
        fs::write(
            proc_root.join("stat"),
            "cpu  1000 10 200 8000 50 0 0 0 0 0\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("meminfo"),
            "MemTotal:        4096000 kB\nMemAvailable:    2048000 kB\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("net").join("dev"),
            "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("pressure").join("cpu"),
            "some avg10=1.50 avg60=1.00 avg300=0.50 total=1000\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("pressure").join("memory"),
            "some avg10=0.10 avg60=0.05 avg300=0.01 total=10\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("pressure").join("io"),
            "some avg10=0.20 avg60=0.10 avg300=0.05 total=20\n",
        )
        .unwrap();
        let conntrack = dir.join("nf_conntrack");
        fs::write(&conntrack, "").unwrap();

        let cfg = Config {
            host_id: "test-host".to_string(),
            node_id: "node-123".to_string(),
            container_runtimes: "none".to_string(),
            ..Config::default()
        };
        let mut state = AgentState::with_paths(&cfg, proc_root, conntrack);
        let report = state.build_report_json(&cfg, 1_700_000_000);

        for required_key in [
            "\"host_id\":\"test-host\"",
            "\"node_id\":\"node-123\"",
            "\"client_config\":{",
            "\"agent_version\":",
            "\"timestamp\":1700000000",
            "\"container_network\":{\"ipv4_ok\":true,\"ipv6_ok\":false}",
            "\"podman_network\":{\"ipv4_ok\":true,\"ipv6_ok\":false}",
            "\"containers\":[]",
            "\"security\":{",
            "\"operations\":{",
            "\"cpu_guard\":{",
            "\"memory_guard\":{",
            "\"io_guard\":{",
            "\"host_metrics\":{",
        ] {
            assert!(
                report.contains(required_key),
                "missing {required_key} in report: {report}"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_check_config_and_dry_run_modes() {
        let cfg_check = Config {
            shared_secret: "super-secret".to_string(),
            check_config: true,
            ..Config::default()
        };
        let mut state = AgentState::new(&cfg_check);
        let mut out = Vec::new();
        let stop = AtomicBool::new(false);
        let code = run_with_config(&cfg_check, &mut state, &mut out, &stop).unwrap();
        assert_eq!(code, 0);
        let printed = String::from_utf8(out).unwrap();
        assert!(printed.contains("configured(redacted)"));
        assert!(!printed.contains("super-secret"));

        let cfg_dry = Config {
            host_id: "dry-host".to_string(),
            once: true,
            dry_run: true,
            ..Config::default()
        };
        let mut out2 = Vec::new();
        let code2 = run_with_config(&cfg_dry, &mut state, &mut out2, &stop).unwrap();
        assert_eq!(code2, 0);
        let printed2 = String::from_utf8(out2).unwrap();
        assert!(printed2.contains("\"host_id\":\"dry-host\""));
        assert!(printed2.contains("\"operations\":{"));
    }

    #[test]
    fn test_action_poll_and_result_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().unwrap();
        let secret = "poll-test-secret".to_string();
        let secret_clone = secret.clone();

        let handle = thread::spawn(move || {
            for idx in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                reader.read_line(&mut req_line).unwrap();
                let mut ts_header = 0i64;
                let mut content_len = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = trimmed.split_once(':') {
                        if k.eq_ignore_ascii_case(HEADER_TIMESTAMP) {
                            ts_header = v.trim().parse().unwrap_or(0);
                        } else if k.eq_ignore_ascii_case("content-length") {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                let mut body_buf = vec![0u8; content_len];
                reader.read_exact(&mut body_buf).unwrap();

                let resp_body = if idx == 0 {
                    b"{\"actions\":[{\"id\":42,\"action_type\":\"host_security_rescan\"}]}".to_vec()
                } else {
                    b"{\"ok\":true}".to_vec()
                };
                let resp_sig = sign_payload(&resp_body, &secret_clone, ts_header);
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}: {}\r\nConnection: close\r\n\r\n",
                    resp_body.len(),
                    HEADER_RESPONSE_SIGNATURE,
                    resp_sig
                );
                stream.write_all(header.as_bytes()).unwrap();
                stream.write_all(&resp_body).unwrap();
            }
        });

        let cfg = Config {
            server_url: format!("http://{addr}"),
            shared_secret: secret,
            host_id: "h1".to_string(),
            node_id: "n1".to_string(),
            ..Config::default()
        };
        let client = TransportClient::new(cfg.to_transport_config()).unwrap();
        let handled = poll_actions_once(&client, &cfg).expect("poll actions");
        assert_eq!(handled, 1);
        handle.join().unwrap();
    }

    #[test]
    fn test_extract_proc_infos_and_aggregate_socket_abuse() {
        let snapshot = r#"{
            "available": true,
            "items": [
                {
                    "pid": 101,
                    "ppid": 1,
                    "lifetime_cpu_percent": 42.5,
                    "rss_bytes": 1048576,
                    "process": "xmrig",
                    "command": "/tmp/xmrig --url stratum+tcp://pool.example:3333"
                },
                {
                    "pid": 102,
                    "ppid": 1,
                    "cpu_percent": 3.25,
                    "rss_bytes": 2048,
                    "process": "nginx",
                    "command": "nginx: master process"
                }
            ]
        }"#;

        let procs = extract_proc_infos_from_snapshot(snapshot);
        assert_eq!(procs.len(), 2);
        assert_eq!(procs[0].pid, 101);
        assert_eq!(procs[0].ppid, 1);
        assert!((procs[0].cpu_percent - 42.5).abs() < 1e-6);
        assert_eq!(procs[0].rss_bytes, 1_048_576);
        assert_eq!(procs[0].process, "xmrig");
        assert_eq!(
            procs[0].command,
            "/tmp/xmrig --url stratum+tcp://pool.example:3333"
        );
        assert_eq!(procs[1].pid, 102);
        assert!((procs[1].cpu_percent - 3.25).abs() < 1e-6);

        let findings = detect_suspicious_processes(&procs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pid, 101);

        let c1 = ContainerSample {
            id: "c1".to_string(),
            stable_id: "docker:c1".to_string(),
            name: "app1".to_string(),
            image: "alpine".to_string(),
            runtime: "docker".to_string(),
            runtime_bin: "docker".to_string(),
            project: String::new(),
            pid: Some(1000),
            status: "running".to_string(),
            instance_id: String::new(),
            network_addresses: Vec::new(),
            pid_metrics_json: Some(r#"{"available":true,"mem_bytes":52428800}"#.to_string()),
            socket_tables_json: Some(
                r#"{"available":true,"tcp_established":10,"tcp_time_wait":4,"syn_sent_count":2,"syn_recv_count":3,"udp_sockets":5}"#
                    .to_string(),
            ),
            cgroup_metrics_json: Some(
                r#"{"available":true,"cpu_max":{"quota_usec":150000,"period_usec":100000},"memory":{"current_bytes":67108864,"max_bytes":134217728}}"#
                    .to_string(),
            ),
        };
        let c2 = ContainerSample {
            id: "c2".to_string(),
            stable_id: "docker:c2".to_string(),
            name: "app2".to_string(),
            image: "alpine".to_string(),
            runtime: "docker".to_string(),
            runtime_bin: "docker".to_string(),
            project: String::new(),
            pid: Some(2000),
            status: "running".to_string(),
            instance_id: String::new(),
            network_addresses: Vec::new(),
            pid_metrics_json: Some(r#"{"available":true,"mem_bytes":16777216}"#.to_string()),
            socket_tables_json: Some(
                r#"{"available":true,"tcp_established":5,"tcp_time_wait":1,"tcp_syn_sent":1,"tcp_syn_recv":2,"udp_sockets":3,"conn_count":20}"#
                    .to_string(),
            ),
            cgroup_metrics_json: None,
        };

        let containers = vec![c1, c2];
        let agg = aggregate_socket_abuse_from_containers(&containers, 1_700_000_123);
        assert_eq!(agg.evaluated_at, 1_700_000_123);
        assert_eq!(agg.tcp_established, 15);
        assert_eq!(agg.tcp_time_wait, 5);
        assert_eq!(agg.tcp_syn_sent, 3);
        assert_eq!(agg.tcp_syn_recv, 5);
        assert_eq!(agg.udp_sockets, 8);
        assert_eq!(agg.conn_count, 44);
        assert!(agg.has_tcp_states);

        let (mem_samples, cpu_samples) = extract_container_guard_samples(&containers, 4);
        assert_eq!(mem_samples.len(), 2);
        assert_eq!(mem_samples[0].key, "docker:c1");
        assert_eq!(mem_samples[0].current_bytes, 67_108_864);
        assert_eq!(mem_samples[0].max_bytes, Some(134_217_728));
        assert_eq!(mem_samples[1].key, "docker:c2");
        assert_eq!(mem_samples[1].current_bytes, 16_777_216);
        assert_eq!(mem_samples[1].max_bytes, None);

        assert_eq!(cpu_samples.len(), 2);
        assert_eq!(cpu_samples[0].key, "docker:c1");
        assert!((cpu_samples[0].effective_cpus - 1.5).abs() < 1e-6);
        assert_eq!(cpu_samples[1].key, "docker:c2");
        assert!((cpu_samples[1].effective_cpus - 4.0).abs() < 1e-6);
    }

    #[test]
    fn test_two_tick_cross_delta_diskstats_and_network_rates() {
        let dir = std::env::temp_dir().join(format!("agent-core-delta-test-{}", std::process::id()));
        let proc_root = dir.join("proc");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(proc_root.join("net")).unwrap();
        fs::create_dir_all(proc_root.join("pressure")).unwrap();
        fs::write(proc_root.join("loadavg"), "0.20 0.15 0.10 1/100 42\n").unwrap();
        fs::write(proc_root.join("uptime"), "100.00 200.00\n").unwrap();
        fs::write(
            proc_root.join("meminfo"),
            "MemTotal:        4096000 kB\nMemAvailable:    2048000 kB\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("net").join("dev"),
            "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("pressure").join("cpu"),
            "some avg10=1.00 avg60=0.50 avg300=0.25 total=100\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("pressure").join("memory"),
            "some avg10=0.10 avg60=0.05 avg300=0.01 total=10\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("pressure").join("io"),
            "some avg10=0.20 avg60=0.10 avg300=0.05 total=20\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("stat"),
            "cpu  1000 0 500 8500 0 0 0 0 0 0\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("diskstats"),
            "   8       0 sda 100 0 2000 10 50 0 1000 5 0 500 15\n",
        )
        .unwrap();
        let conntrack = dir.join("nf_conntrack");
        fs::write(&conntrack, "").unwrap();

        let cfg = Config {
            host_id: "delta-host".to_string(),
            node_id: "node-delta".to_string(),
            container_runtimes: "none".to_string(),
            ..Config::default()
        };
        let mut state = AgentState::with_paths(&cfg, proc_root.clone(), conntrack);

        // Tick 1 via public build_report_json(): records baseline diskstats & CPU without panics.
        let report1 = state.build_report_json(&cfg, 1_700_000_000);
        assert!(report1.contains("\"total_rx_bps\":0.000"));
        assert!(state.prev_host_disks.contains_key("8:0"));

        // Advance /proc/stat & /proc/diskstats for tick 2 (10s later).
        fs::write(
            proc_root.join("stat"),
            "cpu  1200 0 600 9200 0 0 0 0 0 0\n",
        )
        .unwrap();
        fs::write(
            proc_root.join("diskstats"),
            "   8       0 sda 200 0 6000 20 150 0 3000 15 0 2500 35\n",
        )
        .unwrap();
        let report2 = state.build_report_json(&cfg, 1_700_000_010);
        assert!(report2.contains("\"interval_seconds\":10.000"));
        assert_eq!(state.prev_host_disks.get("8:0"), Some(&(200, 6000, 150, 3000, 2500)));

        // Verify diskstats delta calculation directly on tick 3 (10s later).
        fs::write(
            proc_root.join("diskstats"),
            "   8       0 sda 300 0 10000 30 250 0 5000 25 0 7500 55\n",
        )
        .unwrap();
        let disk_samples = state.sample_host_disks(Some(10.0));
        assert_eq!(disk_samples.len(), 1);
        assert_eq!(disk_samples[0].device, "8:0");
        assert!((disk_samples[0].busy_percent - 50.0).abs() < 1e-6);
        assert!((disk_samples[0].total_bps - 307_200.0).abs() < 1e-6);
        assert!((disk_samples[0].total_iops - 20.0).abs() < 1e-6);

        // Verify two-tick container CPU, IO, and network rate deltas via build_report_json_with_containers().
        let make_container = |usage_usec: u64, rbytes: u64, wbytes: u64, rios: u64, wios: u64, rx_b: u64, tx_b: u64, rx_p: u64, tx_p: u64| {
            ContainerSample {
                id: "c1".to_string(),
                stable_id: "docker:c1".to_string(),
                name: "app1".to_string(),
                image: "alpine".to_string(),
                runtime: "docker".to_string(),
                runtime_bin: "docker".to_string(),
                project: String::new(),
                pid: Some(1000),
                status: "running".to_string(),
                instance_id: String::new(),
                network_addresses: Vec::new(),
                pid_metrics_json: Some(format!(
                    r#"{{"available":true,"mem_bytes":52428800,"net":{{"rx_bytes":{rx_b},"tx_bytes":{tx_b},"rx_packets":{rx_p},"tx_packets":{tx_p}}}}}"#
                )),
                socket_tables_json: None,
                cgroup_metrics_json: Some(format!(
                    r#"{{"available":true,"cpu_stat":{{"usage_usec":{usage_usec}}},"memory":{{"current_bytes":52428800,"max_bytes":134217728}},"io":{{"available":true,"devices":[{{"dev":"8:0","rbytes":{rbytes},"wbytes":{wbytes},"rios":{rios},"wios":{wios}}}]}}}}"#
                )),
            }
        };

        let c_tick1 = vec![make_container(1_000_000, 10_000, 20_000, 100, 200, 1_000, 2_000, 10, 20)];
        let c_tick2 = vec![make_container(6_000_000, 30_000, 60_000, 150, 300, 11_000, 22_000, 110, 220)];

        let _ = state.build_report_json_with_containers(&cfg, 1_700_000_020, &c_tick1);
        let net_report = state.build_report_json_with_containers(&cfg, 1_700_000_030, &c_tick2);

        assert!(net_report.contains("\"total_rx_bps\":1000.000"));
        assert!(net_report.contains("\"total_tx_bps\":2000.000"));
        assert!(net_report.contains("\"total_rx_pps\":10.000"));
        assert!(net_report.contains("\"total_tx_pps\":20.000"));

        // Verify CPU & IO container deltas on a follow-up tick (10s later).
        let c_tick3 = vec![make_container(11_000_000, 50_000, 100_000, 200, 400, 21_000, 42_000, 210, 420)];
        let (_, cpu_samples) = extract_container_guard_samples_with_cpu_delta(
            &mut state.prev_container_cpu,
            &c_tick3,
            1_700_000_040,
            4,
        );
        assert_eq!(cpu_samples.len(), 1);
        assert!((cpu_samples[0].cpu_percent.unwrap() - 50.0).abs() < 1e-6);

        let io_samples = state.extract_container_io_samples(&c_tick3, Some(10.0));
        assert_eq!(io_samples.len(), 1);
        assert_eq!(io_samples[0].device_rates[0].0, "8:0");
        assert!((io_samples[0].device_rates[0].1.rbps - 2000.0).abs() < 1e-6);
        assert!((io_samples[0].device_rates[0].1.wbps - 4000.0).abs() < 1e-6);
        assert!((io_samples[0].device_rates[0].1.riops - 5.0).abs() < 1e-6);
        assert!((io_samples[0].device_rates[0].1.wiops - 10.0).abs() < 1e-6);

        let _ = fs::remove_dir_all(&dir);
    }
}
