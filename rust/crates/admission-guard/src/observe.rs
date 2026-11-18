use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::path::Path;

use net_guard::{
    podman_inspect_args, quarantine_target, CommandRunner, IncusIsolation, IncusTransport,
    LiveRunmanTransport, RunmanIsolation, RunmanTransport, UnixIncusApi, DEFAULT_INCUS_SOCKET,
    DEFAULT_RUNMAN_SOCKET,
};
use runtime_drivers::JsonVal;
use socket_sec::decode_hex_ip_port;

use crate::policy::{self, current_unix_ts_i64, TcpFlow};
use crate::AdmissionError;

const MAX_PROC_NET_BYTES: usize = 8 * 1024 * 1024;
const MAX_IP_LINK_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedNetwork {
    pub instance_id: String,
    pub message: String,
}

impl UnsupportedNetwork {
    pub fn new(instance_id: impl Into<String>) -> Self {
        Self {
            instance_id: instance_id.into(),
            message: "verified instance no longer has a supported private forwarding network"
                .to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketObservation {
    pub epoch: String,
    pub flows: BTreeSet<TcpFlow>,
    pub inbound: Vec<String>,
    pub listening: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerDescriptor {
    pub runtime: String,
    pub project: String,
    pub name: String,
    pub id: String,
    pub instance_id: String,
    pub pid: Option<u32>,
    pub network_addresses: Vec<String>,
}

impl ContainerDescriptor {
    pub fn new(runtime: impl Into<String>, project: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            runtime: runtime.into(),
            project: project.into(),
            name: name.into(),
            id: String::new(),
            instance_id: String::new(),
            pid: None,
            network_addresses: Vec::new(),
        }
    }

    pub fn normalized_project(&self) -> &str {
        if self.project.is_empty() {
            ""
        } else {
            self.project.as_str()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSnapshot {
    pub instance_id: String,
    pub ips: Vec<String>,
    pub interfaces: Vec<String>,
    pub epoch: String,
    pub flows: BTreeSet<TcpFlow>,
    pub inbound: Vec<String>,
    pub listening_ports: Vec<u16>,
    pub pid: Option<u32>,
    pub observed_at: i64,
    pub shared_network: bool,
}

pub fn is_valid_ifname(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=15).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
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

/// Decode hex-encoded IPv4 (8 hex chars) or IPv6 (32 hex chars) from `/proc/<pid>/net/tcp{,6}`
/// and normalize via `policy::address`.
pub fn decode(value: &str) -> Result<String, AdmissionError> {
    let trimmed = value.trim();
    let is_v6 = match trimmed.len() {
        8 => false,
        32 => true,
        _ => return Err(AdmissionError::Value("invalid hex IP length".to_string())),
    };
    let endpoint = format!("{trimmed}:0000");
    let (ip_str, _) = decode_hex_ip_port(&endpoint, is_v6)
        .ok_or_else(|| AdmissionError::Value("invalid hex IP encoding".to_string()))?;
    policy::address(&ip_str)
}

fn read_ns_identifier(path: &Path) -> Result<String, AdmissionError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(path).map_err(AdmissionError::from_io)?;
        return Ok(meta.ino().to_string());
    }
    #[cfg(not(unix))]
    {
        let content = fs::read_to_string(path).map_err(AdmissionError::from_io)?;
        Ok(content.trim().to_string())
    }
}

pub fn incarnation(pid: u32) -> Result<String, AdmissionError> {
    incarnation_from_root(
        Path::new("/proc"),
        Path::new("/proc/sys/kernel/random/boot_id"),
        pid,
    )
}

pub fn incarnation_from_root(
    proc_root: &Path,
    boot_id_path: &Path,
    pid: u32,
) -> Result<String, AdmissionError> {
    if pid <= 1 {
        return Err(AdmissionError::Value("invalid init PID".to_string()));
    }
    let pid_dir = proc_root.join(pid.to_string());
    let init_dir = proc_root.join("1");
    let mut net_ino = String::new();
    for kind in ["pid", "net"] {
        let container_ns = read_ns_identifier(&pid_dir.join("ns").join(kind))?;
        let host_ns = read_ns_identifier(&init_dir.join("ns").join(kind))?;
        if container_ns == host_ns {
            return Err(AdmissionError::Value("shared host namespace".to_string()));
        }
        if kind == "net" {
            net_ino = container_ns;
        }
    }
    let stat_text = fs::read_to_string(pid_dir.join("stat")).map_err(AdmissionError::from_io)?;
    let ticks = parse_stat_start_ticks(&stat_text)
        .ok_or_else(|| AdmissionError::Value("invalid /proc/<pid>/stat".to_string()))?;
    let boot = fs::read_to_string(boot_id_path)
        .map_err(AdmissionError::from_io)?
        .trim()
        .to_string();
    if boot.is_empty() {
        return Err(AdmissionError::Value("empty boot_id".to_string()));
    }
    Ok(format!("{boot}:{net_ino}:{ticks}"))
}

pub fn parse_stat_start_ticks(stat_text: &str) -> Option<String> {
    let (_, after) = stat_text.rsplit_once(')')?;
    let fields: Vec<&str> = after.split_whitespace().collect();
    let ticks = *fields.get(19)?;
    if ticks.is_empty() || !ticks.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(ticks.to_string())
}

pub fn sockets(pid: u32) -> Result<SocketObservation, AdmissionError> {
    let net_dir = Path::new("/proc").join(pid.to_string()).join("net");
    sockets_from_dir(pid, &net_dir, || incarnation(pid))
}

pub fn sockets_from_dir<F>(
    _pid: u32,
    net_dir: &Path,
    mut incarnation_fn: F,
) -> Result<SocketObservation, AdmissionError>
where
    F: FnMut() -> Result<String, AdmissionError>,
{
    let epoch = incarnation_fn()?;
    let mut entries: Vec<(String, String, u16, String, u16)> = Vec::new();
    for name in ["tcp", "tcp6", "udp", "udp6"] {
        let file = fs::File::open(net_dir.join(name)).map_err(AdmissionError::from_io)?;
        let mut buf = Vec::new();
        file.take((MAX_PROC_NET_BYTES + 1) as u64)
            .read_to_end(&mut buf)
            .map_err(AdmissionError::from_io)?;
        if buf.len() > MAX_PROC_NET_BYTES {
            return Err(AdmissionError::Value(
                "socket observation exceeds budget".to_string(),
            ));
        }
        let text = String::from_utf8(buf)
            .map_err(|_| AdmissionError::Value("invalid ASCII in socket table".to_string()))?;
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                return Err(AdmissionError::Value(
                    "incomplete socket observation".to_string(),
                ));
            }
            if name.starts_with("udp") {
                continue;
            }
            let state = fields[3].to_string();
            let (local, port_hex) = fields[1]
                .split_once(':')
                .ok_or_else(|| AdmissionError::Value("invalid local endpoint".to_string()))?;
            let (remote, rport_hex) = fields[2]
                .split_once(':')
                .ok_or_else(|| AdmissionError::Value("invalid remote endpoint".to_string()))?;
            let port = u16::from_str_radix(port_hex, 16)
                .map_err(|_| AdmissionError::Value("invalid local port hex".to_string()))?;
            let rport = u16::from_str_radix(rport_hex, 16)
                .map_err(|_| AdmissionError::Value("invalid remote port hex".to_string()))?;
            entries.push((state, local.to_string(), port, remote.to_string(), rport));
        }
    }

    let mut listen = BTreeSet::new();
    for (state, _, port, _, _) in &entries {
        if state == "0A" {
            listen.insert(*port);
        }
    }

    let mut flows = BTreeSet::new();
    let mut inbound = Vec::new();
    for (state, local, port, remote, rport) in entries {
        if state != "01" {
            continue;
        }
        let (Ok(laddr), Ok(raddr)) = (decode(&local), decode(&remote)) else {
            continue;
        };
        flows.insert((laddr, port, raddr.clone(), rport));
        if listen.contains(&port) && !inbound.contains(&raddr) {
            inbound.push(raddr);
        }
    }

    if epoch != incarnation_fn()? {
        return Err(AdmissionError::Value(
            "container restarted during observation".to_string(),
        ));
    }

    Ok(SocketObservation {
        epoch,
        flows,
        inbound,
        listening: listen.into_iter().collect(),
    })
}

pub fn snapshot(
    container: &ContainerDescriptor,
    runtime_bins: &BTreeMap<String, String>,
    runner: &mut dyn CommandRunner,
    require_forward: bool,
) -> Result<ContainerSnapshot, AdmissionError> {
    let mut incus_api = UnixIncusApi::new(&container.project, DEFAULT_INCUS_SOCKET);
    let mut runman_tx = LiveRunmanTransport::new(DEFAULT_RUNMAN_SOCKET);
    snapshot_with_transports(
        container,
        runtime_bins,
        runner,
        &mut incus_api,
        &mut runman_tx,
        require_forward,
        sockets,
        incarnation,
    )
}

struct IncusTransportRef<'a, T: IncusTransport>(&'a mut T);

impl<'a, T: IncusTransport> IncusTransport for IncusTransportRef<'a, T> {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&JsonVal>,
        etag: Option<&str>,
    ) -> Result<(JsonVal, Option<String>), String> {
        self.0.request(method, path, body, etag)
    }
}

struct RunmanTransportRef<'a, T: RunmanTransport>(&'a mut T);

impl<'a, T: RunmanTransport> RunmanTransport for RunmanTransportRef<'a, T> {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), String> {
        self.0.request(method, path, body)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn snapshot_with_transports<IT, RT, SF, IF>(
    container: &ContainerDescriptor,
    runtime_bins: &BTreeMap<String, String>,
    runner: &mut dyn CommandRunner,
    incus_api: &mut IT,
    runman_transport: &mut RT,
    require_forward: bool,
    mut sockets_fn: SF,
    mut incarnation_fn: IF,
) -> Result<ContainerSnapshot, AdmissionError>
where
    IT: IncusTransport,
    RT: RunmanTransport,
    SF: FnMut(u32) -> Result<SocketObservation, AdmissionError>,
    IF: FnMut(u32) -> Result<String, AdmissionError>,
{
    let runtime = container.runtime.as_str();
    let name = container.name.as_str();
    let project = container.normalized_project();

    let (identity, pid, raw_ips): (String, u32, Vec<String>) = match runtime {
        "incus" => {
            let instance_path = format!("/1.0/instances/{}", url_encode_component(name));
            let (item, _) = incus_api
                .request("GET", &instance_path, None, None)
                .map_err(AdmissionError::Runtime)?;
            let id = item
                .get("config")
                .and_then(|c| c.get_str("volatile.uuid"))
                .unwrap_or("")
                .to_string();
            {
                let mut driver = IncusIsolation::new(IncusTransportRef(incus_api), name, &id);
                driver.inspect().map_err(AdmissionError::Runtime)?;
            }
            if item.get_str("type").unwrap_or("container") != "container" {
                return Err(AdmissionError::Value(
                    "VM networking needs a separate driver".to_string(),
                ));
            }
            let state_path = format!("{instance_path}/state");
            let (state, _) = incus_api
                .request("GET", &state_path, None, None)
                .map_err(AdmissionError::Runtime)?;
            let pid_val = state
                .get_u64("pid")
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0);
            let mut addrs = Vec::new();
            if let Some(net_map) = state.get("network").and_then(JsonVal::as_obj) {
                for device in net_map.values() {
                    if let Some(arr) = device.get("addresses").and_then(JsonVal::as_arr) {
                        for a in arr {
                            if a.get_str("scope") == Some("global") {
                                if let Some(addr_str) = a.get_str("address") {
                                    addrs.push(addr_str.to_string());
                                }
                            }
                        }
                    }
                }
            }
            (id, pid_val, addrs)
        }
        "podman" => {
            let binary = runtime_bins
                .get("podman")
                .filter(|s| !s.is_empty())
                .ok_or_else(|| AdmissionError::Value("Podman unavailable".to_string()))?;
            let mut cmd = Vec::with_capacity(5);
            cmd.push(binary.clone());
            cmd.extend(podman_inspect_args(name));
            let (ok, output) = runner.run(&cmd, None);
            if !ok {
                return Err(AdmissionError::Value(
                    "Podman inspect unavailable".to_string(),
                ));
            }
            let parsed = JsonVal::parse(&output)
                .map_err(|_| AdmissionError::Value("invalid Podman inspect JSON".to_string()))?;
            let item = parsed
                .as_arr()
                .and_then(|a| a.first())
                .ok_or_else(|| AdmissionError::Value("empty Podman inspect array".to_string()))?;
            let id = item.get_str("Id").unwrap_or("").to_string();
            let expected = container.id.as_str();
            if expected.len() < 12 || !id.starts_with(expected) {
                return Err(AdmissionError::Value(
                    "Podman instance identity changed".to_string(),
                ));
            }
            let mode = item
                .get("HostConfig")
                .and_then(|h| h.get_str("NetworkMode"))
                .unwrap_or("");
            let has_pod = item.get_str("Pod").is_some_and(|p| !p.is_empty());
            if matches!(mode, "host" | "none")
                || mode.starts_with("container:")
                || mode.starts_with("ns:")
                || mode.starts_with("slirp")
                || mode.starts_with("pasta")
                || has_pod
            {
                return Err(AdmissionError::UnsupportedNetwork(UnsupportedNetwork::new(
                    id,
                )));
            }
            let pid_val = item
                .get("State")
                .and_then(|s| s.get_u64("Pid"))
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0);
            let mut addrs = Vec::new();
            if let Some(nets) = item
                .get("NetworkSettings")
                .and_then(|ns| ns.get("Networks"))
                .and_then(JsonVal::as_obj)
            {
                for v in nets.values() {
                    for k in ["IPAddress", "GlobalIPv6Address"] {
                        if let Some(ip_str) = v.get_str(k).filter(|s| !s.is_empty()) {
                            addrs.push(ip_str.to_string());
                        }
                    }
                }
            }
            (id, pid_val, addrs)
        }
        "runman" => {
            let id = container.instance_id.clone();
            quarantine_target(runtime, project, name, &id).map_err(AdmissionError::Value)?;
            let mut driver = RunmanIsolation::new(RunmanTransportRef(runman_transport), name, &id);
            let state = driver.inspect().map_err(AdmissionError::Runtime)?;
            let init_pid = state
                .get_i64("init_pid")
                .and_then(|p| if p > 1 { u32::try_from(p).ok() } else { None });
            if state.get_bool("running") != Some(true)
                || state.get_str("instance_id") != Some(id.as_str())
                || init_pid.is_none()
            {
                return Err(AdmissionError::Value(
                    "Runman generation or init PID is unavailable".to_string(),
                ));
            }
            let pid_val = init_pid.unwrap();
            let reported_pid = container.pid.unwrap_or(0);
            if reported_pid != pid_val {
                return Err(AdmissionError::Value(
                    "Runman inventory PID changed".to_string(),
                ));
            }
            if container.network_addresses.is_empty() || container.network_addresses.len() > 32 {
                return Err(AdmissionError::UnsupportedNetwork(UnsupportedNetwork::new(
                    id,
                )));
            }
            let mut addrs = Vec::new();
            for value in &container.network_addresses {
                if !value.is_empty() {
                    addrs.push(policy::address(value)?);
                }
            }
            if addrs.is_empty() {
                return Err(AdmissionError::UnsupportedNetwork(UnsupportedNetwork::new(
                    id,
                )));
            }
            (id, pid_val, addrs)
        }
        _ => return Err(AdmissionError::Value("unsupported runtime".to_string())),
    };

    quarantine_target(runtime, project, name, &identity).map_err(AdmissionError::Value)?;

    let mut ips_set = BTreeSet::new();
    for x in raw_ips {
        ips_set.insert(policy::address(&x)?);
    }
    if ips_set.is_empty() {
        return Err(AdmissionError::UnsupportedNetwork(UnsupportedNetwork::new(
            identity,
        )));
    }
    let ips: Vec<String> = ips_set.iter().cloned().collect();

    let sock_obs = sockets_fn(pid)?;
    let observed_at = current_unix_ts_i64();
    if !require_forward {
        return Ok(ContainerSnapshot {
            instance_id: identity,
            ips,
            interfaces: Vec::new(),
            epoch: sock_obs.epoch,
            flows: sock_obs.flows,
            inbound: sock_obs.inbound,
            listening_ports: sock_obs.listening,
            pid: Some(pid),
            observed_at,
            shared_network: false,
        });
    }

    let run_links = |runner: &mut dyn CommandRunner, args: &[&str]| -> Result<Vec<JsonVal>, AdmissionError> {
        let cmd: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (ok, stdout) = runner.run(&cmd, None);
        if !ok || stdout.len() > MAX_IP_LINK_BYTES {
            return Err(AdmissionError::Value(
                "network interface proof unavailable".to_string(),
            ));
        }
        let parsed = JsonVal::parse(&stdout)
            .map_err(|_| AdmissionError::Value("network interface proof unavailable".to_string()))?;
        parsed
            .as_arr()
            .map(|a| a.to_vec())
            .ok_or_else(|| AdmissionError::Value("network interface proof unavailable".to_string()))
    };

    let pid_str = pid.to_string();
    let guest = run_links(
        runner,
        &["nsenter", "-t", &pid_str, "-n", "ip", "-d", "-j", "address", "show"],
    )?;
    let host = run_links(runner, &["ip", "-j", "link", "show"])?;

    let mut peers: BTreeMap<i64, JsonVal> = BTreeMap::new();
    for x in &host {
        if let Some(idx) = x.get_i64("ifindex") {
            peers.insert(idx, x.clone());
        }
    }

    let mut interfaces = BTreeSet::new();
    let mut proven = BTreeSet::new();
    let mut internal = BTreeSet::new();
    let mut actual_addresses = BTreeSet::new();

    for dev in &guest {
        let mut addresses = BTreeSet::new();
        if let Some(addr_info) = dev.get("addr_info").and_then(JsonVal::as_arr) {
            for a in addr_info {
                if a.get_str("scope") == Some("global") {
                    if let Some(local) = a.get_str("local") {
                        addresses.insert(policy::address(local)?);
                    }
                }
            }
        }
        let info_kind = dev
            .get("linkinfo")
            .and_then(|li| li.get_str("info_kind"))
            .unwrap_or("");
        let is_internal_kind = matches!(
            info_kind,
            "bridge" | "dummy" | "tun" | "wireguard" | "vxlan" | "ifb"
        );
        if !is_internal_kind {
            for a in &addresses {
                actual_addresses.insert(a.clone());
            }
        }
        let overlap: Vec<String> = addresses.intersection(&ips_set).cloned().collect();
        if overlap.is_empty() {
            continue;
        }
        if is_internal_kind {
            for a in overlap {
                internal.insert(a);
            }
            continue;
        }

        let link_index = dev.get_i64("link_index").unwrap_or(0);
        let peer = peers.get(&link_index);
        let mut iface_name = peer
            .and_then(|p| p.get_str("ifname"))
            .unwrap_or("")
            .to_string();
        let detail = if !iface_name.is_empty() {
            run_links(
                runner,
                &["ip", "-d", "-j", "link", "show", "dev", &iface_name],
            )?
        } else {
            Vec::new()
        };
        let is_veth = detail
            .first()
            .and_then(|d| d.get("linkinfo"))
            .and_then(|li| li.get_str("info_kind"))
            == Some("veth");
        if !is_valid_ifname(&iface_name) || !is_veth {
            return Err(AdmissionError::UnsupportedNetwork(UnsupportedNetwork::new(
                identity,
            )));
        }

        if let Some(master_val) = peer.and_then(|p| p.get("master")) {
            let has_master = match master_val {
                JsonVal::Null => false,
                JsonVal::Str(s) => !s.is_empty(),
                JsonVal::Num(n) => *n != 0.0,
                _ => false,
            };
            if has_master {
                let bridge = host.iter().find(|x| {
                    (master_val.as_i64().is_some() && x.get_i64("ifindex") == master_val.as_i64())
                        || (master_val.as_str().is_some()
                            && x.get_str("ifname") == master_val.as_str())
                });
                iface_name = bridge
                    .and_then(|b| b.get_str("ifname"))
                    .unwrap_or("")
                    .to_string();
                let br_detail = if !iface_name.is_empty() {
                    run_links(
                        runner,
                        &["ip", "-d", "-j", "link", "show", "dev", &iface_name],
                    )?
                } else {
                    Vec::new()
                };
                let is_bridge = br_detail
                    .first()
                    .and_then(|d| d.get("linkinfo"))
                    .and_then(|li| li.get_str("info_kind"))
                    == Some("bridge");
                if !is_valid_ifname(&iface_name) || !is_bridge {
                    return Err(AdmissionError::UnsupportedNetwork(UnsupportedNetwork::new(
                        identity,
                    )));
                }
            }
        }

        interfaces.insert(iface_name);
        for a in overlap {
            proven.insert(a);
        }
    }

    if sock_obs.epoch != incarnation_fn(pid)? {
        return Err(AdmissionError::Value(
            "container incarnation changed".to_string(),
        ));
    }
    if runtime == "runman" && actual_addresses != ips_set {
        return Err(AdmissionError::UnsupportedNetwork(UnsupportedNetwork::new(
            identity,
        )));
    }
    let union_proven_internal: BTreeSet<String> = proven.union(&internal).cloned().collect();
    if proven.is_empty() || union_proven_internal != ips_set {
        return Err(AdmissionError::UnsupportedNetwork(UnsupportedNetwork::new(
            identity,
        )));
    }

    Ok(ContainerSnapshot {
        instance_id: identity,
        ips: proven.into_iter().collect(),
        interfaces: interfaces.into_iter().collect(),
        epoch: sock_obs.epoch,
        flows: sock_obs.flows,
        inbound: sock_obs.inbound,
        listening_ports: sock_obs.listening,
        pid: Some(pid),
        observed_at,
        shared_network: false,
    })
}
