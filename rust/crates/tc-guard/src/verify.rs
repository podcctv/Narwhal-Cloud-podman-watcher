use std::collections::HashSet;
use std::collections::BTreeSet;

use runtime_drivers::{ContainerSample, JsonVal};

use crate::*;

// ---------------------------------------------------------------------------
// 8. Input models & runtime / network verification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInput {
    pub runtime: String,
    pub runtime_bin: String,
    pub project: String,
    pub name: String,
    pub id: String,
    pub instance_id: String,
    pub status: String,
    pub pid: Option<u32>,
}

impl From<&ContainerSample> for ContainerInput {
    fn from(c: &ContainerSample) -> Self {
        Self {
            runtime: c.runtime.clone(),
            runtime_bin: c.runtime_bin.clone(),
            project: c.project.clone(),
            name: c.name.clone(),
            id: c.id.clone(),
            instance_id: c.instance_id.clone(),
            status: c.status.clone(),
            pid: c.pid,
        }
    }
}

impl ContainerInput {
    pub(crate) fn identity(&self) -> (String, String, String, String) {
        let cid = if self.runtime == "runman" {
            self.instance_id.clone()
        } else if !self.id.is_empty() {
            self.id.clone()
        } else {
            String::new()
        };
        (
            self.runtime.clone(),
            self.project.clone(),
            self.name.clone(),
            cid,
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TrafficSampleInput {
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub container_id: String,
    pub traffic_counters_available: bool,
    pub net_tx_bps: Option<f64>,
    pub net_rx_bps: Option<f64>,
}

impl TrafficSampleInput {
    pub(crate) fn identity(&self) -> (String, String, String, String) {
        (
            self.runtime.clone(),
            self.project.clone(),
            self.container_name.clone(),
            self.container_id.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeInterfaceInput {
    pub name: String,
    pub kind: String,
    pub runtimes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerEntry {
    pub runtime: String,
    pub project: String,
    pub container_id: String,
    pub pid: u32,
}

fn parse_csv(raw: &str) -> Vec<Vec<String>> {
    if raw.is_empty() {
        return Vec::new();
    }
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut at_start = true;
    let mut chars = raw.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    let _ = chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(ch);
            }
            continue;
        }
        match ch {
            '"' if at_start => {
                in_quotes = true;
                at_start = false;
            }
            ',' => {
                row.push(std::mem::take(&mut field));
                at_start = true;
            }
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    let _ = chars.next();
                }
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                at_start = true;
            }
            '\n' => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
                at_start = true;
            }
            other => {
                field.push(other);
                at_start = false;
            }
        }
    }
    if !at_start || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// Read all running runtime peers (`incus`, `podman`, `runman`), including unmonitored peers.
pub fn running_container_inventory<R: TcRunner>(
    containers: &[ContainerInput],
    runner: &mut R,
) -> Result<Vec<PeerEntry>, BandwidthError> {
    let mut incus_bins: BTreeSet<String> = BTreeSet::new();
    let mut podman_bins: BTreeSet<String> = BTreeSet::new();

    for candidate in containers {
        if candidate.runtime != "incus" && candidate.runtime != "podman" {
            continue;
        }
        let binary = if candidate.runtime_bin.is_empty() {
            candidate.runtime.as_str()
        } else {
            candidate.runtime_bin.as_str()
        };
        if !is_valid_runtime_bin(binary) {
            return Err(BandwidthError::policy(
                "container runtime executable could not be verified",
            ));
        }
        let Some(resolved) = runner.which(binary) else {
            return Err(BandwidthError::policy(
                "container runtime inventory executable is unavailable",
            ));
        };
        if candidate.runtime == "incus" {
            incus_bins.insert(resolved);
        } else {
            podman_bins.insert(resolved);
        }
    }

    if let Some(resolved) = runner.which("incus") {
        incus_bins.insert(resolved);
    }
    if let Some(resolved) = runner.which("podman") {
        podman_bins.insert(resolved);
    }
    if podman_bins.is_empty() {
        if let Some(resolved) = runner.which("podman-remote") {
            podman_bins.insert(resolved);
        }
    }

    let mut peers: BTreeSet<PeerEntry> = BTreeSet::new();
    for item in containers {
        if item.runtime != "runman" || item.status != "running" {
            continue;
        }
        let pid = item.pid.unwrap_or(0);
        if !is_valid_uuid(&item.instance_id) || pid <= 1 {
            return Err(BandwidthError::policy(
                "running Runman inventory is incomplete; network isolation cannot be verified",
            ));
        }
        let project = if item.project.is_empty() {
            "default".to_string()
        } else {
            item.project.clone()
        };
        peers.insert(PeerEntry {
            runtime: "runman".to_string(),
            project,
            container_id: item.instance_id.to_ascii_lowercase(),
            pid,
        });
    }

    for binary in incus_bins {
        let (code, output) = runner.run_cmd(
            &[
                binary.as_str(),
                "list",
                "--all-projects",
                "type=container",
                "status=running",
                "--format=csv",
                "--columns=nepst",
            ],
            MAX_INVENTORY_OUTPUT + 1,
        );
        if code != 0 || output.len() > MAX_INVENTORY_OUTPUT {
            return Err(BandwidthError::policy(
                "all-running Incus inventory is unavailable",
            ));
        }
        let rows = parse_csv(&output);
        if rows.len() > MAX_INVENTORY_ITEMS {
            return Err(BandwidthError::policy(
                "all-running Incus inventory could not be verified",
            ));
        }
        for row in rows {
            if row.len() != 5 {
                return Err(BandwidthError::policy(
                    "all-running Incus inventory could not be verified",
                ));
            }
            let name = row[0].as_str();
            let project = if row[1].is_empty() {
                "default"
            } else {
                row[1].as_str()
            };
            let pid_text = row[2].as_str();
            let status = row[3].as_str();
            let instance_type = row[4].as_str();
            let pid = pid_text.parse::<u32>().unwrap_or(0);
            if !status.eq_ignore_ascii_case("RUNNING")
                || !instance_type.eq_ignore_ascii_case("CONTAINER")
                || name.is_empty()
                || pid <= 1
            {
                return Err(BandwidthError::policy(
                    "all-running Incus inventory could not be verified",
                ));
            }
            peers.insert(PeerEntry {
                runtime: "incus".to_string(),
                project: project.to_string(),
                container_id: name.to_string(),
                pid,
            });
        }
    }

    for binary in podman_bins {
        let (code, output) = runner.run_cmd(
            &[binary.as_str(), "ps", "--no-trunc", "--format", "{{.ID}}"],
            MAX_INVENTORY_OUTPUT + 1,
        );
        if code != 0 || output.len() > MAX_INVENTORY_OUTPUT {
            return Err(BandwidthError::policy(
                "all-running Podman inventory is unavailable",
            ));
        }
        let ids: Vec<&str> = if output.is_empty() {
            Vec::new()
        } else {
            output.split('\n').map(|s| s.trim_end_matches('\r')).collect()
        };
        if ids.len() > MAX_INVENTORY_ITEMS || ids.iter().any(|id| !is_valid_hex64_lower(id)) {
            return Err(BandwidthError::policy(
                "all-running Podman inventory could not be verified",
            ));
        }
        if ids.is_empty() {
            continue;
        }
        let mut args: Vec<&str> = Vec::with_capacity(4 + ids.len());
        args.extend([binary.as_str(), "inspect", "--format", "{{.Id}}|{{.State.Pid}}"]);
        args.extend(ids.iter().copied());
        let (code, inspect_out) = runner.run_cmd(&args, MAX_INVENTORY_OUTPUT + 1);
        let rows: Vec<&str> = if inspect_out.is_empty() {
            Vec::new()
        } else {
            inspect_out
                .split('\n')
                .map(|s| s.trim_end_matches('\r'))
                .collect()
        };
        if code != 0 || inspect_out.len() > MAX_INVENTORY_OUTPUT || rows.len() != ids.len() {
            return Err(BandwidthError::policy(
                "all-running Podman process inventory is unavailable",
            ));
        }
        let id_set: HashSet<&str> = ids.iter().copied().collect();
        let mut found_ids: HashSet<&str> = HashSet::with_capacity(ids.len());
        for row in rows {
            let Some((cid, pid_str)) = row.split_once('|') else {
                return Err(BandwidthError::policy(
                    "all-running Podman process inventory could not be verified",
                ));
            };
            if pid_str.contains('|') {
                return Err(BandwidthError::policy(
                    "all-running Podman process inventory could not be verified",
                ));
            }
            let pid = pid_str.parse::<u32>().unwrap_or(0);
            if !id_set.contains(cid) || !found_ids.insert(cid) || pid <= 1 {
                return Err(BandwidthError::policy(
                    "all-running Podman process inventory could not be verified",
                ));
            }
            peers.insert(PeerEntry {
                runtime: "podman".to_string(),
                project: String::new(),
                container_id: cid.to_string(),
                pid,
            });
        }
    }

    Ok(peers.into_iter().collect())
}

pub fn container_process_pid<R: TcRunner>(
    item: &NormalizedLimit,
    matched: &ContainerInput,
    runner: &mut R,
) -> Result<u32, BandwidthError> {
    let mut pid = matched.pid.unwrap_or(0);
    if item.runtime == "podman" && pid <= 1 {
        let runtime_bin = if matched.runtime_bin.is_empty() {
            "podman"
        } else {
            matched.runtime_bin.as_str()
        };
        if !is_valid_runtime_bin(runtime_bin) {
            return Err(BandwidthError::policy(
                "Podman runtime executable could not be verified",
            ));
        }
        let (code, output) = runner.run_cmd(
            &[
                runtime_bin,
                "inspect",
                "--format",
                "{{.Id}}|{{.State.Pid}}",
                item.container_name.as_str(),
            ],
            DEFAULT_OUTPUT_LIMIT,
        );
        let fields = output.split_once('|');
        let valid = match fields {
            Some((cid, _)) => code == 0 && cid.starts_with(&item.container_id),
            None => false,
        };
        if !valid {
            return Err(BandwidthError::policy(
                "Podman container ID or state could not be verified",
            ));
        }
        pid = fields
            .and_then(|(_, p)| p.parse::<u32>().ok())
            .unwrap_or(0);
    }
    if pid <= 1 {
        return Err(BandwidthError::policy(
            "container is not running or its init PID is unavailable",
        ));
    }
    Ok(pid)
}

pub fn verify_container_namespace<R: TcRunner>(
    item: &NormalizedLimit,
    pid: u32,
    namespace_inode: &str,
    containers: &[ContainerInput],
    peer_inventory: Option<&[PeerEntry]>,
    runner: &mut R,
) -> Result<(), BandwidthError> {
    let host_ns = runner.netns_inode(1).map_err(|_| {
        BandwidthError::policy(
            "host network namespace is unavailable; container isolation cannot be verified",
        )
    })?;
    if namespace_inode == host_ns.to_string() {
        return Err(BandwidthError::policy(
            "single-container limiting cannot target the host network namespace",
        ));
    }
    let owned_peers;
    let peers = match peer_inventory {
        Some(p) => p,
        None => {
            owned_peers = running_container_inventory(containers, runner)?;
            &owned_peers
        }
    };

    let mut target_found = false;
    for peer in peers {
        let is_target = peer.runtime == item.runtime
            && project_matches(&peer.runtime, &peer.project, &item.project)
            && if peer.runtime == "incus" || peer.runtime == "runman" {
                peer.container_id == item.container_id
            } else {
                peer.container_id.starts_with(&item.container_id)
            };
        if is_target && peer.pid != pid {
            return Err(BandwidthError::policy(
                "container process changed during isolation verification",
            ));
        }
        let peer_ns = runner
            .netns_inode(peer.pid)
            .map_err(|_| {
                BandwidthError::policy(
                    "running container peer namespace is unavailable; isolation cannot be verified",
                )
            })?
            .to_string();
        if is_target {
            target_found = true;
            if peer_ns != namespace_inode {
                return Err(BandwidthError::policy(
                    "container network namespace changed during verification",
                ));
            }
        } else if peer_ns == namespace_inode {
            return Err(BandwidthError::policy(
                "single-container limiting cannot target a shared container network namespace",
            ));
        }
    }
    if !target_found {
        return Err(BandwidthError::policy(
            "container is absent from the verified all-running runtime inventory",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub key: String,
    pub owner_key: String,
    pub scope: Scope,
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
}

pub(crate) fn call_with_prefix<R: TcRunner>(
    runner: &mut R,
    prefix: &[String],
    args: &[&str],
) -> (i32, String) {
    let mut full: Vec<&str> = Vec::with_capacity(prefix.len() + args.len());
    for p in prefix {
        full.push(p.as_str());
    }
    full.extend_from_slice(args);
    runner.run_cmd(&full, DEFAULT_OUTPUT_LIMIT)
}

fn parse_first_default_route_dev(json_str: &str) -> Option<String> {
    let JsonVal::Arr(routes) = JsonVal::parse(json_str).ok()? else {
        return None;
    };
    for route in routes {
        if let Some(dev) = route.get_str("dev") {
            if is_valid_iface_name(dev) {
                return Some(dev.to_string());
            }
        }
    }
    None
}

pub(crate) fn parse_link_indices(json_str: &str) -> Option<(u32, u32)> {
    let JsonVal::Arr(links) = JsonVal::parse(json_str).ok()? else {
        return None;
    };
    let first = links.first()?;
    let ifindex = first
        .get_u64("ifindex")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    let peer_index = first
        .get_u64("link_index")
        .or_else(|| first.get_u64("iflink"))
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    Some((ifindex, peer_index))
}

pub(crate) fn canonical_project<'a>(runtime: &str, project: &'a str) -> &'a str {
    if runtime == "podman" && project.is_empty() {
        "default"
    } else {
        project
    }
}

pub(crate) fn project_matches(runtime: &str, left: &str, right: &str) -> bool {
    canonical_project(runtime, left) == canonical_project(runtime, right)
}

pub fn resolve_entry<R: TcRunner>(
    host_id: &str,
    item: &NormalizedLimit,
    containers: &[ContainerInput],
    peer_inventory: Option<&[PeerEntry]>,
    runner: &mut R,
) -> Result<ResolvedTarget, BandwidthError> {
    if item.scope == Scope::Host {
        let iface = &item.interface;
        let interface_index = runner
            .host_ifindex(iface)
            .map_err(|_| BandwidthError::policy("selected host interface no longer exists"))?;
        let key = format!("host:{iface}");
        return Ok(ResolvedTarget {
            owner_key: format!("{host_id}:{key}"),
            key,
            scope: Scope::Host,
            runtime: String::new(),
            project: String::new(),
            container_name: String::new(),
            container_id: String::new(),
            prefix: Vec::new(),
            pid: 0,
            process_generation: String::new(),
            interface: iface.clone(),
            interface_index,
            peer_index: 0,
            namespace_inode: "host".to_string(),
        });
    }

    let matched = containers
        .iter()
        .find(|c| {
            let cid = if item.runtime == "runman" {
                c.instance_id.as_str()
            } else {
                c.id.as_str()
            };
            c.runtime == item.runtime
                && project_matches(&c.runtime, &c.project, &item.project)
                && c.name == item.container_name
                && cid == item.container_id
        })
        .ok_or_else(|| {
            BandwidthError::policy("container identity is not present in the current runtime inventory")
        })?;

    let pid = container_process_pid(item, matched, runner)?;
    let ns_inode = runner
        .netns_inode(pid)
        .map_err(|_| BandwidthError::policy("container process identity could not be verified"))?
        .to_string();
    let raw_stat = runner
        .read_proc_stat(pid)
        .map_err(|_| BandwidthError::policy("container process identity could not be verified"))?;
    let start_ticks = parse_proc_start_ticks(&raw_stat)
        .map_err(|_| BandwidthError::policy("container process identity could not be verified"))?;

    verify_container_namespace(item, pid, &ns_inode, containers, peer_inventory, runner)?;

    let prefix = vec![
        "nsenter".to_string(),
        "--target".to_string(),
        pid.to_string(),
        "--net".to_string(),
    ];
    let (code, route_out) =
        call_with_prefix(runner, &prefix, &["ip", "-j", "route", "show", "default"]);
    if code != 0 {
        return Err(BandwidthError::policy(
            "container default network interface is unavailable",
        ));
    }
    let interface = parse_first_default_route_dev(&route_out).ok_or_else(|| {
        BandwidthError::policy("container has no verified default route interface")
    })?;

    let (code, link_out) =
        call_with_prefix(runner, &prefix, &["ip", "-j", "link", "show", "dev", &interface]);
    if code != 0 {
        return Err(BandwidthError::policy(
            "container interface disappeared during verification",
        ));
    }
    let (interface_index, peer_index) = parse_link_indices(&link_out).unwrap_or((0, 0));
    if interface_index == 0 {
        return Err(BandwidthError::policy(
            "container interface index could not be verified",
        ));
    }

    let key = item.key();
    Ok(ResolvedTarget {
        owner_key: format!("{host_id}:{key}"),
        key,
        scope: Scope::Container,
        runtime: item.runtime.clone(),
        project: item.project.clone(),
        container_name: item.container_name.clone(),
        container_id: item.container_id.clone(),
        prefix,
        pid,
        process_generation: start_ticks,
        interface,
        interface_index,
        peer_index,
        namespace_inode: ns_inode,
    })
}
