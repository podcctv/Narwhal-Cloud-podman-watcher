use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use net_guard::{
    is_safe_instance_id, is_safe_project, is_safe_quarantine_name, is_uuid_lower,
    is_uuid_v4_lower, json_val_to_string, quarantine_target, read_json_journal,
    write_json_journal, PROTECTED_CONTAINERS,
};
use runtime_drivers::JsonVal;
use transport::sha256_hex;

use crate::linux::{
    packet, LiveNftRunner, Nft, NftRunner, NoopQueueBackend, QueueBackend,
};
use crate::observe::{
    parse_stat_start_ticks, ContainerDescriptor, ContainerSnapshot,
};
use crate::policy::{self, current_unix_ts_i64, Policy};
use crate::sni::{evaluate_inbound_sni, extract_l4_payload, SniDecision};
use crate::AdmissionError;

pub const DEFAULT_ADMISSION_JOURNAL: &str = "/var/lib/narwhal-monitor/admission.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueDirection {
    In,
    Out,
}

/// Return bounded, non-sensitive diagnostics `(code, stage, message)` for operator-facing receipts.
pub fn failure_details(
    error: Option<&AdmissionError>,
    stage: &str,
) -> (&'static str, &'static str, &'static str) {
    if stage == "ownership" {
        return (
            "ambiguous_ownership",
            "ownership",
            "容器地址或宿主机接口无法唯一归属；未确认保护规则已生效",
        );
    }
    let norm_stage = match stage {
        "startup" => "startup",
        "sampling" => "sampling",
        "ownership" => "ownership",
        _ => "enforcement",
    };
    let Some(err) = error else {
        return (
            "worker_error",
            norm_stage,
            "保护检查未完成，具体原因无法归类",
        );
    };
    match err {
        AdmissionError::UnsupportedNetwork(_) => (
            "unsupported_network",
            "sampling",
            "容器网络模式不在当前自动保护支持范围",
        ),
        AdmissionError::Timeout(_) => ("sample_timeout", "sampling", "容器网络采样命令超时"),
        AdmissionError::PermissionDenied(_) => (
            "permission_denied",
            norm_stage,
            "Agent 缺少读取网络或应用防火墙规则所需的权限",
        ),
        AdmissionError::DependencyUnavailable(_) => (
            "dependency_unavailable",
            norm_stage,
            "Agent 依赖的网络工具或内核接口不可用",
        ),
        AdmissionError::Runtime(_) => {
            if stage == "sampling" {
                (
                    "sample_failed",
                    "sampling",
                    "Incus/Podman 或网络采样接口返回失败",
                )
            } else {
                (
                    "firewall_apply_failed",
                    "enforcement",
                    "nftables/NFQUEUE 规则应用或内核读回失败",
                )
            }
        }
        AdmissionError::Value(_) => {
            if stage == "sampling" {
                ("sample_invalid", "sampling", "网络采样数据不完整或无效")
            } else {
                (
                    "firewall_apply_failed",
                    "enforcement",
                    "保护规则配置无效，未能完成应用或验证",
                )
            }
        }
        AdmissionError::Other(_) => (
            "worker_error",
            norm_stage,
            "保护检查未完成，具体原因无法归类",
        ),
    }
}

#[derive(Debug, Clone)]
pub struct AdmissionJournal {
    path: PathBuf,
}

impl Default for AdmissionJournal {
    fn default() -> Self {
        Self::new(Path::new(DEFAULT_ADMISSION_JOURNAL))
    }
}

impl AdmissionJournal {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read(&self) -> Result<BTreeMap<String, JsonVal>, AdmissionError> {
        read_json_journal(&self.path).map_err(AdmissionError::Runtime)
    }

    pub fn write(&self, data: &BTreeMap<String, JsonVal>) -> Result<(), AdmissionError> {
        write_json_journal(&self.path, data, ".admission-guard-", false)
            .map_err(AdmissionError::Runtime)
    }
}

#[derive(Debug, Clone)]
pub struct GuardRecord {
    pub table: String,
    pub queue: u16,
    pub ips: Vec<String>,
    pub container: ContainerDescriptor,
    pub verified_at: i64,
    pub epoch: String,
    pub interfaces: Vec<String>,
    pub pid: Option<u32>,
    pub listening_ports: Vec<u16>,
    pub fingerprint: String,
    pub applied_config: String,
    pub dirty: bool,
    pub disabled: bool,
    pub extra_fields: BTreeMap<String, JsonVal>,
}

impl GuardRecord {
    pub fn from_json_val(val: &JsonVal) -> Option<Self> {
        let obj = val.as_obj()?;
        let table = obj.get("table")?.as_str()?.to_string();
        let queue = obj.get("queue")?.as_u64()? as u16;
        let ips: Vec<String> = obj
            .get("ips")
            .and_then(JsonVal::as_arr)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let c_obj = obj.get("container")?.as_obj()?;
        let container = ContainerDescriptor {
            runtime: c_obj
                .get("runtime")
                .and_then(JsonVal::as_str)
                .unwrap_or("")
                .to_string(),
            project: c_obj
                .get("project")
                .and_then(JsonVal::as_str)
                .unwrap_or("")
                .to_string(),
            name: c_obj
                .get("name")
                .and_then(JsonVal::as_str)
                .unwrap_or("")
                .to_string(),
            id: c_obj
                .get("id")
                .and_then(JsonVal::as_str)
                .unwrap_or("")
                .to_string(),
            instance_id: String::new(),
            pid: None,
            network_addresses: Vec::new(),
        };
        let verified_at = obj
            .get("verified_at")
            .and_then(JsonVal::as_i64)
            .unwrap_or(0);
        let epoch = obj
            .get("epoch")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_string();
        let interfaces: Vec<String> = obj
            .get("interfaces")
            .and_then(JsonVal::as_arr)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let pid = obj
            .get("pid")
            .and_then(JsonVal::as_u64)
            .and_then(|v| u32::try_from(v).ok());
        let listening_ports: Vec<u16> = obj
            .get("listening_ports")
            .and_then(JsonVal::as_arr)
            .map(|a| {
                a.iter()
                    .filter_map(JsonVal::as_u64)
                    .filter_map(|p| u16::try_from(p).ok())
                    .filter(|&p| p > 0)
                    .collect()
            })
            .unwrap_or_default();
        let fingerprint = obj
            .get("fingerprint")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_string();
        let applied_config = obj
            .get("applied_config")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_string();
        let dirty = obj
            .get("dirty")
            .and_then(JsonVal::as_bool)
            .unwrap_or(false);
        let disabled = obj
            .get("disabled")
            .and_then(JsonVal::as_bool)
            .unwrap_or(false);
        let mut extra_fields = BTreeMap::new();
        for (k, v) in obj {
            if !matches!(
                k.as_str(),
                "table"
                    | "queue"
                    | "ips"
                    | "container"
                    | "verified_at"
                    | "epoch"
                    | "interfaces"
                    | "pid"
                    | "listening_ports"
                    | "fingerprint"
                    | "applied_config"
                    | "dirty"
                    | "disabled"
                    | "policy"
            ) {
                extra_fields.insert(k.clone(), v.clone());
            }
        }
        Some(Self {
            table,
            queue,
            ips,
            container,
            verified_at,
            epoch,
            interfaces,
            pid,
            listening_ports,
            fingerprint,
            applied_config,
            dirty,
            disabled,
            extra_fields,
        })
    }

    pub fn to_json_val(&self, policy: &Policy) -> JsonVal {
        let mut map = self.extra_fields.clone();
        map.insert("table".to_string(), JsonVal::Str(self.table.clone()));
        map.insert("queue".to_string(), JsonVal::Num(self.queue as f64));
        map.insert(
            "ips".to_string(),
            JsonVal::Arr(self.ips.iter().cloned().map(JsonVal::Str).collect()),
        );
        let mut c_map = BTreeMap::new();
        c_map.insert(
            "runtime".to_string(),
            JsonVal::Str(self.container.runtime.clone()),
        );
        if !self.container.project.is_empty() {
            c_map.insert(
                "project".to_string(),
                JsonVal::Str(self.container.project.clone()),
            );
        }
        c_map.insert(
            "name".to_string(),
            JsonVal::Str(self.container.name.clone()),
        );
        if !self.container.id.is_empty() {
            c_map.insert("id".to_string(), JsonVal::Str(self.container.id.clone()));
        }
        map.insert("container".to_string(), JsonVal::Obj(c_map));
        map.insert(
            "verified_at".to_string(),
            JsonVal::Num(self.verified_at as f64),
        );
        map.insert("epoch".to_string(), JsonVal::Str(self.epoch.clone()));
        map.insert(
            "interfaces".to_string(),
            JsonVal::Arr(self.interfaces.iter().cloned().map(JsonVal::Str).collect()),
        );
        match self.pid {
            Some(p) => {
                map.insert("pid".to_string(), JsonVal::Num(p as f64));
            }
            None => {
                map.insert("pid".to_string(), JsonVal::Null);
            }
        }
        map.insert(
            "listening_ports".to_string(),
            JsonVal::Arr(
                self.listening_ports
                    .iter()
                    .map(|&p| JsonVal::Num(p as f64))
                    .collect(),
            ),
        );
        if !self.fingerprint.is_empty() {
            map.insert(
                "fingerprint".to_string(),
                JsonVal::Str(self.fingerprint.clone()),
            );
        }
        if !self.applied_config.is_empty() {
            map.insert(
                "applied_config".to_string(),
                JsonVal::Str(self.applied_config.clone()),
            );
        }
        if self.dirty {
            map.insert("dirty".to_string(), JsonVal::Bool(true));
        }
        if self.disabled {
            map.insert("disabled".to_string(), JsonVal::Bool(true));
        }
        map.insert("policy".to_string(), policy.to_json_val());
        JsonVal::Obj(map)
    }
}

pub fn parse_target_key(key: &str) -> Option<(String, String, String, String)> {
    let val = JsonVal::parse(key).ok()?;
    let arr = val.as_arr()?;
    if arr.len() != 4 {
        return None;
    }
    Some((
        arr[0].as_str()?.to_string(),
        arr[1].as_str()?.to_string(),
        arr[2].as_str()?.to_string(),
        arr[3].as_str()?.to_string(),
    ))
}

/// Deterministic queue number: `20000 + 2 * (u32_be(sha256(key)[:4]) % 20000)`.
pub fn deterministic_queue_base(key: &str) -> u16 {
    let digest = transport::sha256(key.as_bytes());
    let word = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    20000 + 2 * ((word % 20000) as u16)
}

pub fn compute_desired_config_hash(
    ips: &[String],
    interfaces: &[String],
    epoch: &str,
    limited: bool,
    source_limit: usize,
    listening_ports: &[u16],
) -> String {
    let arr = JsonVal::Arr(vec![
        JsonVal::Arr(ips.iter().cloned().map(JsonVal::Str).collect()),
        JsonVal::Arr(interfaces.iter().cloned().map(JsonVal::Str).collect()),
        JsonVal::Str(epoch.to_string()),
        JsonVal::Bool(limited),
        JsonVal::Num(source_limit as f64),
        JsonVal::Arr(
            listening_ports
                .iter()
                .map(|&p| JsonVal::Num(p as f64))
                .collect(),
        ),
    ]);
    let json = json_val_to_string(&arr, false);
    sha256_hex(json.as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NotificationSignature {
    pub runtime: String,
    pub project: String,
    pub name: String,
    pub alert_type: String,
    pub review_at: Option<i64>,
    pub state: Option<String>,
    pub failure_code: Option<String>,
    pub failure_stage: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniViolationEvent {
    pub container_key: String,
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub instance_id: String,
    pub src_ip: String,
    pub dst_port: u16,
    pub proto: u8,
    pub sni: Option<String>,
    pub reason: String,
    pub ts: i64,
}

pub struct GuardState<R: NftRunner = LiveNftRunner> {
    pub journal: AdmissionJournal,
    pub nft: Nft<R>,
    pub source_limit: usize,
    pub records: BTreeMap<String, GuardRecord>,
    pub states: BTreeMap<String, Policy>,
    pub by_queue: BTreeMap<u16, (String, QueueDirection)>,
    pub results: BTreeMap<(String, String, String), BTreeMap<String, JsonVal>>,
    pub notifications: BTreeMap<NotificationSignature, i64>,
    pub sni_enforcement: bool,
    pub cn_lookup: Option<Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync>>,
    pub sni_violations: Vec<SniViolationEvent>,
    pub sni_dedup: BTreeMap<(String, u16, String, String), i64>,
}

pub struct Guard<R: NftRunner = LiveNftRunner, Q: QueueBackend = NoopQueueBackend> {
    inner: Mutex<GuardState<R>>,
    queues: Mutex<Q>,
    ready: Mutex<bool>,
}

impl Guard<LiveNftRunner, NoopQueueBackend> {
    pub fn open_default() -> Result<Self, AdmissionError> {
        Self::new(
            AdmissionJournal::default(),
            Nft::default(),
            NoopQueueBackend::new(),
            None,
        )
    }
}

#[cfg(unix)]
impl Guard<LiveNftRunner, crate::linux::SubprocessNfqBackend> {
    /// Opens a live Unix `Guard` backed by `SubprocessNfqBackend` (`libnetfilter_queue`).
    pub fn open_live_unix() -> Result<Arc<Self>, AdmissionError> {
        let guard_slot: Arc<
            Mutex<Option<std::sync::Weak<Guard<LiveNftRunner, crate::linux::SubprocessNfqBackend>>>>,
        > = Arc::new(Mutex::new(None));
        let slot_for_cb = Arc::clone(&guard_slot);
        let backend = crate::linux::SubprocessNfqBackend::new(move |queue, raw| {
            let weak = slot_for_cb.lock().ok().and_then(|g| g.clone());
            if let Some(w) = weak {
                if let Some(g) = w.upgrade() {
                    return g.decision(queue, raw).unwrap_or(false);
                }
            }
            false
        })?;
        let guard = Arc::new(Self::new(
            AdmissionJournal::default(),
            Nft::default(),
            backend,
            None,
        )?);
        if let Ok(mut slot) = guard_slot.lock() {
            *slot = Some(Arc::downgrade(&guard));
        }
        Ok(guard)
    }
}

impl<R: NftRunner, Q: QueueBackend> Guard<R, Q> {
    pub fn new(
        journal: AdmissionJournal,
        nft: Nft<R>,
        queues: Q,
        source_limit: Option<usize>,
    ) -> Result<Self, AdmissionError> {
        let raw_records = journal.read()?;
        let effective_limit = source_limit
            .unwrap_or_else(policy::source_limit_from_env)
            .min(policy::MAX_SOURCE_LIMIT);

        let mut records = BTreeMap::new();
        let mut states = BTreeMap::new();
        for (key, val) in &raw_records {
            if let Some(rec) = GuardRecord::from_json_val(val) {
                let pol = Policy::new(val.get("policy"), effective_limit);
                records.insert(key.clone(), rec);
                states.insert(key.clone(), pol);
            }
        }

        Ok(Self {
            inner: Mutex::new(GuardState {
                journal,
                nft,
                source_limit: effective_limit,
                records,
                states,
                by_queue: BTreeMap::new(),
                results: BTreeMap::new(),
                notifications: BTreeMap::new(),
                sni_enforcement: true,
                cn_lookup: None,
                sni_violations: Vec::new(),
                sni_dedup: BTreeMap::new(),
            }),
            queues: Mutex::new(queues),
            ready: Mutex::new(false),
        })
    }

    pub fn with_inner<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut GuardState<R>) -> T,
    {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut guard)
    }

    pub fn with_queues<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut Q) -> T,
    {
        let mut q = match self.queues.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut q)
    }

    pub fn source_limit(&self) -> usize {
        self.with_inner(|s| s.source_limit)
    }

    pub fn save(&self) -> Result<(), AdmissionError> {
        self.with_inner(Self::save_locked)
    }

    fn save_locked(inner: &mut GuardState<R>) -> Result<(), AdmissionError> {
        let mut out = BTreeMap::new();
        for (key, rec) in &inner.records {
            let pol = inner
                .states
                .get(key)
                .cloned()
                .unwrap_or_else(|| Policy::new(None, inner.source_limit));
            out.insert(key.clone(), rec.to_json_val(&pol));
        }
        inner.journal.write(&out)
    }

    pub fn set_sni_enforcement(
        &self,
        enabled: bool,
        cn_lookup: Option<Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync>>,
    ) {
        self.with_inner(|inner| {
            inner.sni_enforcement = enabled;
            inner.cn_lookup = cn_lookup;
        });
    }

    pub fn drain_sni_violations(&self) -> Vec<SniViolationEvent> {
        self.with_inner(|inner| std::mem::take(&mut inner.sni_violations))
    }

    pub fn decision(&self, queue: u16, raw: &[u8]) -> Result<bool, AdmissionError> {
        self.decision_at(queue, raw, current_unix_ts_i64())
    }

    pub fn decision_at(&self, queue: u16, raw: &[u8], now: i64) -> Result<bool, AdmissionError> {
        let (src, dst, proto, sport, dport) = packet(raw)?;
        self.with_inner(|inner| {
            let Some((key, direction)) = inner.by_queue.get(&queue).cloned() else {
                return Ok(false);
            };
            let Some(record) = inner.records.get(&key).cloned() else {
                return Ok(false);
            };
            if now - record.verified_at > 30 {
                return Ok(false);
            }
            let target_ip = match direction {
                QueueDirection::In => &dst,
                QueueDirection::Out => &src,
            };
            if !record.ips.iter().any(|ip| ip == target_ip) {
                return Ok(false);
            }
            let flow = match direction {
                QueueDirection::In => (dst.clone(), dport, src.clone(), sport),
                QueueDirection::Out => (src.clone(), sport, dst.clone(), dport),
            };
            if direction == QueueDirection::Out {
                let state = inner
                    .states
                    .entry(key.clone())
                    .or_insert_with(|| Policy::new(None, inner.source_limit));
                if proto == 6 && !state.admit_tcp(&flow, now) {
                    return Ok(false);
                }
                return Ok(true);
            }
            if inner.sni_enforcement {
                if let Some(l4) = extract_l4_payload(raw) {
                    let is_cn_src = inner
                        .cn_lookup
                        .as_ref()
                        .is_some_and(|f| f(l4.src_ip));
                    if let SniDecision::Block {
                        reason,
                        sni,
                        proto: vproto,
                        dport: vdport,
                        src_ip,
                    } = evaluate_inbound_sni(raw, is_cn_src)
                    {
                        let dedup_key = (
                            key.clone(),
                            vdport,
                            sni.clone().unwrap_or_default(),
                            reason.to_string(),
                        );
                        let recently_logged = inner
                            .sni_dedup
                            .get(&dedup_key)
                            .is_some_and(|&prev| now - prev < 60);
                        if !recently_logged && inner.sni_violations.len() < 256 {
                            inner.sni_dedup.insert(dedup_key, now);
                            if inner.sni_dedup.len() > 1024 {
                                inner.sni_dedup.retain(|_, ts| now - *ts < 60);
                            }
                            inner.sni_violations.push(SniViolationEvent {
                                container_key: key.clone(),
                                runtime: record.container.runtime.clone(),
                                project: record.container.project.clone(),
                                container_name: record.container.name.clone(),
                                instance_id: record.container.instance_id.clone(),
                                src_ip: src_ip.to_string(),
                                dst_port: vdport,
                                proto: vproto,
                                sni,
                                reason: reason.to_string(),
                                ts: now,
                            });
                        }
                        return Ok(false);
                    }
                    // Established TCP handshake payload packets queued for SNI inspection
                    // must not be re-counted in SYN concurrency/source admission limits.
                    if proto == 6 && (l4.tcp_flags & 0x02) == 0 {
                        return Ok(true);
                    }
                }
            }
            let state = inner
                .states
                .entry(key.clone())
                .or_insert_with(|| Policy::new(None, inner.source_limit));
            if proto == 6 && !state.admit_tcp(&flow, now) {
                return Ok(false);
            }
            if proto == 6
                && !record.listening_ports.is_empty()
                && !record.listening_ports.contains(&dport)
            {
                return Ok(true);
            }
            let (accepted, changed) = state.admit_source(&src, now)?;
            if !accepted {
                return Ok(false);
            }
            if changed {
                let norm_ip = policy::address(&src)?;
                let is_confirmed = inner
                    .states
                    .get(&key)
                    .is_some_and(|st| st.sources.iter().any(|s| s.ip == norm_ip && s.confirmed));
                let _ = Self::save_locked(inner);
                if is_confirmed {
                    let _ = inner.nft.admit(&record.table, &norm_ip);
                }
            }
            Ok(true)
        })
    }

    pub fn start(&self) -> Result<(), AdmissionError> {
        let mut ready = match self.ready.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let is_healthy = self.with_queues(|q| q.healthy());
        if *ready && !is_healthy {
            return Err(AdmissionError::Runtime(
                "NFQUEUE worker is unhealthy".to_string(),
            ));
        }
        *ready = true;
        Ok(())
    }

    pub fn update(
        &self,
        container: &ContainerDescriptor,
        snapshot: &ContainerSnapshot,
        now: Option<i64>,
    ) -> Result<BTreeMap<String, JsonVal>, AdmissionError> {
        let now = now.unwrap_or_else(current_unix_ts_i64);
        let runtime = container.runtime.as_str();
        let project = container.normalized_project();
        let name = container.name.as_str();
        let identity = snapshot.instance_id.as_str();
        let key =
            quarantine_target(runtime, project, name, identity).map_err(AdmissionError::Value)?;

        let mut ips_set = BTreeSet::new();
        for raw_ip in &snapshot.ips {
            ips_set.insert(policy::address(raw_ip)?);
        }
        let ips: Vec<String> = ips_set.into_iter().collect();
        let interfaces = snapshot.interfaces.clone();
        if ips.is_empty() || ips.len() > 32 || snapshot.shared_network {
            return Err(AdmissionError::Value(
                "private unshared container addresses required".to_string(),
            ));
        }
        let epoch = snapshot.epoch.as_str();
        if epoch.is_empty() {
            return Err(AdmissionError::Value(
                "container incarnation unavailable".to_string(),
            ));
        }
        if now - snapshot.observed_at > 30 {
            return Err(AdmissionError::Value(
                "container sample expired".to_string(),
            ));
        }

        let mut listening_ports: Vec<u16> = snapshot
            .listening_ports
            .iter()
            .copied()
            .filter(|&p| p > 0)
            .collect();
        listening_ports.sort_unstable();
        listening_ports.dedup();
        if listening_ports.len() > 64 {
            listening_ports.truncate(64);
        }

        self.start()?;

        // Phase 1: update in-memory record/queue map under lock, then release lock BEFORE calling queues.add.
        let (queue_num, mut fresh) = self.with_inner(|inner| -> Result<(u16, bool), AdmissionError> {
            let existing_keys: Vec<String> = inner.records.keys().cloned().collect();
            for old in existing_keys {
                if old == key {
                    continue;
                }
                let matches_same_instance = inner.records.get(&old).is_some_and(|entry| {
                    entry.container.runtime == runtime
                        && entry.container.normalized_project() == project
                        && parse_target_key(&old).is_some_and(|(_, _, _, id)| id == identity)
                });
                if matches_same_instance {
                    if let Some(mut moved_rec) = inner.records.remove(&old) {
                        moved_rec.container = container.clone();
                        inner.records.insert(key.clone(), moved_rec);
                    }
                    if let Some(moved_state) = inner.states.remove(&old) {
                        inner.states.insert(key.clone(), moved_state);
                    }
                    for (_, (target, _)) in inner.by_queue.iter_mut() {
                        if *target == old {
                            *target = key.clone();
                        }
                    }
                }
            }

            let ips_lookup: BTreeSet<&String> = ips.iter().collect();
            let iface_lookup: BTreeSet<&String> = interfaces.iter().collect();
            for (other, record) in &inner.records {
                if other != &key && !record.disabled {
                    let has_ip_overlap = record.ips.iter().any(|ip| ips_lookup.contains(ip));
                    let has_iface_overlap = record
                        .interfaces
                        .iter()
                        .any(|iface| iface_lookup.contains(iface));
                    if has_ip_overlap && has_iface_overlap {
                        return Err(AdmissionError::Value(
                            "ambiguous container address; manual review required".to_string(),
                        ));
                    }
                }
            }

            let fresh = !inner.records.contains_key(&key);
            if fresh {
                let digest = sha256_hex(key.as_bytes());
                let mut queue = deterministic_queue_base(&key);
                let occupied: BTreeSet<u16> = inner.records.values().map(|r| r.queue).collect();
                while occupied.contains(&queue) {
                    queue = 20000 + ((queue - 20000 + 2) % 40000);
                }
                let rec = GuardRecord {
                    table: format!("nwguard_{}", &digest[..16]),
                    queue,
                    ips: ips.clone(),
                    container: container.clone(),
                    verified_at: now,
                    epoch: epoch.to_string(),
                    interfaces: interfaces.clone(),
                    pid: snapshot.pid,
                    listening_ports: listening_ports.clone(),
                    fingerprint: String::new(),
                    applied_config: String::new(),
                    dirty: false,
                    disabled: false,
                    extra_fields: BTreeMap::new(),
                };
                inner.records.insert(key.clone(), rec);
                inner
                    .states
                    .insert(key.clone(), Policy::new(None, inner.source_limit));
            }

            let queue_num = inner.records[&key].queue;
            inner
                .by_queue
                .insert(queue_num, (key.clone(), QueueDirection::In));
            inner
                .by_queue
                .insert(queue_num + 1, (key.clone(), QueueDirection::Out));
            Ok((queue_num, fresh))
        })?;

        // Phase 2: Register queues WITHOUT holding the Guard inner policy lock!
        self.with_queues(|q| -> Result<(), AdmissionError> {
            q.add(queue_num)?;
            q.add(queue_num + 1)?;
            Ok(())
        })?;

        // Phase 3: Re-acquire lock to observe state, apply nftables if needed, and verify readback.
        self.with_inner(|inner| -> Result<BTreeMap<String, JsonVal>, AdmissionError> {
            let table_name = inner
                .records
                .get(&key)
                .ok_or_else(|| AdmissionError::Runtime("missing guard record".to_string()))?
                .table
                .clone();

            let live_sources: BTreeSet<String> = if !fresh {
                match inner.nft.live(&table_name) {
                    Ok(live) => live,
                    Err(_) => {
                        fresh = true;
                        snapshot.inbound.iter().cloned().collect()
                    }
                }
            } else {
                snapshot.inbound.iter().cloned().collect()
            };

            let source_limit = inner.source_limit;
            let state = inner
                .states
                .entry(key.clone())
                .or_insert_with(|| Policy::new(None, source_limit));
            let mut changed = state.observe(
                &snapshot.flows,
                &snapshot.inbound,
                &live_sources,
                Some(now),
                true,
                epoch,
            );
            let is_limited = state.is_limited();
            let confirmed_only: Vec<String> = state
                .sources
                .iter()
                .filter(|s| s.confirmed)
                .map(|s| s.ip.clone())
                .collect();

            let digest = inner.nft.digests.get(&table_name).cloned().unwrap_or_default();
            let desired = compute_desired_config_hash(
                &ips,
                &interfaces,
                epoch,
                is_limited,
                source_limit,
                &listening_ports,
            );

            {
                let rec = inner.records.get_mut(&key).unwrap();
                changed = changed
                    || fresh
                    || rec.dirty
                    || rec.disabled
                    || digest.is_empty()
                    || rec.fingerprint != digest
                    || rec.applied_config != desired;
                rec.ips = ips.clone();
                rec.epoch = epoch.to_string();
                rec.verified_at = now;
                rec.interfaces = interfaces.clone();
                rec.pid = snapshot.pid;
                rec.listening_ports = listening_ports.clone();
            }
            Self::save_locked(inner)?;

            if changed {
                inner.nft.apply(
                    &table_name,
                    &ips,
                    queue_num,
                    &confirmed_only,
                    is_limited,
                    &[],
                    &interfaces,
                    source_limit,
                    policy::SOURCE_IDLE as u64,
                    &listening_ports,
                )?;
            }

            // Mandatory readback verification: a missing/overwritten table is never green.
            inner.nft.live(&table_name)?;
            let new_digest = inner.nft.digests.get(&table_name).cloned().unwrap_or_default();
            {
                let rec = inner.records.get_mut(&key).unwrap();
                rec.fingerprint = new_digest;
                rec.applied_config = desired;
                rec.dirty = false;
                rec.disabled = false;
            }
            Self::save_locked(inner)?;

            let mut result = inner.states[&key].status();
            result.insert(
                "instance_id".to_string(),
                JsonVal::Str(identity.to_string()),
            );
            result.insert("state".to_string(), JsonVal::Str("enforced".to_string()));
            let eff_limit = if source_limit > 0 { source_limit } else { 5 };
            result.insert("source_limit".to_string(), JsonVal::Num(eff_limit as f64));
            result.insert(
                "source_limit_enforced".to_string(),
                JsonVal::Bool(source_limit > 0),
            );
            result.insert(
                "source_policy".to_string(),
                JsonVal::Str(
                    if source_limit > 0 {
                        "active_limit_enforced"
                    } else {
                        "observe_only"
                    }
                    .to_string(),
                ),
            );
            result.insert(
                "tcp_limit".to_string(),
                if is_limited {
                    JsonVal::Num(500.0)
                } else {
                    JsonVal::Null
                },
            );
            result.insert("observed_at".to_string(), JsonVal::Num(now as f64));

            inner.results.insert(
                (runtime.to_string(), project.to_string(), name.to_string()),
                result.clone(),
            );
            Ok(result)
        })
    }

    pub fn withdraw_unsupported(
        &self,
        container: &ContainerDescriptor,
        identity: &str,
    ) -> Result<(), AdmissionError> {
        let runtime = container.runtime.as_str();
        let project = container.normalized_project();
        self.with_inner(|inner| {
            let matching_keys: Vec<String> = inner
                .records
                .keys()
                .filter(|k| {
                    parse_target_key(k).is_some_and(|(rt, prj, _, stable)| {
                        rt == runtime && prj == project && stable == identity
                    })
                })
                .cloned()
                .collect();
            for key in matching_keys {
                let table = inner.records[&key].table.clone();
                inner.nft.remove(&table)?;
                if let Some(rec) = inner.records.get_mut(&key) {
                    rec.disabled = true;
                    rec.dirty = true;
                    rec.verified_at = 0;
                }
            }
            Self::save_locked(inner)
        })
    }

    pub fn retire_exited(&self) -> Result<(), AdmissionError> {
        self.retire_exited_from_proc(Path::new("/proc"))
    }

    pub fn retire_exited_from_proc(&self, proc_root: &Path) -> Result<(), AdmissionError> {
        let removed_queues = self.with_inner(|inner| -> Result<Vec<u16>, AdmissionError> {
            let mut removed = Vec::new();
            let keys: Vec<String> = inner.records.keys().cloned().collect();
            for key in keys {
                let Some(pid) = inner.records[&key].pid else {
                    continue;
                };
                if pid <= 1 {
                    continue;
                }
                let stat_path = proc_root.join(pid.to_string()).join("stat");
                let gone = match fs::read_to_string(&stat_path) {
                    Ok(text) => {
                        let Some(actual) = parse_stat_start_ticks(&text) else {
                            continue;
                        };
                        let expected = inner.records[&key]
                            .epoch
                            .rsplit(':')
                            .next()
                            .unwrap_or("");
                        actual != expected
                    }
                    Err(e) if e.kind() == ErrorKind::NotFound => true,
                    Err(_) => continue,
                };
                if !gone {
                    continue;
                }
                let table = inner.records[&key].table.clone();
                if inner.nft.remove(&table).is_err() {
                    continue;
                }
                if let Some(rec) = inner.records.remove(&key) {
                    inner.states.remove(&key);
                    inner.results.remove(&(
                        rec.container.runtime.clone(),
                        rec.container.normalized_project().to_string(),
                        rec.container.name.clone(),
                    ));
                }
                let q_keys: Vec<u16> = inner
                    .by_queue
                    .iter()
                    .filter(|(_, (target, _))| target == &key)
                    .map(|(&q, _)| q)
                    .collect();
                for q in q_keys {
                    inner.by_queue.remove(&q);
                    removed.push(q);
                }
            }
            Self::save_locked(inner)?;
            Ok(removed)
        })?;

        // Queue control calls must not hold the callback's policy lock.
        self.with_queues(|q| {
            for queue in removed_queues {
                let _ = q.remove(queue);
            }
        });
        Ok(())
    }

    pub fn failed(
        &self,
        container: &ContainerDescriptor,
        now: i64,
        reason: Option<&AdmissionError>,
        stage: &str,
    ) {
        let (code, norm_stage, message) = failure_details(reason, stage);
        let key_tuple = (
            container.runtime.clone(),
            container.normalized_project().to_string(),
            container.name.clone(),
        );
        self.with_inner(|inner| {
            let mut updated = inner.results.get(&key_tuple).cloned().unwrap_or_default();
            updated.insert("state".to_string(), JsonVal::Str("unverified".to_string()));
            updated.insert("error".to_string(), JsonVal::Str(message.to_string()));
            updated.insert("failure_code".to_string(), JsonVal::Str(code.to_string()));
            updated.insert(
                "failure_stage".to_string(),
                JsonVal::Str(norm_stage.to_string()),
            );
            updated.insert("observed_at".to_string(), JsonVal::Num(now as f64));
            inner.results.insert(key_tuple.clone(), updated);

            let matching_targets: Vec<String> = inner
                .records
                .iter()
                .filter(|(_, rec)| {
                    (
                        rec.container.runtime.clone(),
                        rec.container.normalized_project().to_string(),
                        rec.container.name.clone(),
                    ) == key_tuple
                })
                .map(|(t, _)| t.clone())
                .collect();
            let empty_flows = BTreeSet::new();
            let empty_live = BTreeSet::new();
            for target in matching_targets {
                if let Some(st) = inner.states.get_mut(&target) {
                    st.observe(&empty_flows, &[], &empty_live, Some(now), false, "");
                }
                if let Some(rec) = inner.records.get_mut(&target) {
                    rec.dirty = true;
                    rec.verified_at = 0;
                }
            }
            let _ = Self::save_locked(inner);
        });
    }

    pub fn status(&self, container: &ContainerDescriptor) -> BTreeMap<String, JsonVal> {
        self.status_at(container, current_unix_ts_i64())
    }

    pub fn status_at(&self, container: &ContainerDescriptor, now: i64) -> BTreeMap<String, JsonVal> {
        let key_tuple = (
            container.runtime.clone(),
            container.normalized_project().to_string(),
            container.name.clone(),
        );
        let mut result = self
            .with_inner(|inner| {
                let mut res = inner.results.get(&key_tuple).cloned()?;
                if res.get("state").and_then(JsonVal::as_str) == Some("enforced") {
                    if let Some((target_key, _)) = inner.records.iter().find(|(_, rec)| {
                        (
                            rec.container.runtime.clone(),
                            rec.container.normalized_project().to_string(),
                            rec.container.name.clone(),
                        ) == key_tuple
                    }) {
                        if let Some(st) = inner.states.get(target_key) {
                            for (k, v) in st.status() {
                                res.insert(k, v);
                            }
                        }
                    }
                }
                Some(res)
            })
            .unwrap_or_default();
        if !result.is_empty() && result.get("state").and_then(JsonVal::as_str) == Some("enforced") {
            let observed_at = result
                .get("observed_at")
                .and_then(JsonVal::as_i64)
                .unwrap_or(0);
            if now - observed_at > 30 {
                result.insert("state".to_string(), JsonVal::Str("unverified".to_string()));
                result.insert(
                    "error".to_string(),
                    JsonVal::Str("本地保护采样已过期，不能确认当前状态".to_string()),
                );
                result.insert(
                    "failure_code".to_string(),
                    JsonVal::Str("stale_sample".to_string()),
                );
                result.insert(
                    "failure_stage".to_string(),
                    JsonVal::Str("sampling".to_string()),
                );
            }
        }
        result
    }

    pub fn alerts(&self, container: &ContainerDescriptor) -> Vec<BTreeMap<String, JsonVal>> {
        self.alerts_at(container, current_unix_ts_i64())
    }

    pub fn alerts_at(
        &self,
        container: &ContainerDescriptor,
        now: i64,
    ) -> Vec<BTreeMap<String, JsonVal>> {
        let status = self.status_at(container, now);
        if status.is_empty() {
            return Vec::new();
        }
        if status.get("state").and_then(JsonVal::as_str) != Some("enforced") {
            return Vec::new();
        }
        let instance_id = status
            .get("instance_id")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_string();
        let mut base = BTreeMap::new();
        base.insert(
            "runtime".to_string(),
            JsonVal::Str(container.runtime.clone()),
        );
        base.insert(
            "project".to_string(),
            JsonVal::Str(container.normalized_project().to_string()),
        );
        base.insert(
            "container_name".to_string(),
            JsonVal::Str(container.name.clone()),
        );
        base.insert("instance_id".to_string(), JsonVal::Str(instance_id));
        base.insert("admission".to_string(), JsonVal::Obj(status.clone()));

        let mut result = Vec::new();
        if status.get("limited").and_then(JsonVal::as_bool) == Some(true) {
            let tcp_conns = status
                .get("tcp_connections")
                .and_then(JsonVal::as_i64)
                .unwrap_or(0);
            let review_at = status
                .get("review_at")
                .and_then(JsonVal::as_i64)
                .map_or_else(|| "None".to_string(), |v| v.to_string());
            let extensions = status
                .get("extensions")
                .and_then(JsonVal::as_i64)
                .unwrap_or(0);
            let mut alert = base.clone();
            alert.insert(
                "type".to_string(),
                JsonVal::Str("tcp_concurrency_limited".to_string()),
            );
            alert.insert("severity".to_string(), JsonVal::Str("warning".to_string()));
            alert.insert(
                "title".to_string(),
                JsonVal::Str("TCP 并发已限制为 500".to_string()),
            );
            alert.insert(
                "message".to_string(),
                JsonVal::Str(format!(
                    "当前 TCP 并发 {tcp_conns}；新连接上限 500，本轮复查时间 {review_at}，已续期 {extensions} 次；已有连接自然回落。"
                )),
            );
            alert.insert("value".to_string(), JsonVal::Num(tcp_conns as f64));
            alert.insert("threshold".to_string(), JsonVal::Num(500.0));
            result.push(alert);
        }

        if status
            .get("source_limit_enforced")
            .and_then(JsonVal::as_bool)
            == Some(true)
        {
            let mut active_keys = Vec::new();
            if let Some(JsonVal::Obj(blocked)) = status.get("blocked") {
                for (ip, v) in blocked {
                    let last_seen = v.get_i64("last_seen").unwrap_or(0);
                    if now - last_seen < 120 {
                        active_keys.push(ip.clone());
                    }
                }
            }
            if !active_keys.is_empty() {
                let limit = status
                    .get("source_limit")
                    .and_then(JsonVal::as_i64)
                    .unwrap_or(10);
                let sample_ips: Vec<String> = active_keys.iter().take(5).cloned().collect();
                let blocked_ips = sample_ips.join("、");
                let confirmed_len = status
                    .get("confirmed_sources")
                    .or_else(|| status.get("sources"))
                    .and_then(JsonVal::as_arr)
                    .map_or(0, <[JsonVal]>::len);
                let val = confirmed_len + active_keys.len();

                let mut alert = base;
                alert.insert(
                    "type".to_string(),
                    JsonVal::Str("inbound_source_blocked".to_string()),
                );
                alert.insert("severity".to_string(), JsonVal::Str("warning".to_string()));
                alert.insert(
                    "title".to_string(),
                    JsonVal::Str(format!(
                        "单容器并发业务已达 {limit} IP 上限并阻断新连接"
                    )),
                );
                alert.insert(
                    "message".to_string(),
                    JsonVal::Str(format!(
                        "当前活跃并发业务来源已达上限 {limit} 个；已阻断 {} 个超限新来源。拦截来源示例：{blocked_ips}。已有业务连接不受影响；常规端口扫描不占用名额；来源闲置 2 分钟后自动释放名额。",
                        active_keys.len()
                    )),
                );
                alert.insert("value".to_string(), JsonVal::Num(val as f64));
                alert.insert("threshold".to_string(), JsonVal::Num(limit as f64));
                result.push(alert);
            }
        }

        result
    }
}

/// Explicit rollback/uninstall (`admission_guard.py --release-all`) after stopping the service.
pub fn release_owned() -> Result<(), AdmissionError> {
    let journal = AdmissionJournal::default();
    let mut runner = LiveNftRunner::default();
    release_owned_with(&journal, &mut runner)
}

pub fn release_owned_with<R: NftRunner>(
    journal: &AdmissionJournal,
    runner: &mut R,
) -> Result<(), AdmissionError> {
    let records = journal.read()?;
    if records.is_empty() {
        return Ok(());
    }
    let list_cmd = vec![
        "nft".to_string(),
        "-j".to_string(),
        "list".to_string(),
        "tables".to_string(),
    ];
    let raw = runner.run(&list_cmd, None)?;
    let parsed = JsonVal::parse(&raw)
        .map_err(|_| AdmissionError::Value("invalid nft tables JSON".to_string()))?;
    let mut live_tables = BTreeSet::new();
    if let Some(arr) = parsed.get("nftables").and_then(JsonVal::as_arr) {
        for item in arr {
            if let Some(tb) = item.get("table") {
                if tb.get_str("family") == Some("inet") {
                    if let Some(name) = tb.get_str("name") {
                        live_tables.insert(name.to_string());
                    }
                }
            }
        }
    }
    let mut nft = Nft::new(ClosureNftRunnerProxy { runner });
    for record in records.values() {
        if let Some(table) = record.get_str("table") {
            if live_tables.contains(table) {
                nft.remove(table)?;
            }
        }
    }
    journal.write(&BTreeMap::new())
}

struct ClosureNftRunnerProxy<'a, R: NftRunner> {
    runner: &'a mut R,
}

impl<'a, R: NftRunner> NftRunner for ClosureNftRunnerProxy<'a, R> {
    fn run(&mut self, args: &[String], data: Option<&str>) -> Result<String, AdmissionError> {
        self.runner.run(args, data)
    }
}

pub fn handle_cli_args(args: &[String]) -> Result<(), String> {
    if args.len() != 1 || args[0] != "--release-all" {
        return Err("explicit --release-all required".to_string());
    }
    release_owned().map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// AdmissionController & Server Receipt / Payload Builders (`server/admission_api.py`)
// ---------------------------------------------------------------------------

pub struct AdmissionController<R: NftRunner = LiveNftRunner, Q: QueueBackend = NoopQueueBackend> {
    pub guard: Arc<Guard<R, Q>>,
    pub latest_targets: Mutex<BTreeMap<(String, String, String), ContainerDescriptor>>,
    pub error: Mutex<String>,
}

impl<R: NftRunner, Q: QueueBackend> AdmissionController<R, Q> {
    pub fn new(guard: Arc<Guard<R, Q>>) -> Self {
        Self {
            guard,
            latest_targets: Mutex::new(BTreeMap::new()),
            error: Mutex::new(String::new()),
        }
    }

    /// Execute one complete batch of container snapshots with fail-closed overlap conflict resolution.
    pub fn run_batch<F>(&self, inventory: &[ContainerDescriptor], mut provider: F, now: i64)
    where
        F: FnMut(&ContainerDescriptor) -> Result<ContainerSnapshot, AdmissionError>,
    {
        let targets: Vec<ContainerDescriptor> = inventory
            .iter()
            .filter(|c| {
                matches!(c.runtime.as_str(), "incus" | "podman" | "runman")
                    && !PROTECTED_CONTAINERS.contains(&c.name.as_str())
            })
            .cloned()
            .collect();

        if targets.len() > 1000 {
            if let Ok(mut err) = self.error.lock() {
                *err = "容器数量超过保护容量".to_string();
            }
            return;
        }

        let _ = self.guard.retire_exited();

        {
            if let Ok(mut latest) = self.latest_targets.lock() {
                latest.clear();
                for c in &targets {
                    latest.insert(
                        (
                            c.runtime.clone(),
                            c.normalized_project().to_string(),
                            c.name.clone(),
                        ),
                        c.clone(),
                    );
                }
            }
        }

        let mut snapshots: Vec<(ContainerDescriptor, ContainerSnapshot)> = Vec::new();
        for container in &targets {
            match provider(container) {
                Ok(snap) => snapshots.push((container.clone(), snap)),
                Err(err) => {
                    if let AdmissionError::UnsupportedNetwork(ref un) = err {
                        let _ = self.guard.withdraw_unsupported(container, &un.instance_id);
                    }
                    self.guard.failed(container, now, Some(&err), "sampling");
                }
            }
        }

        let mut conflicts = BTreeSet::new();
        let mut ownership: BTreeMap<(String, String), usize> = BTreeMap::new();
        for (index, (_, snap)) in snapshots.iter().enumerate() {
            for ip in &snap.ips {
                for dev in &snap.interfaces {
                    let slot = (dev.clone(), ip.clone());
                    if let Some(&prev_idx) = ownership.get(&slot) {
                        conflicts.insert(index);
                        conflicts.insert(prev_idx);
                    }
                    ownership.insert(slot, index);
                }
            }
        }

        for (index, (container, snap)) in snapshots.iter().enumerate() {
            if conflicts.contains(&index) {
                let _ = self
                    .guard
                    .withdraw_unsupported(container, &snap.instance_id);
                let conflict_err =
                    AdmissionError::Value("ambiguous network ownership".to_string());
                self.guard
                    .failed(container, now, Some(&conflict_err), "ownership");
                continue;
            }
            if let Err(err) = self.guard.update(container, snap, Some(now)) {
                self.guard
                    .failed(container, now, Some(&err), "enforcement");
            }
        }

        if let Ok(mut err) = self.error.lock() {
            err.clear();
        }
    }

    pub fn collect_status_items(&self, now: i64) -> Vec<JsonVal> {
        let targets: Vec<ContainerDescriptor> = self
            .latest_targets
            .lock()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        let mut items = Vec::new();
        for container in targets {
            let value = self.guard.status_at(&container, now);
            if !value.is_empty() {
                let instance_id = value
                    .get("instance_id")
                    .and_then(JsonVal::as_str)
                    .unwrap_or("")
                    .to_string();
                let mut item = BTreeMap::new();
                item.insert(
                    "runtime".to_string(),
                    JsonVal::Str(container.runtime.clone()),
                );
                item.insert(
                    "project".to_string(),
                    JsonVal::Str(container.normalized_project().to_string()),
                );
                item.insert(
                    "container_name".to_string(),
                    JsonVal::Str(container.name.clone()),
                );
                item.insert("instance_id".to_string(), JsonVal::Str(instance_id));
                item.insert("admission".to_string(), JsonVal::Obj(value));
                items.push(JsonVal::Obj(item));
            }
        }
        items
    }

    /// Collect alerts due for emission (enforcing 300s cooldown and 86400s retention).
    pub fn collect_due_notifications(
        &self,
        now: i64,
    ) -> Vec<(ContainerDescriptor, BTreeMap<String, JsonVal>)> {
        let targets: Vec<ContainerDescriptor> = self
            .latest_targets
            .lock()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        let mut due = Vec::new();
        for container in targets {
            let alerts = self.guard.alerts_at(&container, now);
            for alert in alerts {
                let Some(JsonVal::Obj(ref adm)) = alert.get("admission") else {
                    continue;
                };
                let alert_type = alert
                    .get("type")
                    .and_then(JsonVal::as_str)
                    .unwrap_or("")
                    .to_string();
                let sig = NotificationSignature {
                    runtime: container.runtime.clone(),
                    project: container.normalized_project().to_string(),
                    name: container.name.clone(),
                    alert_type,
                    review_at: adm.get("review_at").and_then(JsonVal::as_i64),
                    state: adm
                        .get("state")
                        .and_then(JsonVal::as_str)
                        .map(ToString::to_string),
                    failure_code: adm
                        .get("failure_code")
                        .and_then(JsonVal::as_str)
                        .map(ToString::to_string),
                    failure_stage: adm
                        .get("failure_stage")
                        .and_then(JsonVal::as_str)
                        .map(ToString::to_string),
                };
                let should_emit = self.guard.with_inner(|inner| {
                    if let Some(&last_sent) = inner.notifications.get(&sig) {
                        if now - last_sent < 300 {
                            return false;
                        }
                    }
                    inner.notifications.insert(sig, now);
                    inner.notifications.retain(|_, &mut ts| now - ts < 86400);
                    true
                });
                if should_emit {
                    due.push((container.clone(), alert));
                }
            }
        }
        due
    }
}

pub fn build_status_payload_json(
    host_id: &str,
    node_id: &str,
    timestamp: i64,
    items: &[JsonVal],
) -> String {
    let mut map = BTreeMap::new();
    map.insert("host_id".to_string(), JsonVal::Str(host_id.to_string()));
    map.insert("node_id".to_string(), JsonVal::Str(node_id.to_string()));
    map.insert("timestamp".to_string(), JsonVal::Num(timestamp as f64));
    map.insert("items".to_string(), JsonVal::Arr(items.to_vec()));
    json_val_to_string(&JsonVal::Obj(map), false)
}

pub fn build_event_payload_json(
    host_id: &str,
    node_id: &str,
    timestamp: i64,
    alert: &BTreeMap<String, JsonVal>,
) -> String {
    let mut map = BTreeMap::new();
    map.insert("host_id".to_string(), JsonVal::Str(host_id.to_string()));
    map.insert("node_id".to_string(), JsonVal::Str(node_id.to_string()));
    map.insert("timestamp".to_string(), JsonVal::Num(timestamp as f64));
    map.insert("alert".to_string(), JsonVal::Obj(alert.clone()));
    json_val_to_string(&JsonVal::Obj(map), false)
}

fn failure_explanation(code: &str) -> (&'static str, &'static str) {
    match code {
        "ambiguous_ownership" => (
            "ambiguous_ownership",
            "容器地址或宿主机接口无法唯一归属；未确认保护规则已生效。",
        ),
        "unsupported_network" => (
            "unsupported_network",
            "该容器网络模式不在当前自动保护支持范围内。",
        ),
        "sample_timeout" => (
            "sample_timeout",
            "容器网络采样命令超时，无法确认当前网络状态。",
        ),
        "permission_denied" => (
            "permission_denied",
            "Agent 缺少读取网络或应用防火墙规则所需的权限。",
        ),
        "dependency_unavailable" => (
            "dependency_unavailable",
            "Agent 依赖的网络工具或内核接口不可用。",
        ),
        "sample_failed" => ("sample_failed", "Incus/Podman 或网络采样接口返回失败。"),
        "firewall_apply_failed" => (
            "firewall_apply_failed",
            "nftables/NFQUEUE 规则应用或内核读回失败，保护未能确认。",
        ),
        "sample_invalid" => (
            "sample_invalid",
            "网络采样数据不完整或无效，保护未能确认。",
        ),
        "stale_sample" => (
            "stale_sample",
            "最近一次保护状态采样已超过 30 秒，无法确认仍有效。",
        ),
        "worker_error" => (
            "worker_error",
            "保护检查未完成，具体原因无法归类；请查看节点 Agent 日志。",
        ),
        _ => ("unknown", "该节点未上报具体失败原因，请查看节点 Agent 日志。"),
    }
}

fn stage_explanation(stage: &str) -> (&'static str, &'static str) {
    match stage {
        "startup" => ("startup", "启动检查"),
        "sampling" => ("sampling", "网络采样"),
        "ownership" => ("ownership", "网络归属检查"),
        "enforcement" => ("enforcement", "防火墙应用/验证"),
        _ => ("unknown", "状态检查"),
    }
}

fn is_valid_remediation_target(s: &str) -> bool {
    let bytes = s.as_bytes();
    (1..=240).contains(&bytes.len())
        && bytes.iter().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'_' | b'.' | b'/' | b'@' | b':' | b'+' | b'-')
        })
}

/// Normalize and validate an admission alert/receipt matching `server/admission_api.py:normalized_alert`.
pub fn normalized_alert(value: &JsonVal, now: i64) -> Result<JsonVal, String> {
    let obj = value
        .as_obj()
        .ok_or_else(|| "unsupported admission event".to_string())?;
    let kind = obj
        .get("type")
        .and_then(JsonVal::as_str)
        .ok_or_else(|| "unsupported admission event".to_string())?;
    if !matches!(
        kind,
        "inbound_source_blocked"
            | "tcp_concurrency_limited"
            | "admission_unverified"
            | "pasarguard_node_removed"
    ) {
        return Err("unsupported admission event".to_string());
    }

    let runtime = obj
        .get("runtime")
        .and_then(JsonVal::as_str)
        .unwrap_or("");
    let project = obj
        .get("project")
        .and_then(JsonVal::as_str)
        .unwrap_or("");
    let name = obj
        .get("container_name")
        .and_then(JsonVal::as_str)
        .unwrap_or("");
    let identity = obj
        .get("instance_id")
        .and_then(JsonVal::as_str)
        .unwrap_or("");

    let is_valid_name = {
        let b = name.as_bytes();
        (1..=200).contains(&b.len())
            && b.iter().all(|ch| {
                ch.is_ascii_alphanumeric()
                    || matches!(ch, b'_' | b'.' | b':' | b'@' | b'+' | b'-')
            })
    };
    if !matches!(runtime, "incus" | "podman" | "runman") || !is_valid_name {
        return Err("supported instance required".to_string());
    }
    if !project.is_empty() && !is_safe_project(project) {
        return Err("invalid project".to_string());
    }
    if !identity.is_empty() && !is_safe_instance_id(identity) {
        return Err("invalid identity".to_string());
    }
    if runtime == "runman"
        && (project != "default"
            || !is_uuid_lower(name)
            || (!identity.is_empty() && !is_uuid_v4_lower(identity)))
    {
        return Err(
            "Runman requires default project, canonical VM UUID and UUID v4 generation".to_string(),
        );
    }
    if identity.is_empty() && kind != "admission_unverified" {
        return Err("stable identity required".to_string());
    }
    let _ = is_safe_quarantine_name;

    let mut clean = BTreeMap::new();
    clean.insert("runtime".to_string(), JsonVal::Str(runtime.to_string()));
    clean.insert("project".to_string(), JsonVal::Str(project.to_string()));
    clean.insert("container_name".to_string(), JsonVal::Str(name.to_string()));
    clean.insert("instance_id".to_string(), JsonVal::Str(identity.to_string()));
    clean.insert("type".to_string(), JsonVal::Str(kind.to_string()));
    clean.insert(
        "severity".to_string(),
        JsonVal::Str(
            if kind == "pasarguard_node_removed" {
                "critical"
            } else {
                "warning"
            }
            .to_string(),
        ),
    );
    clean.insert("value".to_string(), JsonVal::Num(0.0));
    clean.insert(
        "threshold".to_string(),
        JsonVal::Num(if kind == "inbound_source_blocked" {
            5.0
        } else {
            500.0
        }),
    );

    if kind == "pasarguard_node_removed" {
        let rem = obj
            .get("automatic_remediation")
            .and_then(JsonVal::as_obj)
            .ok_or_else(|| "invalid cleanup receipt".to_string())?;
        let raw_items = rem
            .get("items")
            .and_then(JsonVal::as_arr)
            .ok_or_else(|| "invalid cleanup receipt".to_string())?;
        let mut items = Vec::new();
        for item in raw_items.iter().take(20) {
            let Some(item_obj) = item.as_obj() else {
                continue;
            };
            let k = item_obj.get("kind").and_then(JsonVal::as_str).unwrap_or("");
            let st = item_obj
                .get("status")
                .and_then(JsonVal::as_str)
                .unwrap_or("");
            let tgt = item_obj
                .get("target")
                .and_then(JsonVal::as_str)
                .unwrap_or("");
            if matches!(k, "service" | "binary" | "startup")
                && matches!(st, "ok" | "failed")
                && is_valid_remediation_target(tgt)
            {
                let mut m = BTreeMap::new();
                m.insert("kind".to_string(), JsonVal::Str(k.to_string()));
                m.insert("target".to_string(), JsonVal::Str(tgt.to_string()));
                m.insert("status".to_string(), JsonVal::Str(st.to_string()));
                items.push(JsonVal::Obj(m));
            }
        }
        let succeeded = rem.get("succeeded").and_then(JsonVal::as_bool) == Some(true)
            && !items.is_empty()
            && items
                .iter()
                .all(|x| x.get_str("status") == Some("ok"));
        let item_count = items.len();
        clean.insert(
            "title".to_string(),
            JsonVal::Str(format!(
                "禁止运行 PasarGuard Node：{}",
                if succeeded {
                    "已禁用服务"
                } else {
                    "清理未完成"
                }
            )),
        );
        clean.insert(
            "message".to_string(),
            JsonVal::Str(
                if succeeded {
                    "已停止并禁用确认归属的 PasarGuard Node 服务，保留客户实例及数据。"
                } else {
                    "确认存在 PasarGuard Node，但服务清理未完整验证，需管理员处理。"
                }
                .to_string(),
            ),
        );
        let mut rem_out = BTreeMap::new();
        rem_out.insert("attempted".to_string(), JsonVal::Bool(true));
        rem_out.insert("succeeded".to_string(), JsonVal::Bool(succeeded));
        rem_out.insert("items".to_string(), JsonVal::Arr(items));
        clean.insert("automatic_remediation".to_string(), JsonVal::Obj(rem_out));
        clean.insert("value".to_string(), JsonVal::Num(item_count as f64));
        clean.insert("threshold".to_string(), JsonVal::Num(0.0));
        return Ok(JsonVal::Obj(clean));
    }

    let source = obj
        .get("admission")
        .and_then(JsonVal::as_obj)
        .ok_or_else(|| "invalid admission facts".to_string())?;
    if let Some(s) = source.get("sources") {
        if s.as_arr().is_none() {
            return Err("invalid admission facts".to_string());
        }
    }
    if let Some(b) = source.get("blocked") {
        if b.as_obj().is_none() {
            return Err("invalid admission facts".to_string());
        }
    }

    let mut data = BTreeMap::new();
    for k in [
        "tcp_connections",
        "sampled_at",
        "observed_at",
        "blocked_packets",
        "tcp_denied",
        "limited_since",
        "review_at",
        "extensions",
        "recovered_at",
    ] {
        if let Some(v) = source.get(k).and_then(JsonVal::as_i64) {
            if (0..1_000_000_000_000_000).contains(&v) {
                data.insert(k.to_string(), JsonVal::Num(v as f64));
            }
        }
    }

    let mut unverified_err_prefix = String::new();
    if kind == "admission_unverified" {
        let raw_code = source
            .get("failure_code")
            .and_then(JsonVal::as_str)
            .unwrap_or("unknown");
        let raw_stage = source
            .get("failure_stage")
            .and_then(JsonVal::as_str)
            .unwrap_or("unknown");
        let (code_key, code_desc) = failure_explanation(raw_code);
        let (stage_key, stage_desc) = stage_explanation(raw_stage);
        data.insert("failure_code".to_string(), JsonVal::Str(code_key.to_string()));
        data.insert(
            "failure_stage".to_string(),
            JsonVal::Str(stage_key.to_string()),
        );
        unverified_err_prefix = format!("{stage_desc}未通过：{code_desc}");
        data.insert(
            "error".to_string(),
            JsonVal::Str(unverified_err_prefix.clone()),
        );
    }

    let source_limit_enforced =
        source.get("source_limit_enforced").and_then(JsonVal::as_bool) != Some(false);
    let raw_limit = source.get("source_limit").and_then(JsonVal::as_i64);
    let source_limit = raw_limit.unwrap_or(if source_limit_enforced { 10 } else { 5 });
    let default_policy = if source_limit_enforced && raw_limit.is_some() {
        "active_limit_enforced"
    } else if source_limit_enforced {
        "first_five_enforced"
    } else {
        "observe_only"
    };
    let source_policy = source
        .get("source_policy")
        .and_then(JsonVal::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(default_policy);

    let state_str = match source.get("state").and_then(JsonVal::as_str) {
        Some("enforced") => "enforced",
        Some("unavailable") => "unavailable",
        _ => "unverified",
    };
    let limited_bool = source.get("limited").and_then(JsonVal::as_bool) == Some(true);

    data.insert("state".to_string(), JsonVal::Str(state_str.to_string()));
    data.insert("limited".to_string(), JsonVal::Bool(limited_bool));
    data.insert("source_limit".to_string(), JsonVal::Num(source_limit as f64));
    data.insert(
        "source_limit_enforced".to_string(),
        JsonVal::Bool(source_limit_enforced),
    );
    data.insert(
        "source_policy".to_string(),
        JsonVal::Str(source_policy.to_string()),
    );
    data.insert(
        "tcp_limit".to_string(),
        if limited_bool {
            JsonVal::Num(500.0)
        } else {
            JsonVal::Null
        },
    );

    let max_sources = if source_limit_enforced {
        source_limit.max(5) as usize
    } else {
        5
    };
    let mut clean_sources = Vec::new();
    if let Some(arr) = source.get("sources").and_then(JsonVal::as_arr) {
        for item in arr.iter().take(max_sources) {
            let item_obj = item
                .as_obj()
                .ok_or_else(|| "invalid bounded source facts".to_string())?;
            let ip_str = item_obj
                .get("ip")
                .and_then(JsonVal::as_str)
                .ok_or_else(|| "invalid bounded source facts".to_string())?;
            let parsed_ip: IpAddr = ip_str
                .parse()
                .map_err(|_| "invalid bounded source facts".to_string())?;
            let first_seen = item_obj
                .get("first_seen")
                .and_then(JsonVal::as_i64)
                .ok_or_else(|| "invalid bounded source facts".to_string())?
                .max(0);
            let confirmed = item_obj
                .get("confirmed")
                .and_then(JsonVal::as_bool)
                .unwrap_or(true);
            let mut sm = BTreeMap::new();
            sm.insert("ip".to_string(), JsonVal::Str(parsed_ip.to_string()));
            sm.insert("first_seen".to_string(), JsonVal::Num(first_seen as f64));
            sm.insert("confirmed".to_string(), JsonVal::Bool(confirmed));
            clean_sources.push(JsonVal::Obj(sm));
        }
    }
    let clean_sources_len = clean_sources.len();
    data.insert("sources".to_string(), JsonVal::Arr(clean_sources));

    if let Some(conf_arr) = source.get("confirmed_sources").and_then(JsonVal::as_arr) {
        let mut clean_conf = Vec::new();
        for item in conf_arr.iter().take(max_sources) {
            if let (Some(ip_str), Some(fs)) = (
                item.get_str("ip"),
                item.get_i64("first_seen"),
            ) {
                if let Ok(parsed_ip) = ip_str.parse::<IpAddr>() {
                    let mut cm = BTreeMap::new();
                    cm.insert("ip".to_string(), JsonVal::Str(parsed_ip.to_string()));
                    cm.insert("first_seen".to_string(), JsonVal::Num(fs.max(0) as f64));
                    clean_conf.push(JsonVal::Obj(cm));
                }
            }
        }
        data.insert("confirmed_sources".to_string(), JsonVal::Arr(clean_conf));
    }

    let mut clean_blocked = BTreeMap::new();
    if let Some(blk_obj) = source.get("blocked").and_then(JsonVal::as_obj) {
        for (ip_str, item) in blk_obj.iter().take(32) {
            let parsed_ip: IpAddr = ip_str
                .parse()
                .map_err(|_| "invalid bounded source facts".to_string())?;
            let item_obj = item
                .as_obj()
                .ok_or_else(|| "invalid bounded source facts".to_string())?;
            let mut bm = BTreeMap::new();
            for k in ["first_seen", "last_seen", "packets"] {
                let v = item_obj
                    .get(k)
                    .and_then(JsonVal::as_i64)
                    .unwrap_or(0)
                    .clamp(0, 1_000_000_000_000_000);
                bm.insert(k.to_string(), JsonVal::Num(v as f64));
            }
            clean_blocked.insert(parsed_ip.to_string(), JsonVal::Obj(bm));
        }
    }
    let clean_blocked_len = clean_blocked.len();
    data.insert("blocked".to_string(), JsonVal::Obj(clean_blocked));

    let observed_at = data
        .get("observed_at")
        .and_then(JsonVal::as_i64)
        .unwrap_or(0);
    if kind != "admission_unverified" && (state_str != "enforced" || (now - observed_at).abs() > 30)
    {
        return Err("fresh verified enforcement receipt required".to_string());
    }

    let tcp_conns = data
        .get("tcp_connections")
        .and_then(JsonVal::as_i64)
        .unwrap_or(0);
    let extensions = data
        .get("extensions")
        .and_then(JsonVal::as_i64)
        .unwrap_or(0);

    let title = match kind {
        "inbound_source_blocked" => {
            format!("单容器并发业务已达 {source_limit} IP 上限并阻断新连接")
        }
        "tcp_concurrency_limited" => "TCP 新连接上限已设为 500".to_string(),
        _ => "容器网络保护未确认生效".to_string(),
    };
    let message = match kind {
        "inbound_source_blocked" => format!(
            "活跃并发业务来源已达上限 {source_limit} 个，已阻断超出上限的新来源连接；不影响已有业务连接与常规端口扫描探测。"
        ),
        "tcp_concurrency_limited" => format!(
            "TCP 当前 {tcp_conns} 条，新连接上限 500，已续期 {extensions} 次。已有连接自然回落，通知失败不影响保护。"
        ),
        _ => format!(
            "{unverified_err_prefix}这表示保护状态待核实，不代表已确认攻击，也不能认定保护已生效。"
        ),
    };

    let threshold = if kind == "inbound_source_blocked" && raw_limit.is_some() {
        source_limit as f64
    } else if kind == "inbound_source_blocked" {
        5.0
    } else {
        500.0
    };
    let value_num = if kind == "tcp_concurrency_limited" {
        tcp_conns as f64
    } else {
        (clean_sources_len + clean_blocked_len) as f64
    };

    clean.insert("title".to_string(), JsonVal::Str(title));
    clean.insert("message".to_string(), JsonVal::Str(message));
    clean.insert("admission".to_string(), JsonVal::Obj(data));
    clean.insert("threshold".to_string(), JsonVal::Num(threshold));
    clean.insert("value".to_string(), JsonVal::Num(value_num));

    Ok(JsonVal::Obj(clean))
}
