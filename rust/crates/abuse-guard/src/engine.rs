use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use net_guard::{
    json_val_to_string, quarantine_entry, quarantine_target, safe_evidence, IsolationDriver,
    QuarantineJournal, PROTECTED_CONTAINERS,
};
use runtime_drivers::JsonVal;
use transport::sha256_hex;

use crate::detection::{
    evaluate_process, network_evidence, Finding, ProcessRecord, SocketRecord, SourceFeatures,
};

pub fn kind_title(kind: &str) -> &str {
    match kind {
        "outbound_scan" => "对外扫描",
        "authentication_bruteforce" => "认证爆破",
        "credential_stuffing" => "撞库",
        "identity_enumeration" => "身份信息枚举",
        "bandwidth_monetization" => "挂机卖带宽 / P2P 代理节点",
        _ => kind,
    }
}

pub fn now_unix_secs_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerTarget {
    pub runtime: String,
    pub runtime_bin: String,
    pub project: String,
    pub name: String,
    pub id: String,
    pub pid: Option<u32>,
    pub stable_id: String,
    pub instance_id: String,
}

impl ContainerTarget {
    pub fn normalized_project(&self) -> &str {
        &self.project
    }

    pub fn telemetry_identity(&self) -> &str {
        if self.runtime == "runman" {
            &self.instance_id
        } else if !self.stable_id.is_empty() {
            &self.stable_id
        } else {
            &self.id
        }
    }

    pub fn identity_key(&self) -> (String, String, String) {
        (
            self.runtime.clone(),
            self.project.clone(),
            self.name.clone(),
        )
    }
}

pub trait AbuseIsolationDriver: IsolationDriver {
    fn check_evidence(&mut self, _findings: &[Finding]) -> Result<(), String> {
        Ok(())
    }
}

pub struct PlainIsolationDriver<D: IsolationDriver>(pub D);

impl<D: IsolationDriver> IsolationDriver for PlainIsolationDriver<D> {
    fn snapshot(&mut self) -> Result<JsonVal, String> {
        self.0.snapshot()
    }
    fn refresh_backup(&mut self, backup: &mut JsonVal) -> Result<(), String> {
        self.0.refresh_backup(backup)
    }
    fn isolate(&mut self, backup: &JsonVal) -> Result<(), String> {
        self.0.isolate(backup)
    }
    fn verify(&mut self, backup: &JsonVal) -> Result<(), String> {
        self.0.verify(backup)
    }
    fn release(&mut self, backup: &JsonVal) -> Result<net_guard::DriverReleaseOutcome, String> {
        self.0.release(backup)
    }
    fn prove_replaced(&mut self) -> Result<String, String> {
        self.0.prove_replaced()
    }
}

impl<D: IsolationDriver> AbuseIsolationDriver for PlainIsolationDriver<D> {}

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkQuarantineOutcome {
    pub status: String,
    pub ingress_blocked: bool,
    pub egress_blocked: bool,
    pub verified_at: Option<u64>,
    pub error: Option<String>,
    pub data_preserved: bool,
}

impl NetworkQuarantineOutcome {
    pub fn from_json_val(val: &JsonVal) -> Self {
        Self {
            status: val
                .get_str("status")
                .unwrap_or("failed")
                .to_string(),
            ingress_blocked: val.get_bool("ingress_blocked").unwrap_or(false),
            egress_blocked: val.get_bool("egress_blocked").unwrap_or(false),
            verified_at: val.get_u64("verified_at"),
            error: val.get_str("error").map(ToString::to_string),
            data_preserved: val.get_bool("data_preserved").unwrap_or(true),
        }
    }

    pub fn to_json_val(&self) -> JsonVal {
        let mut map = BTreeMap::new();
        map.insert("status".to_string(), JsonVal::Str(self.status.clone()));
        map.insert(
            "ingress_blocked".to_string(),
            JsonVal::Bool(self.ingress_blocked),
        );
        map.insert(
            "egress_blocked".to_string(),
            JsonVal::Bool(self.egress_blocked),
        );
        if let Some(ts) = self.verified_at {
            map.insert("verified_at".to_string(), JsonVal::Num(ts as f64));
        }
        if let Some(ref err) = self.error {
            map.insert("error".to_string(), JsonVal::Str(err.clone()));
        }
        map.insert(
            "data_preserved".to_string(),
            JsonVal::Bool(self.data_preserved),
        );
        JsonVal::Obj(map)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AbuseAlert {
    pub alert_type: String,
    pub severity: String,
    pub title: String,
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub instance_id: String,
    pub message: String,
    pub value: usize,
    pub threshold: usize,
    pub abuse_evidence: Vec<JsonVal>,
    pub network_quarantine: NetworkQuarantineOutcome,
}

impl AbuseAlert {
    pub fn to_json_val(&self) -> JsonVal {
        let mut map = BTreeMap::new();
        map.insert("type".to_string(), JsonVal::Str(self.alert_type.clone()));
        map.insert("severity".to_string(), JsonVal::Str(self.severity.clone()));
        map.insert("title".to_string(), JsonVal::Str(self.title.clone()));
        map.insert("runtime".to_string(), JsonVal::Str(self.runtime.clone()));
        map.insert("project".to_string(), JsonVal::Str(self.project.clone()));
        map.insert(
            "container_name".to_string(),
            JsonVal::Str(self.container_name.clone()),
        );
        map.insert(
            "instance_id".to_string(),
            JsonVal::Str(self.instance_id.clone()),
        );
        map.insert("message".to_string(), JsonVal::Str(self.message.clone()));
        map.insert("value".to_string(), JsonVal::Num(self.value as f64));
        map.insert("threshold".to_string(), JsonVal::Num(self.threshold as f64));
        map.insert(
            "abuse_evidence".to_string(),
            JsonVal::Arr(self.abuse_evidence.clone()),
        );
        map.insert(
            "network_quarantine".to_string(),
            self.network_quarantine.to_json_val(),
        );
        JsonVal::Obj(map)
    }

    pub fn to_json(&self) -> String {
        json_val_to_string(&self.to_json_val(), false)
    }
}

/// Build the signed `/api/v1/abuse/events` request payload.
pub fn build_abuse_event_payload(
    host_id: &str,
    node_id: &str,
    agent_version: &str,
    timestamp: u64,
    alert: &AbuseAlert,
) -> JsonVal {
    let mut map = BTreeMap::new();
    map.insert("host_id".to_string(), JsonVal::Str(host_id.to_string()));
    map.insert("node_id".to_string(), JsonVal::Str(node_id.to_string()));
    map.insert(
        "agent_version".to_string(),
        JsonVal::Str(agent_version.to_string()),
    );
    map.insert("timestamp".to_string(), JsonVal::Num(timestamp as f64));
    map.insert("alert".to_string(), alert.to_json_val());
    JsonVal::Obj(map)
}

pub fn build_abuse_event_payload_json(
    host_id: &str,
    node_id: &str,
    agent_version: &str,
    timestamp: u64,
    alert: &AbuseAlert,
) -> String {
    json_val_to_string(
        &build_abuse_event_payload(host_id, node_id, agent_version, timestamp, alert),
        false,
    )
}

#[derive(Debug, Clone, PartialEq)]
pub struct AbuseCheckResult {
    pub state: String,
    pub observed_at: Option<f64>,
    pub instance_id: Option<String>,
    pub findings: Option<Vec<JsonVal>>,
    pub alert: Option<AbuseAlert>,
    pub coverage: Option<String>,
    pub collection_failed_at: Option<f64>,
    pub event_relayed: Option<bool>,
    pub notification_pending: Option<bool>,
}

impl AbuseCheckResult {
    pub fn pending_not_sampled() -> Self {
        Self {
            state: "pending".to_string(),
            observed_at: None,
            instance_id: None,
            findings: None,
            alert: None,
            coverage: Some("abuse worker has not sampled this instance".to_string()),
            collection_failed_at: None,
            event_relayed: None,
            notification_pending: None,
        }
    }

    pub fn unsupported() -> Self {
        Self {
            state: "unsupported".to_string(),
            observed_at: None,
            instance_id: None,
            findings: None,
            alert: None,
            coverage: None,
            collection_failed_at: None,
            event_relayed: None,
            notification_pending: None,
        }
    }

    pub fn to_json_val(&self) -> JsonVal {
        let mut map = BTreeMap::new();
        map.insert("state".to_string(), JsonVal::Str(self.state.clone()));
        if let Some(obs) = self.observed_at {
            map.insert("observed_at".to_string(), JsonVal::Num(obs));
        }
        if let Some(ref id) = self.instance_id {
            map.insert("instance_id".to_string(), JsonVal::Str(id.clone()));
        }
        if let Some(ref findings) = self.findings {
            map.insert("findings".to_string(), JsonVal::Arr(findings.clone()));
        }
        if let Some(ref alert) = self.alert {
            map.insert("alert".to_string(), alert.to_json_val());
        }
        if let Some(ref cov) = self.coverage {
            map.insert("coverage".to_string(), JsonVal::Str(cov.clone()));
        }
        if let Some(ts) = self.collection_failed_at {
            map.insert("collection_failed_at".to_string(), JsonVal::Num(ts));
        }
        if let Some(relayed) = self.event_relayed {
            map.insert("event_relayed".to_string(), JsonVal::Bool(relayed));
        }
        if let Some(pending) = self.notification_pending {
            map.insert("notification_pending".to_string(), JsonVal::Bool(pending));
        }
        JsonVal::Obj(map)
    }

    pub fn to_json(&self) -> String {
        json_val_to_string(&self.to_json_val(), false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct CandidateToken {
    key: String,
    kind: String,
    pid: u32,
    start_ticks: String,
    source_sha256: String,
    basis: String,
}

#[derive(Debug, Clone)]
struct CandidateWindow {
    first_seen: f64,
    last_seen: f64,
    samples: u32,
}

#[derive(Debug, Clone)]
struct NotificationEntry {
    signature: String,
    timestamp: f64,
    pending: bool,
}

pub struct AbuseEngine {
    pub journal: QuarantineJournal,
    pub confirm_seconds: f64,
    pub max_gap: f64,
    candidates: HashMap<CandidateToken, CandidateWindow>,
    pub results: HashMap<(String, String, String), AbuseCheckResult>,
    notified: HashMap<(String, String, String, String), NotificationEntry>,
    pub cursor: usize,
}

impl AbuseEngine {
    pub fn new(journal: QuarantineJournal, confirm_seconds: f64, max_gap: f64) -> Self {
        Self {
            journal,
            confirm_seconds: confirm_seconds.max(20.0),
            max_gap,
            candidates: HashMap::new(),
            results: HashMap::new(),
            notified: HashMap::new(),
            cursor: 0,
        }
    }

    pub fn with_defaults() -> Result<Self, String> {
        Ok(Self::new(QuarantineJournal::new(None)?, 20.0, 180.0))
    }

    fn find_record(&self, key: &str) -> Result<Option<JsonVal>, String> {
        let mut records = self.journal.read()?;
        if let Some(record) = records.get(key) {
            return Ok(Some(record.clone()));
        }
        let Ok(parsed_key) = JsonVal::parse(key) else {
            return Ok(None);
        };
        let Some(key_arr) = parsed_key.as_arr() else {
            return Ok(None);
        };
        if key_arr.len() != 4 {
            return Ok(None);
        }
        let runtime = key_arr[0].as_str().unwrap_or("");
        let project = key_arr[1].as_str().unwrap_or("");
        let identity = key_arr[3].as_str().unwrap_or("");

        let previous_keys: Vec<String> = records.keys().cloned().collect();
        for previous in previous_keys {
            let Ok(prev_val) = JsonVal::parse(&previous) else {
                continue;
            };
            let Some(prev_arr) = prev_val.as_arr() else {
                continue;
            };
            if prev_arr.len() != 4 {
                continue;
            }
            let (Some(old_rt), Some(old_proj), Some(_old_name), Some(old_id)) = (
                prev_arr[0].as_str(),
                prev_arr[1].as_str(),
                prev_arr[2].as_str(),
                prev_arr[3].as_str(),
            ) else {
                continue;
            };
            if (old_rt, old_proj, old_id) == (runtime, project, identity) {
                // Renames never release connectivity or lose a recovery record.
                if let Some(record) = records.remove(&previous) {
                    records.insert(key.to_string(), record.clone());
                    self.journal.write(&records)?;
                    return Ok(Some(record));
                }
            }
        }
        Ok(None)
    }

    pub fn check(
        &mut self,
        container: &ContainerTarget,
        instance_id: &str,
        driver: &mut dyn AbuseIsolationDriver,
        processes: &[ProcessRecord],
        sockets: &[SocketRecord],
        now: Option<f64>,
    ) -> Result<AbuseCheckResult, String> {
        let now = now.unwrap_or_else(now_unix_secs_f64);
        let project = container.normalized_project();
        let key = quarantine_target(&container.runtime, project, &container.name, instance_id)?;
        let existing = self.find_record(&key)?;

        let findings: Vec<Finding> = if let Some(ref record) = existing {
            record
                .get("evidence")
                .and_then(JsonVal::as_arr)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Finding::from_json_val)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        } else {
            let mut raw_findings = Vec::new();
            let mut process_tokens: HashMap<u32, String> = HashMap::new();
            for p in processes {
                if p.pid >= 1 && !p.start_ticks.is_empty() {
                    process_tokens.insert(p.pid, p.start_ticks.clone());
                }
            }
            for p in processes {
                raw_findings.extend(evaluate_process(p, sockets));
            }
            for mut item in network_evidence(sockets) {
                if let Some(ticks) = process_tokens.get(&item.pid) {
                    item.start_ticks = ticks.clone();
                    raw_findings.push(item);
                }
            }

            let mut current_keys: BTreeSet<CandidateToken> = BTreeSet::new();
            let mut confirmed = Vec::new();
            for item in &raw_findings {
                let token = CandidateToken {
                    key: key.clone(),
                    kind: item.kind.clone(),
                    pid: item.pid,
                    start_ticks: item.start_ticks.clone(),
                    source_sha256: item.source_sha256.clone().unwrap_or_default(),
                    basis: item.basis.clone(),
                };
                current_keys.insert(token.clone());
                let entry = self.candidates.entry(token).or_insert(CandidateWindow {
                    first_seen: now,
                    last_seen: now,
                    samples: 0,
                });
                if entry.samples > 0 && (0.0..=self.max_gap).contains(&(now - entry.last_seen)) {
                    entry.last_seen = now;
                    entry.samples += 1;
                } else {
                    entry.first_seen = now;
                    entry.last_seen = now;
                    entry.samples = 1;
                }
                if entry.samples >= 2 && (now - entry.first_seen) >= self.confirm_seconds {
                    let mut value = item.clone();
                    value.confidence = "high".to_string();
                    let mut feat = value.features.take().unwrap_or(SourceFeatures {
                        http_calls: 0,
                        enumeration: false,
                        dictionary_inputs: false,
                        identity_generator: false,
                        concurrency: 0,
                        corroborating_samples: None,
                    });
                    feat.corroborating_samples = Some(entry.samples);
                    value.features = Some(feat);
                    confirmed.push(value);
                }
            }

            self.candidates.retain(|token, win| {
                !(token.key == key && !current_keys.contains(token))
                    && (now - win.last_seen) <= self.max_gap
            });

            if confirmed.is_empty() {
                let safe_list = if raw_findings.is_empty() {
                    Vec::new()
                } else {
                    let raw_vals: Vec<JsonVal> =
                        raw_findings.iter().map(Finding::to_json_val).collect();
                    safe_evidence(&raw_vals).unwrap_or_default()
                };
                return Ok(AbuseCheckResult {
                    state: if raw_findings.is_empty() {
                        "not_observed"
                    } else {
                        "suspected"
                    }
                    .to_string(),
                    observed_at: Some(now),
                    instance_id: Some(instance_id.to_string()),
                    findings: Some(safe_list),
                    alert: None,
                    coverage: None,
                    collection_failed_at: None,
                    event_relayed: None,
                    notification_pending: None,
                });
            }
            confirmed
        };

        let finding_vals: Vec<JsonVal> = findings.iter().map(Finding::to_json_val).collect();
        let quarantine_res = (|| -> Result<JsonVal, String> {
            if existing.is_none() {
                driver.check_evidence(&findings)?;
            }
            quarantine_entry(
                &self.journal,
                &key,
                driver,
                &finding_vals,
                now.max(0.0) as u64,
            )
        })();

        let quarantine = match quarantine_res {
            Ok(q_val) => NetworkQuarantineOutcome::from_json_val(&q_val),
            Err(err) => NetworkQuarantineOutcome {
                status: "failed".to_string(),
                ingress_blocked: false,
                egress_blocked: false,
                verified_at: None,
                error: Some(err),
                data_preserved: true,
            },
        };

        let mut title_parts: Vec<&str> = Vec::new();
        for f in &findings {
            let label = kind_title(&f.kind);
            if !title_parts.contains(&label) {
                title_parts.push(label);
            }
        }
        let titles = title_parts.join("、");
        let success = quarantine.status == "isolated";
        let message = if success {
            format!(
                "高置信度命中：{titles}；已隔离容器全部受管入站和出站网络；容器与磁盘保留，等待管理员复核。"
            )
        } else {
            format!(
                "高置信度命中：{titles}；双向隔离未能完整验证，必须人工处理；未删除容器或数据。"
            )
        };
        let safe_vals = safe_evidence(&finding_vals).unwrap_or(finding_vals);

        let alert = AbuseAlert {
            alert_type: "prohibited_activity".to_string(),
            severity: "critical".to_string(),
            title: format!("违规活动：{titles}"),
            runtime: container.runtime.clone(),
            project: project.to_string(),
            container_name: container.name.clone(),
            instance_id: instance_id.to_string(),
            message,
            value: findings.len(),
            threshold: 1,
            abuse_evidence: safe_vals,
            network_quarantine: quarantine.clone(),
        };

        Ok(AbuseCheckResult {
            state: quarantine.status,
            observed_at: Some(now),
            instance_id: Some(instance_id.to_string()),
            findings: None,
            alert: Some(alert),
            coverage: None,
            collection_failed_at: None,
            event_relayed: None,
            notification_pending: None,
        })
    }

    pub fn notify<E>(&mut self, result: &mut AbuseCheckResult, mut emit: E, now: f64)
    where
        E: FnMut(&AbuseAlert) -> Result<JsonVal, String>,
    {
        let Some(ref alert) = result.alert else {
            return;
        };
        let identity = (
            alert.runtime.clone(),
            alert.project.clone(),
            alert.container_name.clone(),
            alert.instance_id.clone(),
        );
        let sig_payload = JsonVal::Arr(vec![
            JsonVal::Arr(alert.abuse_evidence.clone()),
            JsonVal::Str(alert.network_quarantine.status.clone()),
        ]);
        let signature = sha256_hex(json_val_to_string(&sig_payload, false).as_bytes());
        if let Some(prev) = self.notified.get(&identity) {
            if prev.signature == signature && (now - prev.timestamp) < 300.0 {
                result.notification_pending = Some(prev.pending);
                return;
            }
        }
        let Ok(response) = emit(alert) else {
            result.notification_pending = Some(true);
            return;
        };
        // An authenticated server ACK is not proof of Telegram delivery.
        let delivered = response
            .get("telegram_delivery")
            .and_then(|t| t.get_str("state"))
            == Some("delivered");
        result.event_relayed = Some(true);
        result.notification_pending = Some(!delivered);
        self.notified.insert(
            identity,
            NotificationEntry {
                signature,
                timestamp: if delivered { now } else { now - 270.0 },
                pending: !delivered,
            },
        );
    }

    /// Select up to `batch_size` eligible targets using bounded round-robin cursor.
    pub fn select_batch(
        &mut self,
        containers: &[ContainerTarget],
        batch_size: usize,
    ) -> Vec<ContainerTarget> {
        if batch_size == 0 {
            return Vec::new();
        }
        let eligible: Vec<&ContainerTarget> = containers
            .iter()
            .filter(|c| {
                matches!(c.runtime.as_str(), "podman" | "incus" | "runman")
                    && !PROTECTED_CONTAINERS.contains(&c.name.as_str())
            })
            .collect();
        if eligible.is_empty() {
            return Vec::new();
        }
        let take_count = batch_size.min(eligible.len());
        let mut selected = Vec::with_capacity(take_count);
        for i in 0..take_count {
            let item = eligible[(self.cursor + i) % eligible.len()].clone();
            selected.push(item);
        }
        self.cursor = (self.cursor + selected.len()) % eligible.len();
        selected
    }

    pub fn record_collection_failure(&mut self, container: &ContainerTarget, now: f64) {
        let key = container.identity_key();
        let updated = match self.results.get(&key) {
            Some(previous) if previous.alert.is_some() => {
                let mut cloned = previous.clone();
                cloned.collection_failed_at = Some(now);
                cloned.coverage =
                    Some("unavailable; previous isolation is not freshly verified".to_string());
                cloned.state = "unverified".to_string();
                if let Some(ref mut alert) = cloned.alert {
                    alert.network_quarantine.status = "unverified".to_string();
                    alert.network_quarantine.ingress_blocked = false;
                    alert.network_quarantine.egress_blocked = false;
                    alert.message =
                        "上次已要求双向隔离，但本次采集不可用；当前网络状态待确认，仍需管理员复核。"
                            .to_string();
                }
                cloned
            }
            _ => AbuseCheckResult {
                state: "collection_failed".to_string(),
                observed_at: Some(now),
                instance_id: None,
                findings: None,
                alert: None,
                coverage: Some("unavailable; not a clean observation".to_string()),
                collection_failed_at: None,
                event_relayed: None,
                notification_pending: None,
            },
        };
        self.results.insert(key, updated);
    }

    /// Synchronous single-batch execution helper (matches `schedule` inner work loop).
    pub fn poll_batch<P, D, E>(
        &mut self,
        containers: &[ContainerTarget],
        batch_size: usize,
        mut provider: P,
        mut emit: E,
        now_fn: fn() -> f64,
    ) -> usize
    where
        P: FnMut(
            &ContainerTarget,
        ) -> Result<(String, D, Vec<ProcessRecord>, Vec<SocketRecord>), String>,
        D: AbuseIsolationDriver,
        E: FnMut(&AbuseAlert) -> Result<JsonVal, String>,
    {
        let selected = self.select_batch(containers, batch_size);
        let count = selected.len();
        for container in &selected {
            let key = container.identity_key();
            match provider(container) {
                Ok((instance_id, mut driver, processes, sockets)) => {
                    let check_now = now_fn();
                    match self.check(
                        container,
                        &instance_id,
                        &mut driver,
                        &processes,
                        &sockets,
                        Some(check_now),
                    ) {
                        Ok(mut result) => {
                            self.notify(&mut result, &mut emit, now_fn());
                            self.results.insert(key, result);
                        }
                        Err(_) => {
                            self.record_collection_failure(container, now_fn());
                        }
                    }
                }
                Err(_) => {
                    self.record_collection_failure(container, now_fn());
                }
            }
        }
        count
    }

    pub fn status(&self, container: &ContainerTarget, now: Option<f64>) -> AbuseCheckResult {
        let now = now.unwrap_or_else(now_unix_secs_f64);
        if PROTECTED_CONTAINERS.contains(&container.name.as_str()) {
            return AbuseCheckResult {
                state: "protected".to_string(),
                observed_at: None,
                instance_id: None,
                findings: None,
                alert: None,
                coverage: Some("management service excluded from automatic quarantine".to_string()),
                collection_failed_at: None,
                event_relayed: None,
                notification_pending: None,
            };
        }
        let key = container.identity_key();
        let maybe_result = self.results.get(&key).cloned();
        let identity = container.telemetry_identity();
        let seen = maybe_result
            .as_ref()
            .and_then(|r| r.instance_id.as_deref())
            .unwrap_or("");
        if container.runtime == "runman" && !seen.is_empty() && identity.is_empty() {
            return AbuseCheckResult {
                state: "pending".to_string(),
                observed_at: None,
                instance_id: None,
                findings: None,
                alert: None,
                coverage: Some("current Runman generation unavailable".to_string()),
                collection_failed_at: None,
                event_relayed: None,
                notification_pending: None,
            };
        }
        if !identity.is_empty()
            && !seen.is_empty()
            && identity != seen
            && !(container.runtime == "podman"
                && identity.len() >= 12
                && seen.starts_with(identity))
        {
            return AbuseCheckResult {
                state: "pending".to_string(),
                observed_at: None,
                instance_id: None,
                findings: None,
                alert: None,
                coverage: Some("instance identity changed".to_string()),
                collection_failed_at: None,
                event_relayed: None,
                notification_pending: None,
            };
        }
        let observed_at = maybe_result
            .as_ref()
            .and_then(|r| r.observed_at)
            .unwrap_or(0.0);
        if (now - observed_at) > 900.0 {
            if let Some(mut res) = maybe_result {
                if let Some(ref mut alert) = res.alert {
                    res.state = "stale".to_string();
                    res.coverage = Some(
                        "previous isolation is not freshly verified; review still required"
                            .to_string(),
                    );
                    alert.network_quarantine.status = "unverified".to_string();
                    alert.network_quarantine.ingress_blocked = false;
                    alert.network_quarantine.egress_blocked = false;
                    alert.message =
                        "隔离验证采样已过期；保留待复核事件，当前网络状态待确认，不表示风险已恢复。"
                            .to_string();
                    return res;
                }
            }
            return AbuseCheckResult {
                state: "stale".to_string(),
                observed_at: None,
                instance_id: None,
                findings: None,
                alert: None,
                coverage: Some("no fresh abuse sample; not verified clean".to_string()),
                collection_failed_at: None,
                event_relayed: None,
                notification_pending: None,
            };
        }
        maybe_result.unwrap_or_else(AbuseCheckResult::pending_not_sampled)
    }

    pub fn forget(&mut self, container: &ContainerTarget, instance_id: &str) {
        let project = container.normalized_project();
        if let Ok(key) = quarantine_target(&container.runtime, project, &container.name, instance_id)
        {
            self.candidates.retain(|token, _| token.key != key);
        }
        self.results.remove(&container.identity_key());
        self.notified.remove(&(
            container.runtime.clone(),
            project.to_string(),
            container.name.clone(),
            instance_id.to_string(),
        ));
    }

    /// Forget only the retired identity; preserve any result for its replacement.
    pub fn forget_replaced(&mut self, container: &ContainerTarget, old_instance_id: &str) {
        let project = container.normalized_project();
        if let Ok(key) = quarantine_target(
            &container.runtime,
            project,
            &container.name,
            old_instance_id,
        ) {
            self.candidates.retain(|token, _| token.key != key);
        }
        let id_key = container.identity_key();
        if let Some(res) = self.results.get(&id_key) {
            if res.instance_id.as_deref().unwrap_or("") == old_instance_id {
                self.results.remove(&id_key);
            }
        }
        self.notified.remove(&(
            container.runtime.clone(),
            project.to_string(),
            container.name.clone(),
            old_instance_id.to_string(),
        ));
    }
}

/// Thread-safe background worker wrapper matching `abuse_guard.Engine.schedule`.
pub struct SharedAbuseEngine {
    pub inner: Arc<Mutex<AbuseEngine>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl SharedAbuseEngine {
    pub fn new(engine: AbuseEngine) -> Self {
        Self {
            inner: Arc::new(Mutex::new(engine)),
            worker: Mutex::new(None),
        }
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, AbuseEngine> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// One bounded worker; diagnostics never block the normal Agent loop.
    pub fn schedule<P, D, E>(
        &self,
        containers: &[ContainerTarget],
        mut provider: P,
        mut emit: E,
        batch_size: usize,
    ) -> bool
    where
        P: FnMut(
                &ContainerTarget,
            ) -> Result<(String, D, Vec<ProcessRecord>, Vec<SocketRecord>), String>
            + Send
            + 'static,
        D: AbuseIsolationDriver + 'static,
        E: FnMut(&AbuseAlert) -> Result<JsonVal, String> + Send + 'static,
    {
        let mut worker_slot = match self.worker.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(ref handle) = *worker_slot {
            if !handle.is_finished() {
                return false;
            }
        }
        if let Some(prev) = worker_slot.take() {
            let _ = prev.join();
        }

        let selected = {
            let mut guard = self.lock();
            guard.select_batch(containers, batch_size)
        };
        if selected.is_empty() {
            return false;
        }

        let shared = Arc::clone(&self.inner);
        let builder = thread::Builder::new().name("narwhal-abuse-guard".to_string());
        let handle = builder.spawn(move || {
            for container in selected {
                let key = container.identity_key();
                match provider(&container) {
                    Ok((instance_id, mut driver, processes, sockets)) => {
                        let mut guard = match shared.lock() {
                            Ok(g) => g,
                            Err(p) => p.into_inner(),
                        };
                        match guard.check(
                            &container,
                            &instance_id,
                            &mut driver,
                            &processes,
                            &sockets,
                            None,
                        ) {
                            Ok(mut result) => {
                                guard.notify(&mut result, &mut emit, now_unix_secs_f64());
                                guard.results.insert(key, result);
                            }
                            Err(_) => {
                                guard.record_collection_failure(&container, now_unix_secs_f64());
                            }
                        }
                    }
                    Err(_) => {
                        let mut guard = match shared.lock() {
                            Ok(g) => g,
                            Err(p) => p.into_inner(),
                        };
                        guard.record_collection_failure(&container, now_unix_secs_f64());
                    }
                }
            }
        });

        match handle {
            Ok(h) => {
                *worker_slot = Some(h);
                true
            }
            Err(_) => false,
        }
    }

    pub fn join_worker(&self) {
        let handle = {
            let mut slot = match self.worker.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            slot.take()
        };
        if let Some(h) = handle {
            let _ = h.join();
        }
    }

    pub fn status(&self, container: &ContainerTarget, now: Option<f64>) -> AbuseCheckResult {
        self.lock().status(container, now)
    }

    pub fn forget(&self, container: &ContainerTarget, instance_id: &str) {
        self.lock().forget(container, instance_id);
    }

    pub fn forget_replaced(&self, container: &ContainerTarget, old_instance_id: &str) {
        self.lock().forget_replaced(container, old_instance_id);
    }
}
