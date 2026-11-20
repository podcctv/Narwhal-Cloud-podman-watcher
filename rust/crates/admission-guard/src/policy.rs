use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use runtime_drivers::JsonVal;

use crate::AdmissionError;

pub const SAMPLE_GAP: i64 = 30;
pub const WINDOW: i64 = 120;
pub const PERIOD: i64 = 1800;
pub const DEFAULT_SOURCE_LIMIT: usize = 10;
pub const MAX_SOURCE_LIMIT: usize = 64;
pub const SOURCE_IDLE: i64 = 120;
pub const PROBATION_GAP: i64 = 15;
pub const OBSERVE_SAMPLE: usize = 5;
pub const BLOCKED_MAX: usize = 32;

pub type TcpFlow = (String, u16, String, u16);

pub fn current_unix_ts_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Configured active-source limit; 0 disables enforcement (observe only).
pub fn source_limit_from_env() -> usize {
    let raw = env::var("SECURITY_ADMISSION_SOURCE_LIMIT")
        .unwrap_or_else(|_| DEFAULT_SOURCE_LIMIT.to_string());
    parse_source_limit(raw.trim())
}

pub fn parse_source_limit(raw: &str) -> usize {
    match raw.trim().parse::<i64>() {
        Ok(val) => val.clamp(0, MAX_SOURCE_LIMIT as i64) as usize,
        Err(_) => DEFAULT_SOURCE_LIMIT,
    }
}

pub fn is_non_business_ipv4(v4: Ipv4Addr) -> bool {
    v4.is_unspecified() || v4.is_multicast() || v4.is_loopback() || v4.is_link_local()
}

pub fn is_non_business_ipv6(v6: Ipv6Addr) -> bool {
    let seg0 = v6.segments()[0];
    let is_link_local = (seg0 & 0xffc0) == 0xfe80;
    v6.is_unspecified() || v6.is_multicast() || v6.is_loopback() || is_link_local
}

pub fn normalize_ip(parsed: IpAddr) -> IpAddr {
    match parsed {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            if octets[..10] == [0u8; 10] && octets[10] == 0xff && octets[11] == 0xff {
                IpAddr::V4(Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]))
            } else {
                IpAddr::V6(v6)
            }
        }
    }
}

/// Normalize IPv4/IPv6 address (unwrapping IPv4-mapped IPv6) and reject loopback,
/// unspecified, multicast, and link-local addresses.
pub fn address(value: &str) -> Result<String, AdmissionError> {
    let parsed: IpAddr = value
        .trim()
        .parse()
        .map_err(|_| AdmissionError::Value(format!("invalid IP address: {value}")))?;
    let norm = normalize_ip(parsed);
    match norm {
        IpAddr::V4(v4) => {
            if is_non_business_ipv4(v4) {
                return Err(AdmissionError::Value("not a business source".to_string()));
            }
            Ok(v4.to_string())
        }
        IpAddr::V6(v6) => {
            if is_non_business_ipv6(v6) {
                return Err(AdmissionError::Value("not a business source".to_string()));
            }
            Ok(v6.to_string())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntry {
    pub ip: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub confirmed: bool,
    pub active_established: Option<bool>,
}

impl SourceEntry {
    pub fn to_json_val(&self) -> JsonVal {
        let mut map = BTreeMap::new();
        map.insert("ip".to_string(), JsonVal::Str(self.ip.clone()));
        map.insert("first_seen".to_string(), JsonVal::Num(self.first_seen as f64));
        map.insert("last_seen".to_string(), JsonVal::Num(self.last_seen as f64));
        map.insert("confirmed".to_string(), JsonVal::Bool(self.confirmed));
        if let Some(active) = self.active_established {
            map.insert("active_established".to_string(), JsonVal::Bool(active));
        }
        JsonVal::Obj(map)
    }

    pub fn from_json_val(val: &JsonVal) -> Option<Self> {
        let obj = val.as_obj()?;
        let ip = obj.get("ip")?.as_str()?.to_string();
        let first_seen = obj
            .get("first_seen")
            .and_then(JsonVal::as_i64)
            .unwrap_or(0);
        let last_seen = obj
            .get("last_seen")
            .and_then(JsonVal::as_i64)
            .unwrap_or(first_seen);
        let confirmed = obj
            .get("confirmed")
            .and_then(JsonVal::as_bool)
            .unwrap_or(true);
        let active_established = obj.get("active_established").and_then(JsonVal::as_bool);
        Some(Self {
            ip,
            first_seen,
            last_seen,
            confirmed,
            active_established,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedEntry {
    pub first_seen: i64,
    pub last_seen: i64,
    pub packets: u64,
}

impl BlockedEntry {
    pub fn to_json_val(&self) -> JsonVal {
        let mut map = BTreeMap::new();
        map.insert("first_seen".to_string(), JsonVal::Num(self.first_seen as f64));
        map.insert("last_seen".to_string(), JsonVal::Num(self.last_seen as f64));
        map.insert("packets".to_string(), JsonVal::Num(self.packets as f64));
        JsonVal::Obj(map)
    }

    pub fn from_json_val(val: &JsonVal) -> Option<Self> {
        let obj = val.as_obj()?;
        let first_seen = obj
            .get("first_seen")
            .and_then(JsonVal::as_i64)
            .unwrap_or(0);
        let last_seen = obj
            .get("last_seen")
            .and_then(JsonVal::as_i64)
            .unwrap_or(0);
        let packets = obj.get("packets").and_then(JsonVal::as_u64).unwrap_or(0);
        Some(Self {
            first_seen,
            last_seen,
            packets,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniBlockedDomain {
    pub sni: String,
    pub reason: String,
    pub dst_port: u16,
    pub proto: String,
    pub count: u64,
    pub last_seen: i64,
}

impl SniBlockedDomain {
    pub fn to_json_val(&self) -> JsonVal {
        let mut map = BTreeMap::new();
        map.insert("sni".to_string(), JsonVal::Str(self.sni.clone()));
        map.insert("reason".to_string(), JsonVal::Str(self.reason.clone()));
        map.insert("dst_port".to_string(), JsonVal::Num(self.dst_port as f64));
        map.insert("proto".to_string(), JsonVal::Str(self.proto.clone()));
        map.insert("count".to_string(), JsonVal::Num(self.count as f64));
        map.insert("last_seen".to_string(), JsonVal::Num(self.last_seen as f64));
        JsonVal::Obj(map)
    }

    pub fn from_json_val(val: &JsonVal) -> Option<Self> {
        let map = val.as_obj()?;
        Some(Self {
            sni: map.get("sni").and_then(JsonVal::as_str)?.to_string(),
            reason: map
                .get("reason")
                .and_then(JsonVal::as_str)
                .unwrap_or("disallowed_sni")
                .to_string(),
            dst_port: map.get("dst_port").and_then(JsonVal::as_u64).unwrap_or(443) as u16,
            proto: map
                .get("proto")
                .and_then(JsonVal::as_str)
                .unwrap_or("tls")
                .to_string(),
            count: map.get("count").and_then(JsonVal::as_u64).unwrap_or(1),
            last_seen: map.get("last_seen").and_then(JsonVal::as_i64).unwrap_or(0),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub sources: Vec<SourceEntry>,
    pub blocked: BTreeMap<String, BlockedEntry>,
    pub blocked_packets: u64,
    pub sni_blocked_total: u64,
    pub sni_cn_missing_total: u64,
    pub sni_recent_blocked: Vec<SniBlockedDomain>,
    pub tcp_denied: u64,
    pub extensions: u64,
    pub seeded: bool,
    pub source_order_basis: Option<String>,
    pub last_blocked_at: Option<i64>,
    pub sample_state: Option<String>,
    pub above_since: Option<i64>,
    pub below_since: Option<i64>,
    pub sampled_at: Option<i64>,
    pub epoch: Option<String>,
    pub tcp_connections: Option<usize>,
    pub limited: Option<bool>,
    pub limited_since: Option<i64>,
    pub review_at: Option<i64>,
    pub recovered_at: Option<i64>,
    pub event: Option<String>,
    pub extra_data: BTreeMap<String, JsonVal>,
    pub source_limit: usize,
    pub pending: BTreeMap<TcpFlow, i64>,
    pub flows: BTreeSet<TcpFlow>,
    pub sample_at: i64,
    pub last_denied_at: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self::new(None, 0)
    }
}

impl Policy {
    pub fn new(saved: Option<&JsonVal>, source_limit: usize) -> Self {
        let clamped_limit = source_limit.min(MAX_SOURCE_LIMIT);
        let mut policy = Self {
            sources: Vec::new(),
            blocked: BTreeMap::new(),
            blocked_packets: 0,
            sni_blocked_total: 0,
            sni_cn_missing_total: 0,
            sni_recent_blocked: Vec::new(),
            tcp_denied: 0,
            extensions: 0,
            seeded: false,
            source_order_basis: None,
            last_blocked_at: None,
            sample_state: None,
            above_since: None,
            below_since: None,
            sampled_at: None,
            epoch: None,
            tcp_connections: None,
            limited: None,
            limited_since: None,
            review_at: None,
            recovered_at: None,
            event: None,
            extra_data: BTreeMap::new(),
            source_limit: clamped_limit,
            pending: BTreeMap::new(),
            flows: BTreeSet::new(),
            sample_at: 0,
            last_denied_at: 0,
        };
        if let Some(JsonVal::Obj(map)) = saved {
            policy.load_from_map(map);
        }
        policy
    }

    fn load_from_map(&mut self, map: &BTreeMap<String, JsonVal>) {
        if let Some(JsonVal::Arr(arr)) = map.get("sources") {
            self.sources = arr.iter().filter_map(SourceEntry::from_json_val).collect();
        }
        if let Some(JsonVal::Obj(blk)) = map.get("blocked") {
            for (k, v) in blk {
                if let Some(entry) = BlockedEntry::from_json_val(v) {
                    self.blocked.insert(k.clone(), entry);
                }
            }
        }
        if let Some(v) = map.get("blocked_packets").and_then(JsonVal::as_u64) {
            self.blocked_packets = v;
        }
        if let Some(v) = map.get("sni_blocked_total").and_then(JsonVal::as_u64) {
            self.sni_blocked_total = v;
        }
        if let Some(v) = map.get("sni_cn_missing_total").and_then(JsonVal::as_u64) {
            self.sni_cn_missing_total = v;
        }
        if let Some(arr) = map.get("sni_recent_blocked").and_then(JsonVal::as_arr) {
            for item in arr.iter().take(16) {
                if let Some(entry) = SniBlockedDomain::from_json_val(item) {
                    self.sni_recent_blocked.push(entry);
                }
            }
        }
        if let Some(v) = map.get("tcp_denied").and_then(JsonVal::as_u64) {
            self.tcp_denied = v;
        }
        if let Some(v) = map.get("extensions").and_then(JsonVal::as_u64) {
            self.extensions = v;
        }
        if let Some(v) = map.get("seeded").and_then(JsonVal::as_bool) {
            self.seeded = v;
        }
        if let Some(v) = map.get("source_order_basis").and_then(JsonVal::as_str) {
            self.source_order_basis = Some(v.to_string());
        }
        if let Some(v) = map.get("last_blocked_at").and_then(JsonVal::as_i64) {
            self.last_blocked_at = Some(v);
        }
        if let Some(v) = map.get("sample_state").and_then(JsonVal::as_str) {
            self.sample_state = Some(v.to_string());
        }
        if let Some(v) = map.get("above_since").and_then(JsonVal::as_i64) {
            self.above_since = Some(v);
        }
        if let Some(v) = map.get("below_since").and_then(JsonVal::as_i64) {
            self.below_since = Some(v);
        }
        if let Some(v) = map.get("sampled_at").and_then(JsonVal::as_i64) {
            self.sampled_at = Some(v);
        }
        if let Some(v) = map.get("epoch").and_then(JsonVal::as_str) {
            self.epoch = Some(v.to_string());
        }
        if let Some(v) = map.get("tcp_connections").and_then(JsonVal::as_u64) {
            self.tcp_connections = Some(v as usize);
        }
        if let Some(v) = map.get("limited").and_then(JsonVal::as_bool) {
            self.limited = Some(v);
        }
        if let Some(v) = map.get("limited_since").and_then(JsonVal::as_i64) {
            self.limited_since = Some(v);
        }
        if let Some(v) = map.get("review_at").and_then(JsonVal::as_i64) {
            self.review_at = Some(v);
        }
        if let Some(v) = map.get("recovered_at").and_then(JsonVal::as_i64) {
            self.recovered_at = Some(v);
        }
        if let Some(v) = map.get("event").and_then(JsonVal::as_str) {
            self.event = Some(v.to_string());
        }
        for (k, v) in map {
            if !matches!(
                k.as_str(),
                "sources"
                    | "blocked"
                    | "blocked_packets"
                    | "sni_blocked_total"
                    | "sni_cn_missing_total"
                    | "sni_recent_blocked"
                    | "tcp_denied"
                    | "extensions"
                    | "seeded"
                    | "source_order_basis"
                    | "last_blocked_at"
                    | "sample_state"
                    | "above_since"
                    | "below_since"
                    | "sampled_at"
                    | "epoch"
                    | "tcp_connections"
                    | "limited"
                    | "limited_since"
                    | "review_at"
                    | "recovered_at"
                    | "event"
            ) {
                self.extra_data.insert(k.clone(), v.clone());
            }
        }
    }

    pub fn to_json_map(&self) -> BTreeMap<String, JsonVal> {
        let mut map = self.extra_data.clone();
        map.insert(
            "sources".to_string(),
            JsonVal::Arr(self.sources.iter().map(SourceEntry::to_json_val).collect()),
        );
        let mut blk = BTreeMap::new();
        for (k, v) in &self.blocked {
            blk.insert(k.clone(), v.to_json_val());
        }
        map.insert("blocked".to_string(), JsonVal::Obj(blk));
        map.insert(
            "blocked_packets".to_string(),
            JsonVal::Num(self.blocked_packets as f64),
        );
        if self.sni_blocked_total > 0 {
            map.insert(
                "sni_blocked_total".to_string(),
                JsonVal::Num(self.sni_blocked_total as f64),
            );
        }
        if self.sni_cn_missing_total > 0 {
            map.insert(
                "sni_cn_missing_total".to_string(),
                JsonVal::Num(self.sni_cn_missing_total as f64),
            );
        }
        if !self.sni_recent_blocked.is_empty() {
            map.insert(
                "sni_recent_blocked".to_string(),
                JsonVal::Arr(
                    self.sni_recent_blocked
                        .iter()
                        .map(SniBlockedDomain::to_json_val)
                        .collect(),
                ),
            );
        }
        map.insert(
            "tcp_denied".to_string(),
            JsonVal::Num(self.tcp_denied as f64),
        );
        map.insert(
            "extensions".to_string(),
            JsonVal::Num(self.extensions as f64),
        );
        if self.seeded {
            map.insert("seeded".to_string(), JsonVal::Bool(true));
        }
        if let Some(ref v) = self.source_order_basis {
            map.insert("source_order_basis".to_string(), JsonVal::Str(v.clone()));
        }
        if let Some(v) = self.last_blocked_at {
            map.insert("last_blocked_at".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(ref v) = self.sample_state {
            map.insert("sample_state".to_string(), JsonVal::Str(v.clone()));
        }
        if let Some(v) = self.above_since {
            map.insert("above_since".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(v) = self.below_since {
            map.insert("below_since".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(v) = self.sampled_at {
            map.insert("sampled_at".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(ref v) = self.epoch {
            map.insert("epoch".to_string(), JsonVal::Str(v.clone()));
        }
        if let Some(v) = self.tcp_connections {
            map.insert("tcp_connections".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(v) = self.limited {
            map.insert("limited".to_string(), JsonVal::Bool(v));
        }
        if let Some(v) = self.limited_since {
            map.insert("limited_since".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(v) = self.review_at {
            map.insert("review_at".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(v) = self.recovered_at {
            map.insert("recovered_at".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(ref v) = self.event {
            map.insert("event".to_string(), JsonVal::Str(v.clone()));
        }
        map
    }

    pub fn to_json_val(&self) -> JsonVal {
        JsonVal::Obj(self.to_json_map())
    }

    pub fn enforced(&self) -> bool {
        self.source_limit > 0
    }

    pub fn is_limited(&self) -> bool {
        self.limited.unwrap_or(false)
    }

    pub fn capacity(&self) -> usize {
        if self.enforced() {
            self.source_limit
        } else {
            OBSERVE_SAMPLE
        }
    }

    pub fn record_sni_block(
        &mut self,
        sni: Option<&str>,
        reason: &str,
        dst_port: u16,
        proto: u8,
        now: i64,
    ) {
        self.sni_blocked_total = self.sni_blocked_total.saturating_add(1);
        if reason == "missing_or_invalid_sni_cn" {
            self.sni_cn_missing_total = self.sni_cn_missing_total.saturating_add(1);
        }
        let sni_str = sni.unwrap_or("").trim().to_string();
        let proto_str = if proto == 17 { "quic" } else { "tls" };
        if let Some(existing) = self.sni_recent_blocked.iter_mut().find(|e| {
            e.sni == sni_str && e.reason == reason && e.dst_port == dst_port && e.proto == proto_str
        }) {
            existing.count = existing.count.saturating_add(1);
            existing.last_seen = now;
        } else {
            if self.sni_recent_blocked.len() >= 16 {
                if let Some((oldest_idx, _)) = self
                    .sni_recent_blocked
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, e)| e.last_seen)
                {
                    self.sni_recent_blocked.remove(oldest_idx);
                }
            }
            self.sni_recent_blocked.push(SniBlockedDomain {
                sni: sni_str,
                reason: reason.to_string(),
                dst_port,
                proto: proto_str.to_string(),
                count: 1,
                last_seen: now,
            });
        }
    }

    /// The first complete observation seeds slots from live established sources.
    pub fn seed<I, S>(&mut self, sources: I, now: i64)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if self.seeded {
            return;
        }
        let cap = self.capacity();
        let mut seen: BTreeSet<String> = self.sources.iter().map(|s| s.ip.clone()).collect();
        for value in sources {
            let Ok(ip) = address(value.as_ref()) else {
                continue;
            };
            if seen.contains(&ip) {
                continue;
            }
            seen.insert(ip.clone());
            if self.sources.len() < cap {
                self.sources.push(SourceEntry {
                    ip,
                    first_seen: now,
                    last_seen: now,
                    confirmed: true,
                    active_established: None,
                });
            }
        }
        self.seeded = true;
        self.source_order_basis = Some("first_complete_observation".to_string());
    }

    /// Record a bounded sample of current IPs without an admission decision.
    pub fn observe_source(
        &mut self,
        source: &str,
        now: i64,
        confirmed: bool,
    ) -> Result<bool, AdmissionError> {
        let ip = address(source)?;
        for entry in &mut self.sources {
            if entry.ip == ip {
                if confirmed {
                    entry.confirmed = true;
                }
                entry.last_seen = now;
                return Ok(false);
            }
        }
        if self.sources.len() < self.capacity() {
            self.sources.push(SourceEntry {
                ip,
                first_seen: now,
                last_seen: now,
                confirmed,
                active_established: None,
            });
            return Ok(true);
        }
        Ok(false)
    }

    pub fn _expire_idle(&mut self, now: i64) -> bool {
        let old_len = self.sources.len();
        self.sources.retain(|s| {
            if s.confirmed {
                now - s.last_seen <= SOURCE_IDLE
            } else {
                now - s.first_seen <= PROBATION_GAP
            }
        });
        self.sources.len() != old_len
    }

    pub fn expire_idle(&mut self, now: i64) -> bool {
        self._expire_idle(now)
    }

    /// Admission decision for a NEW inbound flow; returns `(accepted, slot_added)`.
    pub fn admit_source(
        &mut self,
        source: &str,
        now: i64,
    ) -> Result<(bool, bool), AdmissionError> {
        let ip = address(source)?;
        if !self.enforced() {
            let added = self.observe_source(&ip, now, true)?;
            return Ok((true, added));
        }
        for entry in &mut self.sources {
            if entry.ip == ip {
                entry.last_seen = now;
                return Ok((true, false));
            }
        }
        self._expire_idle(now);
        let confirmed_count = self.sources.iter().filter(|s| s.confirmed).count();
        if confirmed_count >= self.source_limit {
            self.blocked_packets += 1;
            self.last_blocked_at = Some(now);
            if !self.blocked.contains_key(&ip) && self.blocked.len() >= BLOCKED_MAX {
                if let Some(oldest_key) = self
                    .blocked
                    .iter()
                    .min_by_key(|(_, v)| v.last_seen)
                    .map(|(k, _)| k.clone())
                {
                    self.blocked.remove(&oldest_key);
                }
            }
            let item = self.blocked.entry(ip).or_insert(BlockedEntry {
                first_seen: now,
                last_seen: now,
                packets: 0,
            });
            item.last_seen = now;
            item.packets += 1;
            return Ok((false, false));
        }
        self.sources.push(SourceEntry {
            ip: ip.clone(),
            first_seen: now,
            last_seen: now,
            confirmed: false,
            active_established: None,
        });
        self.blocked.remove(&ip);
        Ok((true, true))
    }

    pub fn admit_tcp(&mut self, flow: &TcpFlow, now: i64) -> bool {
        if !self.is_limited() {
            return true;
        }
        if self.flows.contains(flow) || self.pending.contains_key(flow) {
            return true;
        }
        let mut union_count = self.flows.len();
        for k in self.pending.keys() {
            if !self.flows.contains(k) {
                union_count += 1;
            }
        }
        if now - self.sample_at > SAMPLE_GAP || union_count >= 500 {
            self.tcp_denied += 1;
            self.last_denied_at = now;
            return false;
        }
        self.pending.insert(flow.clone(), now);
        true
    }

    pub fn _refresh_sources(
        &mut self,
        inbound: &[String],
        live_sources: &BTreeSet<String>,
        now: i64,
    ) -> bool {
        if !self.enforced() {
            let mut live: BTreeSet<String> = inbound.iter().cloned().collect();
            for s in live_sources {
                live.insert(s.clone());
            }
            let old_len = self.sources.len();
            self.sources.retain(|s| live.contains(&s.ip));
            let mut changed = self.sources.len() != old_len;
            for value in inbound.iter().chain(live_sources.iter()) {
                if let Ok(added) = self.observe_source(value, now, true) {
                    changed = added || changed;
                }
            }
            return changed;
        }

        let mut inbound_set = BTreeSet::new();
        for value in inbound {
            if let Ok(ip) = address(value) {
                inbound_set.insert(ip);
            }
        }
        let mut _kernel = BTreeSet::new();
        for value in live_sources {
            if let Ok(ip) = address(value) {
                _kernel.insert(ip);
            }
        }
        let old = self.sources.len();
        let mut keep = Vec::new();
        let mut seen = BTreeSet::new();
        for mut entry in self.sources.drain(..) {
            let ip = entry.ip.clone();
            if seen.contains(&ip) {
                continue;
            }
            if inbound_set.contains(&ip) {
                entry.confirmed = true;
                entry.active_established = Some(true);
                entry.last_seen = now;
                keep.push(entry);
                seen.insert(ip);
            } else if entry.confirmed {
                entry.active_established = Some(false);
                if now - entry.last_seen <= SOURCE_IDLE {
                    keep.push(entry);
                    seen.insert(ip);
                }
            } else {
                entry.active_established = Some(false);
                if now - entry.first_seen <= PROBATION_GAP {
                    keep.push(entry);
                    seen.insert(ip);
                }
            }
        }
        for ip in inbound_set {
            if seen.contains(&ip) {
                continue;
            }
            if keep.iter().filter(|s| s.confirmed).count() >= self.source_limit {
                break;
            }
            keep.push(SourceEntry {
                ip: ip.clone(),
                first_seen: now,
                last_seen: now,
                confirmed: true,
                active_established: Some(true),
            });
            seen.insert(ip);
        }
        self.sources = keep;
        self.sources.len() != old
    }

    pub fn refresh_sources(
        &mut self,
        inbound: &[String],
        live_sources: &BTreeSet<String>,
        now: i64,
    ) -> bool {
        self._refresh_sources(inbound, live_sources, now)
    }

    pub fn observe(
        &mut self,
        flows: &BTreeSet<TcpFlow>,
        inbound: &[String],
        live_sources: &BTreeSet<String>,
        now: Option<i64>,
        valid: bool,
        epoch: &str,
    ) -> bool {
        let now = now.unwrap_or_else(current_unix_ts_i64);
        if !valid || epoch.is_empty() {
            self.sample_state = Some("unverified".to_string());
            self.above_since = Some(0);
            self.below_since = Some(0);
            return false;
        }
        let previous = self.sampled_at.unwrap_or(0);
        if now <= previous {
            return false;
        }
        let same = self.epoch.as_deref() == Some(epoch)
            && (now - previous) > 0
            && (now - previous) <= SAMPLE_GAP;
        self.flows = flows.clone();
        self.pending
            .retain(|k, &mut v| !self.flows.contains(k) && (now - v) < 30);
        self.sample_at = now;
        self.epoch = Some(epoch.to_string());
        self.sampled_at = Some(now);
        self.sample_state = Some("valid".to_string());
        self.tcp_connections = Some(self.flows.len());
        self.seed(inbound, now);
        let mut changed = self._refresh_sources(inbound, live_sources, now);
        let count = self.flows.len();
        let prev_above = self.above_since.unwrap_or(0);
        let above = if same && count > 1000 {
            if prev_above != 0 {
                prev_above
            } else {
                now
            }
        } else if count > 1000 {
            now
        } else {
            0
        };
        let prev_below = self.below_since.unwrap_or(0);
        let below = if same && count < 500 && (now - self.last_denied_at) > WINDOW {
            if prev_below != 0 {
                prev_below
            } else {
                now
            }
        } else if count < 500 && (now - self.last_denied_at) > WINDOW {
            now
        } else {
            0
        };
        self.above_since = Some(above);
        self.below_since = Some(below);

        let is_limited = self.is_limited();
        let review_at = self.review_at.unwrap_or(0);
        if !is_limited && above != 0 && (now - above) >= WINDOW {
            self.limited = Some(true);
            self.limited_since = Some(now);
            self.review_at = Some(now + PERIOD);
            self.extensions = 0;
            self.event = Some("limited".to_string());
            changed = true;
        } else if is_limited && now >= review_at {
            if below != 0 && (now - below) >= WINDOW {
                self.limited = Some(false);
                self.recovered_at = Some(now);
                self.event = Some("released".to_string());
                changed = true;
            } else if count >= 500 || (now - self.last_denied_at) <= WINDOW {
                self.review_at = Some(now.max(review_at) + PERIOD);
                self.extensions += 1;
                self.event = Some("extended".to_string());
            }
        }
        changed
    }

    pub fn status(&self) -> BTreeMap<String, JsonVal> {
        const STATUS_KEYS: &[&str] = &[
            "sample_state",
            "sampled_at",
            "tcp_connections",
            "sources",
            "source_order_basis",
            "blocked",
            "blocked_packets",
            "tcp_denied",
            "limited",
            "limited_since",
            "review_at",
            "extensions",
            "recovered_at",
            "event",
            "last_blocked_at",
        ];
        let full = self.to_json_map();
        let mut res = BTreeMap::new();
        for &k in STATUS_KEYS {
            if let Some(v) = full.get(k) {
                res.insert(k.to_string(), v.clone());
            }
        }
        let confirmed_sources: Vec<JsonVal> = self
            .sources
            .iter()
            .filter(|x| x.confirmed)
            .map(SourceEntry::to_json_val)
            .collect();
        let probation_sources: Vec<JsonVal> = self
            .sources
            .iter()
            .filter(|x| !x.confirmed)
            .map(SourceEntry::to_json_val)
            .collect();
        res.insert(
            "confirmed_sources".to_string(),
            JsonVal::Arr(confirmed_sources),
        );
        res.insert(
            "probation_sources".to_string(),
            JsonVal::Arr(probation_sources),
        );
        res
    }
}
