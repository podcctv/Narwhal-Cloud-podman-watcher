#![forbid(unsafe_code)]

//! Pure-Rust state machines for conservative, reversible container resource guards.
//!
//! This crate mirrors the exact threshold, hysteresis, sustained window,
//! escalation, recovery, and cooldown contracts of:
//! - `client/cpu_guard.py` (`CpuGuardTracker`)
//! - `client/memory_guard.py` (`MemoryGuardTracker`)
//! - `client/io_guard.py` (`IoGuardTracker`)

use std::collections::{HashMap, HashSet};

pub mod security;

/// Host or cgroup PSI sample (`avg10` primary, `avg60` optional secondary).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct PsiSample {
    pub avg10: Option<f64>,
    pub avg60: Option<f64>,
}

impl PsiSample {
    /// Create a PSI sample from finite non-negative percentages.
    pub fn new(avg10: Option<f64>, avg60: Option<f64>) -> Self {
        Self {
            avg10: sanitize_non_neg(avg10),
            avg60: sanitize_non_neg(avg60),
        }
    }

    /// Return primary `avg10` if available, otherwise fall back to `avg60`.
    pub fn effective_avg(&self) -> Option<f64> {
        sanitize_non_neg(self.avg10).or_else(|| sanitize_non_neg(self.avg60))
    }
}

fn sanitize_non_neg(v: Option<f64>) -> Option<f64> {
    match v {
        Some(n) if n.is_finite() && n >= 0.0 => Some(n),
        _ => None,
    }
}

fn finite_or(v: f64, default: f64) -> f64 {
    if v.is_finite() {
        v
    } else {
        default
    }
}

fn ceil_div_plus_one(duration: u64, interval: f64) -> usize {
    let ratio = (duration as f64 / interval).ceil();
    if ratio.is_finite() && ratio >= 0.0 {
        (ratio as usize).saturating_add(1)
    } else {
        1
    }
}

/// Lifecycle stage of a guarded container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardStage {
    Normal,
    WaitingForPressure,
    WaitingForHostPsi,
    Watching,
    WaitingForOtherLimit,
    Active,
    Restored,
    Cooldown,
    SamplingUnavailable,
    Unsupported,
}

// ============================================================================
// 1. CpuGuardTracker
// ============================================================================

/// Configuration matching `client/cpu_guard.py` defaults and clamping bounds.
#[derive(Debug, Clone, PartialEq)]
pub struct CpuGuardConfig {
    pub interval_seconds: f64,
    pub high_threshold_percent: f64,
    pub host_busy_threshold_percent: f64,
    pub recovery_ratio: f64,
    pub recovery_host_busy_threshold_percent: f64,
    pub host_psi_threshold_percent: f64,
    pub recovery_host_psi_threshold_percent: f64,
    pub required_duration_seconds: u64,
    pub runaway_required_duration_seconds: u64,
    pub explicit_required_duration_override: bool,
    pub escalation_duration_seconds: u64,
    pub recovery_duration_seconds: u64,
    pub recovery_samples_min: usize,
    pub retry_seconds: u64,
    pub cooldown_seconds: u64,
    pub target_ratio: f64,
    pub contention_min_cpu_percent: Option<f64>,
    pub max_simultaneous_limits: Option<usize>,
}

impl Default for CpuGuardConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 300.0,
            high_threshold_percent: 65.0,
            host_busy_threshold_percent: 80.0,
            recovery_ratio: 0.5,
            recovery_host_busy_threshold_percent: 70.0,
            host_psi_threshold_percent: 5.0,
            recovery_host_psi_threshold_percent: 2.0,
            required_duration_seconds: 600,
            runaway_required_duration_seconds: 180,
            explicit_required_duration_override: false,
            escalation_duration_seconds: 300,
            recovery_duration_seconds: 600,
            recovery_samples_min: 3,
            retry_seconds: 600,
            cooldown_seconds: 900,
            target_ratio: 0.5,
            contention_min_cpu_percent: None,
            max_simultaneous_limits: None,
        }
    }
}

impl CpuGuardConfig {
    /// Return a clamped copy enforcing all `cpu_guard.py` bounds.
    pub fn normalized(&self) -> Self {
        let interval = finite_or(self.interval_seconds, 300.0).max(30.0);
        let high = finite_or(self.high_threshold_percent, 65.0).clamp(50.0, 99.0);
        let host_busy = finite_or(self.host_busy_threshold_percent, 80.0).clamp(50.0, 99.0);
        let rec_ratio = finite_or(self.recovery_ratio, 0.5).clamp(0.1, 0.8);
        let rec_host_busy = finite_or(self.recovery_host_busy_threshold_percent, 70.0).clamp(0.0, 99.0);
        let host_psi = finite_or(self.host_psi_threshold_percent, 5.0).clamp(0.1, 50.0);
        let rec_host_psi = finite_or(self.recovery_host_psi_threshold_percent, 2.0).clamp(0.0, host_psi);
        let req_dur = self.required_duration_seconds.max(600);
        let runaway_dur = self.runaway_required_duration_seconds.max(120);
        let esc_dur = self.escalation_duration_seconds.max(300);
        let rec_dur = self.recovery_duration_seconds.max(600);
        let rec_samples_min = self.recovery_samples_min.max(1);
        let retry = self.retry_seconds.max(300);
        let cooldown = self.cooldown_seconds.max(300);
        let target_ratio = finite_or(self.target_ratio, 0.5).clamp(0.1, 0.75);
        let contention_min = self
            .contention_min_cpu_percent
            .map(|v| finite_or(v, 10.0).clamp(5.0, 50.0));
        let max_sim = self.max_simultaneous_limits.map(|v| v.max(1));
        Self {
            interval_seconds: interval,
            high_threshold_percent: high,
            host_busy_threshold_percent: host_busy,
            recovery_ratio: rec_ratio,
            recovery_host_busy_threshold_percent: rec_host_busy,
            host_psi_threshold_percent: host_psi,
            recovery_host_psi_threshold_percent: rec_host_psi,
            required_duration_seconds: req_dur,
            runaway_required_duration_seconds: runaway_dur,
            explicit_required_duration_override: self.explicit_required_duration_override,
            escalation_duration_seconds: esc_dur,
            recovery_duration_seconds: rec_dur,
            recovery_samples_min: rec_samples_min,
            retry_seconds: retry,
            cooldown_seconds: cooldown,
            target_ratio,
            contention_min_cpu_percent: contention_min,
            max_simultaneous_limits: max_sim,
        }
    }

    fn max_gap(&self) -> u64 {
        ((self.interval_seconds * 2.5) as u64).max(180)
    }

    fn min_samples(&self) -> usize {
        ceil_div_plus_one(self.required_duration_seconds, self.interval_seconds).max(3)
    }

    fn escalation_samples(&self) -> usize {
        ceil_div_plus_one(self.escalation_duration_seconds, self.interval_seconds).max(2)
    }

    fn recovery_samples(&self) -> usize {
        ceil_div_plus_one(self.recovery_duration_seconds, self.interval_seconds)
            .max(3)
            .max(self.recovery_samples_min)
    }
}

/// Host CPU sample for `CpuGuardTracker`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HostCpuSample {
    pub ready: bool,
    pub busy_percent: f64,
    pub logical_cpus: u32,
    pub load_1m: Option<f64>,
    pub psi_some_avg10: Option<f64>,
}

/// Per-container CPU observation input.
#[derive(Debug, Clone, PartialEq)]
pub struct CpuContainerSample {
    pub key: String,
    pub cpu_percent: Option<f64>,
    pub effective_cpus: f64,
    pub cgroup_cpu_psi_some_avg10: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
enum CpuRecordState {
    Candidate {
        high_samples: usize,
        high_since: u64,
        last_high: u64,
        required_samples: usize,
        required_duration: u64,
        is_runaway: bool,
        is_contention: bool,
        pressure_basis: &'static str,
    },
    Active {
        tier: u8,
        original_cpus: f64,
        applied_cpus: f64,
        applied_at: u64,
        last_step_at: u64,
        escalation_high_samples: usize,
        escalation_high_since: u64,
        escalation_last_high: u64,
        low_samples: usize,
        low_since: u64,
    },
    Cooldown {
        cooldown_until: u64,
    },
}

/// Action emitted for a container during a CPU guard observation tick.
#[derive(Debug, Clone, PartialEq)]
pub enum CpuGuardAction {
    ApplyLimit {
        key: String,
        tier: u8,
        target_cpus: f64,
        fair_share_cpus: Option<f64>,
        pressure_basis: &'static str,
    },
    EscalateLimit {
        key: String,
        tier: u8,
        target_cpus: f64,
    },
    RestoreLimit {
        key: String,
        original_cpus: f64,
        cooldown_until: u64,
    },
}

/// Per-container status snapshot returned by `CpuGuardTracker::observe`.
#[derive(Debug, Clone, PartialEq)]
pub struct CpuContainerDecision {
    pub key: String,
    pub stage: GuardStage,
    pub tier: u8,
    pub applied_cpus: Option<f64>,
    pub high_samples: usize,
    pub required_samples: usize,
    pub low_samples: usize,
    pub recovery_samples_required: usize,
    pub escalation_samples: usize,
    pub escalation_samples_required: usize,
    pub cooldown_remaining_seconds: u64,
    pub pressure_basis: &'static str,
}

/// Summary of a single `CpuGuardTracker::observe` tick.
#[derive(Debug, Clone, PartialEq)]
pub struct CpuObserveOutput {
    pub multi_container_contention: bool,
    pub decisions: Vec<CpuContainerDecision>,
    pub actions: Vec<CpuGuardAction>,
}

/// Stateful CPU guard tracker implementing sustained window, hysteresis,
/// multi-container contention target calculation, tiered escalation, and recovery.
#[derive(Debug, Clone)]
pub struct CpuGuardTracker {
    config: CpuGuardConfig,
    records: HashMap<String, CpuRecordState>,
}

impl CpuGuardTracker {
    pub fn new(config: CpuGuardConfig) -> Self {
        Self {
            config: config.normalized(),
            records: HashMap::new(),
        }
    }

    pub fn config(&self) -> &CpuGuardConfig {
        &self.config
    }

    /// Compute target CPUs given original effective CPUs and optional multi-container fair-share cap.
    pub fn compute_target_cpus(
        &self,
        configured_cpus: f64,
        effective_cpus: f64,
        fair_share_cpus: Option<f64>,
    ) -> Option<f64> {
        let avail = finite_or(effective_cpus, 0.0).max(0.0);
        let conf = finite_or(configured_cpus, 0.0).max(0.0);
        let baseline = if avail > 0.0 && conf > 0.0 {
            conf.min(avail)
        } else if avail > 0.0 {
            avail
        } else {
            conf
        };
        if baseline <= 0.0 {
            return None;
        }
        let mut desired = baseline * self.config.target_ratio;
        if let Some(fs) = fair_share_cpus {
            if fs.is_finite() && fs > 0.0 {
                desired = desired.min(fs.max(0.1));
            }
        }
        if desired > 0.0 && desired < baseline {
            Some(desired)
        } else {
            None
        }
    }

    fn host_cpu_pressure(&self, host: &HostCpuSample) -> (bool, Option<f64>, &'static str) {
        let busy = finite_or(host.busy_percent, -1.0);
        let psi = sanitize_non_neg(host.psi_some_avg10);
        if !host.ready || busy < self.config.host_busy_threshold_percent {
            return (false, psi, "host_busy_below_threshold");
        }
        match psi {
            None => (true, None, "host_busy_psi_unavailable_fallback"),
            Some(p) if p < self.config.host_psi_threshold_percent => {
                (false, Some(p), "host_psi_below_threshold")
            }
            Some(p) => (true, Some(p), "host_busy_and_psi_confirmed"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn container_cpu_pressure_confirmed(
        &self,
        host: &HostCpuSample,
        metrics_cpu: f64,
        saturation: f64,
        cgroup_cpu_psi: Option<f64>,
        host_pressure_confirmed: bool,
        host_pressure_basis: &'static str,
    ) -> (bool, &'static str, bool) {
        if !host.ready {
            return (false, host_pressure_basis, false);
        }
        let busy = finite_or(host.busy_percent, -1.0);
        let logical_cpus = host.logical_cpus.max(1) as f64;
        let load_1m = sanitize_non_neg(host.load_1m).unwrap_or(-1.0);
        let runaway_threshold = self.config.high_threshold_percent.max(85.0).min(99.0);
        let is_runaway = metrics_cpu >= runaway_threshold
            && (saturation * 100.0 >= runaway_threshold
                || metrics_cpu >= logical_cpus * 75.0
                || (logical_cpus <= 1.0 && metrics_cpu >= runaway_threshold));
        if host_pressure_confirmed {
            return (true, host_pressure_basis, is_runaway);
        }
        if busy < self.config.host_busy_threshold_percent {
            return (false, host_pressure_basis, false);
        }
        if let Some(cpsi) = sanitize_non_neg(cgroup_cpu_psi) {
            if cpsi >= self.config.host_psi_threshold_percent {
                return (true, "host_busy_and_container_psi_confirmed", is_runaway);
            }
        }
        let busy_85 = self.config.host_busy_threshold_percent.max(85.0);
        let busy_95 = self.config.host_busy_threshold_percent.max(95.0);
        let single_core_threshold = self.config.high_threshold_percent.max(70.0).min(runaway_threshold);
        if logical_cpus <= 1.0
            && (busy >= busy_95 || (busy >= busy_85 && load_1m >= 1.0))
            && (metrics_cpu >= single_core_threshold || saturation * 100.0 >= single_core_threshold)
        {
            return (true, "single_core_host_cpu_saturation", true);
        }
        if logical_cpus <= 1.0
            && busy >= busy_85
            && (metrics_cpu >= runaway_threshold || saturation * 100.0 >= runaway_threshold)
        {
            return (true, "single_core_host_cpu_saturation", true);
        }
        if busy >= busy_85 && metrics_cpu >= runaway_threshold.max(logical_cpus * 75.0) {
            return (true, "host_dominant_container_cpu_saturation", true);
        }
        if (busy >= self.config.host_busy_threshold_percent.max(95.0)
            || (busy >= busy_85 && load_1m >= logical_cpus))
            && is_runaway
        {
            return (true, "host_extreme_busy_runaway_container", true);
        }
        (false, host_pressure_basis, false)
    }

    /// Observe one tick across all containers at `timestamp` (unix seconds).
    pub fn observe(
        &mut self,
        timestamp: u64,
        host: &HostCpuSample,
        containers: &[CpuContainerSample],
        allow_new_limits: bool,
    ) -> CpuObserveOutput {
        let logical_cpus = host.logical_cpus.max(1);
        let max_gap = self.config.max_gap();
        let min_samples = self.config.min_samples();
        let esc_samples = self.config.escalation_samples();
        let rec_samples = self.config.recovery_samples();
        let (host_pressure_confirmed, host_cpu_psi, host_pressure_basis) =
            self.host_cpu_pressure(host);
        let host_busy = if host.ready {
            finite_or(host.busy_percent, -1.0)
        } else {
            -1.0
        };
        let load_1m = sanitize_non_neg(host.load_1m).unwrap_or(-1.0);
        let host_contention_confirmed = host.ready
            && host_busy >= self.config.host_busy_threshold_percent
            && (host_pressure_confirmed
                || (host_busy >= self.config.host_busy_threshold_percent.max(85.0)
                    && load_1m >= logical_cpus as f64)
                || host_busy >= 95.0);

        let default_contention_min = if logical_cpus <= 1 {
            8.0
        } else if logical_cpus <= 2 {
            10.0
        } else {
            15.0
        };
        let contention_min_cpu = self
            .config
            .contention_min_cpu_percent
            .unwrap_or(default_contention_min);

        let contending_cpus: Vec<f64> = containers
            .iter()
            .filter_map(|c| sanitize_non_neg(c.cpu_percent))
            .filter(|&cpu| cpu >= contention_min_cpu)
            .collect();
        let multi_container_contention = host_contention_confirmed
            && contending_cpus.len() >= 2
            && contending_cpus.iter().sum::<f64>() >= (logical_cpus as f64 * 25.0).max(25.0);

        let max_simultaneous = self
            .config
            .max_simultaneous_limits
            .unwrap_or_else(|| (logical_cpus as usize * 4).max(2))
            .max(1);

        let mut seen: HashSet<String> = HashSet::with_capacity(containers.len());
        let mut active_keys: HashSet<String> = HashSet::new();
        let mut ready_candidates: Vec<(String, f64, f64, &'static str)> = Vec::new();
        let mut decisions: Vec<CpuContainerDecision> = Vec::with_capacity(containers.len());
        let mut actions: Vec<CpuGuardAction> = Vec::new();

        for container in containers {
            seen.insert(container.key.clone());
            let metrics_cpu = sanitize_non_neg(container.cpu_percent).unwrap_or(-1.0);
            let sample_available = metrics_cpu >= 0.0;
            let effective_cpus = if container.effective_cpus.is_finite() && container.effective_cpus > 0.0 {
                container.effective_cpus
            } else {
                logical_cpus as f64
            };

            // 1. Cooldown check
            if let Some(CpuRecordState::Cooldown { cooldown_until }) = self.records.get(&container.key) {
                let remaining = cooldown_until.saturating_sub(timestamp);
                if remaining > 0 {
                    decisions.push(CpuContainerDecision {
                        key: container.key.clone(),
                        stage: GuardStage::Cooldown,
                        tier: 0,
                        applied_cpus: None,
                        high_samples: 0,
                        required_samples: min_samples,
                        low_samples: 0,
                        recovery_samples_required: rec_samples,
                        escalation_samples: 0,
                        escalation_samples_required: esc_samples,
                        cooldown_remaining_seconds: remaining,
                        pressure_basis: "cooldown",
                    });
                    continue;
                }
                self.records.remove(&container.key);
            }

            // 2. Active state (escalation & recovery)
            if let Some(CpuRecordState::Active {
                tier,
                original_cpus,
                applied_cpus,
                applied_at,
                last_step_at,
                escalation_high_samples,
                escalation_high_since,
                escalation_last_high,
                low_samples,
                low_since,
            }) = self.records.get(&container.key).cloned()
            {
                let mut cur_tier = tier.clamp(1, 3);
                let mut cur_applied = applied_cpus.max(0.001);
                let mut cur_last_step = last_step_at;
                let mut esc_samples_cnt = escalation_high_samples;
                let mut esc_since = escalation_high_since;
                let mut esc_last = escalation_last_high;
                let mut cur_low_samples = low_samples;
                let mut cur_low_since = low_since;

                let ratio = if metrics_cpu >= 0.0 {
                    metrics_cpu / (cur_applied * 100.0)
                } else {
                    -1.0
                };
                let (active_pressure_confirmed, active_basis, _) = self
                    .container_cpu_pressure_confirmed(
                        host,
                        metrics_cpu,
                        ratio.max(0.0),
                        container.cgroup_cpu_psi_some_avg10,
                        host_pressure_confirmed,
                        host_pressure_basis,
                    );
                let high_now = ratio * 100.0 >= self.config.high_threshold_percent
                    && (active_pressure_confirmed || ratio >= 0.90);

                if high_now && cur_tier < 3 {
                    if esc_last == 0 || timestamp <= esc_last || timestamp - esc_last > max_gap {
                        esc_since = timestamp;
                        esc_samples_cnt = 1;
                    } else {
                        esc_samples_cnt += 1;
                    }
                    esc_last = timestamp;
                    let step_ratio = if cur_tier == 1 { 0.5 } else { 0.4 };
                    let target_cpus = (cur_applied * step_ratio).max(0.001);
                    if esc_samples_cnt >= esc_samples
                        && timestamp.saturating_sub(esc_since) >= self.config.escalation_duration_seconds
                        && timestamp.saturating_sub(cur_last_step.max(applied_at))
                            >= self.config.escalation_duration_seconds
                        && target_cpus < cur_applied
                    {
                        cur_tier += 1;
                        cur_applied = target_cpus;
                        cur_last_step = timestamp;
                        esc_samples_cnt = 0;
                        esc_since = 0;
                        esc_last = 0;
                        actions.push(CpuGuardAction::EscalateLimit {
                            key: container.key.clone(),
                            tier: cur_tier,
                            target_cpus: cur_applied,
                        });
                    }
                } else {
                    esc_samples_cnt = 0;
                    esc_since = 0;
                    esc_last = 0;
                }

                let ratio_after = if metrics_cpu >= 0.0 {
                    metrics_cpu / (cur_applied * 100.0)
                } else {
                    -1.0
                };
                let recovering = ratio_after >= 0.0
                    && ratio_after <= self.config.recovery_ratio
                    && host.ready
                    && host_busy < self.config.recovery_host_busy_threshold_percent
                    && host_cpu_psi.map_or(true, |p| p < self.config.recovery_host_psi_threshold_percent);
                if recovering {
                    if cur_low_since == 0 {
                        cur_low_since = timestamp;
                    }
                    cur_low_samples += 1;
                } else {
                    cur_low_samples = 0;
                    cur_low_since = 0;
                }

                if cur_low_samples >= rec_samples
                    && timestamp.saturating_sub(cur_low_since) >= self.config.recovery_duration_seconds
                {
                    let cooldown_until = timestamp + self.config.cooldown_seconds;
                    self.records.insert(
                        container.key.clone(),
                        CpuRecordState::Cooldown { cooldown_until },
                    );
                    actions.push(CpuGuardAction::RestoreLimit {
                        key: container.key.clone(),
                        original_cpus,
                        cooldown_until,
                    });
                    decisions.push(CpuContainerDecision {
                        key: container.key.clone(),
                        stage: GuardStage::Restored,
                        tier: 0,
                        applied_cpus: None,
                        high_samples: 0,
                        required_samples: min_samples,
                        low_samples: cur_low_samples,
                        recovery_samples_required: rec_samples,
                        escalation_samples: 0,
                        escalation_samples_required: esc_samples,
                        cooldown_remaining_seconds: self.config.cooldown_seconds,
                        pressure_basis: active_basis,
                    });
                    continue;
                }

                active_keys.insert(container.key.clone());
                self.records.insert(
                    container.key.clone(),
                    CpuRecordState::Active {
                        tier: cur_tier,
                        original_cpus,
                        applied_cpus: cur_applied,
                        applied_at,
                        last_step_at: cur_last_step,
                        escalation_high_samples: esc_samples_cnt,
                        escalation_high_since: esc_since,
                        escalation_last_high: esc_last,
                        low_samples: cur_low_samples,
                        low_since: cur_low_since,
                    },
                );
                decisions.push(CpuContainerDecision {
                    key: container.key.clone(),
                    stage: GuardStage::Active,
                    tier: cur_tier,
                    applied_cpus: Some(cur_applied),
                    high_samples: 0,
                    required_samples: min_samples,
                    low_samples: cur_low_samples,
                    recovery_samples_required: rec_samples,
                    escalation_samples: esc_samples_cnt,
                    escalation_samples_required: esc_samples,
                    cooldown_remaining_seconds: 0,
                    pressure_basis: active_basis,
                });
                continue;
            }

            if !allow_new_limits {
                self.records.remove(&container.key);
                decisions.push(CpuContainerDecision {
                    key: container.key.clone(),
                    stage: GuardStage::Normal,
                    tier: 0,
                    applied_cpus: None,
                    high_samples: 0,
                    required_samples: min_samples,
                    low_samples: 0,
                    recovery_samples_required: rec_samples,
                    escalation_samples: 0,
                    escalation_samples_required: esc_samples,
                    cooldown_remaining_seconds: 0,
                    pressure_basis: "disabled",
                });
                continue;
            }

            // 3. Candidate evaluation
            let saturation = if metrics_cpu >= 0.0 && effective_cpus > 0.0 {
                metrics_cpu / (effective_cpus * 100.0)
            } else {
                -1.0
            };
            let per_core_pressure = metrics_cpu >= self.config.high_threshold_percent;
            let (pressure_confirmed, mut container_basis, is_runaway) = self
                .container_cpu_pressure_confirmed(
                    host,
                    metrics_cpu,
                    saturation,
                    container.cgroup_cpu_psi_some_avg10,
                    host_pressure_confirmed,
                    host_pressure_basis,
                );
            let is_contention = multi_container_contention && metrics_cpu >= contention_min_cpu;
            let qualifies = (((saturation * 100.0 >= self.config.high_threshold_percent
                || per_core_pressure)
                && pressure_confirmed)
                || is_contention)
                && effective_cpus > 0.0
                && host.ready;
            if is_contention && !(saturation * 100.0 >= self.config.high_threshold_percent || per_core_pressure) {
                container_basis = if host_pressure_confirmed {
                    host_pressure_basis
                } else {
                    "multi_container_host_cpu_contention"
                };
            }

            if qualifies {
                let (prev_samples, prev_since, prev_last_high) = match self.records.get(&container.key) {
                    Some(CpuRecordState::Candidate {
                        high_samples,
                        high_since,
                        last_high,
                        ..
                    }) => (*high_samples, *high_since, *last_high),
                    _ => (0, 0, 0),
                };
                let (high_samples, high_since) = if prev_last_high == 0
                    || timestamp <= prev_last_high
                    || timestamp - prev_last_high > max_gap
                {
                    (1, timestamp)
                } else {
                    (prev_samples + 1, prev_since)
                };

                let (cand_req_duration, cand_min_samples) =
                    if (is_runaway || is_contention) && !self.config.explicit_required_duration_override {
                        let rd = self
                            .config
                            .required_duration_seconds
                            .min(self.config.runaway_required_duration_seconds);
                        let ms = ceil_div_plus_one(rd, self.config.interval_seconds).max(2);
                        (rd, ms)
                    } else {
                        (self.config.required_duration_seconds, min_samples)
                    };

                self.records.insert(
                    container.key.clone(),
                    CpuRecordState::Candidate {
                        high_samples,
                        high_since,
                        last_high: timestamp,
                        required_samples: cand_min_samples,
                        required_duration: cand_req_duration,
                        is_runaway,
                        is_contention,
                        pressure_basis: container_basis,
                    },
                );

                if high_samples >= cand_min_samples
                    && timestamp.saturating_sub(high_since) >= cand_req_duration
                {
                    ready_candidates.push((
                        container.key.clone(),
                        metrics_cpu,
                        effective_cpus,
                        container_basis,
                    ));
                }

                decisions.push(CpuContainerDecision {
                    key: container.key.clone(),
                    stage: GuardStage::Watching,
                    tier: 0,
                    applied_cpus: None,
                    high_samples,
                    required_samples: cand_min_samples,
                    low_samples: 0,
                    recovery_samples_required: rec_samples,
                    escalation_samples: 0,
                    escalation_samples_required: esc_samples,
                    cooldown_remaining_seconds: 0,
                    pressure_basis: container_basis,
                });
            } else {
                // Hysteresis hold during transient warming / unavailable sample within max_gap
                let hold = (!host.ready || !sample_available)
                    && matches!(
                        self.records.get(&container.key),
                        Some(CpuRecordState::Candidate { high_samples, last_high, .. })
                        if *high_samples > 0 && timestamp.saturating_sub(*last_high) <= max_gap
                    );
                if !hold {
                    self.records.remove(&container.key);
                }
                let stage = if !sample_available || effective_cpus <= 0.0 || !host.ready {
                    GuardStage::SamplingUnavailable
                } else if saturation < self.config.high_threshold_percent / 100.0 && !per_core_pressure {
                    GuardStage::Normal
                } else if host_busy >= self.config.host_busy_threshold_percent
                    && host_cpu_psi.map_or(false, |p| p < self.config.host_psi_threshold_percent)
                {
                    GuardStage::WaitingForHostPsi
                } else {
                    GuardStage::WaitingForPressure
                };
                decisions.push(CpuContainerDecision {
                    key: container.key.clone(),
                    stage,
                    tier: 0,
                    applied_cpus: None,
                    high_samples: 0,
                    required_samples: min_samples,
                    low_samples: 0,
                    recovery_samples_required: rec_samples,
                    escalation_samples: 0,
                    escalation_samples_required: esc_samples,
                    cooldown_remaining_seconds: 0,
                    pressure_basis: container_basis,
                });
            }
        }

        // Prune vanished candidates
        self.records.retain(|k, v| {
            seen.contains(k) || !matches!(v, CpuRecordState::Candidate { .. })
        });

        // Apply limits to ready candidates up to remaining slots, with fair-share contention cap
        let remaining_slots = max_simultaneous.saturating_sub(active_keys.len());
        if remaining_slots > 0 && !ready_candidates.is_empty() {
            ready_candidates.sort_by(|a, b| {
                b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
            });
            let to_limit_count = ready_candidates.len().min(remaining_slots);
            let total_contending_limited = active_keys.len() + to_limit_count;
            let fair_share_cpus = if total_contending_limited >= 2 {
                Some(((0.85 * logical_cpus as f64) / total_contending_limited as f64).max(0.15))
            } else {
                None
            };

            for (key, _cpu, effective_cpus, basis) in ready_candidates.into_iter().take(to_limit_count) {
                if let Some(target_cpus) =
                    self.compute_target_cpus(effective_cpus, effective_cpus, fair_share_cpus)
                {
                    self.records.insert(
                        key.clone(),
                        CpuRecordState::Active {
                            tier: 1,
                            original_cpus: effective_cpus,
                            applied_cpus: target_cpus,
                            applied_at: timestamp,
                            last_step_at: timestamp,
                            escalation_high_samples: 0,
                            escalation_high_since: 0,
                            escalation_last_high: 0,
                            low_samples: 0,
                            low_since: 0,
                        },
                    );
                    if let Some(dec) = decisions.iter_mut().find(|d| d.key == key) {
                        dec.stage = GuardStage::Active;
                        dec.tier = 1;
                        dec.applied_cpus = Some(target_cpus);
                    }
                    actions.push(CpuGuardAction::ApplyLimit {
                        key,
                        tier: 1,
                        target_cpus,
                        fair_share_cpus,
                        pressure_basis: basis,
                    });
                }
            }
        }

        CpuObserveOutput {
            multi_container_contention,
            decisions,
            actions,
        }
    }
}

// ============================================================================
// 2. MemoryGuardTracker
// ============================================================================

/// Configuration matching `client/memory_guard.py` defaults and clamping bounds.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryGuardConfig {
    pub interval_seconds: f64,
    pub start_usage_percent: f64,
    pub host_psi_threshold_percent: f64,
    pub container_psi_threshold_percent: f64,
    pub required_duration_seconds: u64,
    pub escalation_duration_seconds: u64,
    pub recovery_duration_seconds: u64,
    pub cooldown_seconds: u64,
    pub recovery_psi_threshold_percent: f64,
}

impl Default for MemoryGuardConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 300.0,
            start_usage_percent: 85.0,
            host_psi_threshold_percent: 5.0,
            container_psi_threshold_percent: 5.0,
            required_duration_seconds: 600,
            escalation_duration_seconds: 600,
            recovery_duration_seconds: 900,
            cooldown_seconds: 900,
            recovery_psi_threshold_percent: 2.0,
        }
    }
}

impl MemoryGuardConfig {
    /// Return a clamped copy enforcing all `memory_guard.py` bounds.
    pub fn normalized(&self) -> Self {
        let interval = finite_or(self.interval_seconds, 300.0).max(60.0);
        let start_usage = finite_or(self.start_usage_percent, 85.0).clamp(70.0, 98.0);
        let host_psi = finite_or(self.host_psi_threshold_percent, 5.0).clamp(1.0, 80.0);
        let cgroup_psi = finite_or(self.container_psi_threshold_percent, 5.0).clamp(1.0, 90.0);
        let req_dur = self.required_duration_seconds.max(600);
        let esc_dur = self.escalation_duration_seconds.max(300);
        let rec_dur = self.recovery_duration_seconds.max(600);
        let cooldown = self.cooldown_seconds.max(300);
        let rec_psi = finite_or(self.recovery_psi_threshold_percent, 2.0).clamp(0.5, host_psi);
        Self {
            interval_seconds: interval,
            start_usage_percent: start_usage,
            host_psi_threshold_percent: host_psi,
            container_psi_threshold_percent: cgroup_psi,
            required_duration_seconds: req_dur,
            escalation_duration_seconds: esc_dur,
            recovery_duration_seconds: rec_dur,
            cooldown_seconds: cooldown,
            recovery_psi_threshold_percent: rec_psi,
        }
    }

    fn max_gap(&self) -> u64 {
        ((self.interval_seconds * 2.5) as u64).max(180)
    }

    fn min_samples(&self) -> usize {
        ceil_div_plus_one(self.required_duration_seconds, self.interval_seconds).max(3)
    }

    fn escalation_samples(&self) -> usize {
        ceil_div_plus_one(self.escalation_duration_seconds, self.interval_seconds).max(2)
    }

    fn recovery_samples(&self) -> usize {
        ceil_div_plus_one(self.recovery_duration_seconds, self.interval_seconds).max(3)
    }
}

const MIN_MEMORY_MAX_BYTES: u64 = 32 * 1024 * 1024;
const MIN_MEMORY_HIGH_BYTES: u64 = 16 * 1024 * 1024;

/// Compute `memory.high` target bytes for tier 1 (90%), 2 (80%), or 3 (70%).
pub fn memory_tier_target_bytes(max_bytes: u64, tier: u8) -> u64 {
    let ratio = match tier {
        1 => 0.90,
        2 => 0.80,
        _ => 0.70,
    };
    ((max_bytes as f64 * ratio) as u64).max(MIN_MEMORY_HIGH_BYTES)
}

/// Per-container memory observation input.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryContainerSample {
    pub key: String,
    pub current_bytes: u64,
    pub max_bytes: Option<u64>,
    pub original_high_bytes: Option<u64>,
    pub container_psi: PsiSample,
}

#[derive(Debug, Clone, PartialEq)]
enum MemoryRecordState {
    Candidate {
        high_samples: usize,
        high_since: u64,
        last_high: u64,
    },
    Active {
        tier: u8,
        original_high_bytes: Option<u64>,
        applied_high_bytes: u64,
        escalation_since: u64,
        escalation_samples: usize,
        last_high: u64,
        low_since: u64,
        last_low: u64,
        low_samples: usize,
    },
    Cooldown {
        cooldown_until: u64,
    },
}

/// Action emitted for a container during a memory guard observation tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryGuardAction {
    ApplyMemoryHigh {
        key: String,
        tier: u8,
        target_bytes: u64,
    },
    EscalateMemoryHigh {
        key: String,
        tier: u8,
        target_bytes: u64,
    },
    RestoreMemoryHigh {
        key: String,
        original_high_bytes: Option<u64>,
        cooldown_until: u64,
    },
}

/// Per-container status snapshot returned by `MemoryGuardTracker::observe`.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryContainerDecision {
    pub key: String,
    pub stage: GuardStage,
    pub tier: u8,
    pub applied_high_bytes: Option<u64>,
    pub used_percent: Option<f64>,
    pub high_samples: usize,
    pub required_samples: usize,
    pub low_samples: usize,
    pub recovery_samples_required: usize,
    pub cooldown_remaining_seconds: u64,
}

/// Stateful memory guard tracker implementing PSI (`avg10`/`avg60`) + cgroup memory %
/// sustained pressure, tiered `memory.high` escalation, and recovery/cooldown.
#[derive(Debug, Clone)]
pub struct MemoryGuardTracker {
    config: MemoryGuardConfig,
    records: HashMap<String, MemoryRecordState>,
}

impl MemoryGuardTracker {
    pub fn new(config: MemoryGuardConfig) -> Self {
        Self {
            config: config.normalized(),
            records: HashMap::new(),
        }
    }

    pub fn config(&self) -> &MemoryGuardConfig {
        &self.config
    }

    /// Observe one tick across containers with host memory PSI (`avg10`/`avg60`).
    pub fn observe(
        &mut self,
        timestamp: u64,
        host_psi: PsiSample,
        containers: &[MemoryContainerSample],
        allow_new_limits: bool,
    ) -> (Vec<MemoryContainerDecision>, Vec<MemoryGuardAction>) {
        let max_gap = self.config.max_gap();
        let min_samples = self.config.min_samples();
        let esc_samples_req = self.config.escalation_samples();
        let rec_samples_req = self.config.recovery_samples();
        let host_some = host_psi.effective_avg();

        let mut seen: HashSet<String> = HashSet::with_capacity(containers.len());
        let mut reserved: HashSet<String> = self
            .records
            .iter()
            .filter_map(|(k, v)| match v {
                MemoryRecordState::Active { .. } => Some(k.clone()),
                _ => None,
            })
            .collect();

        let mut decisions = Vec::with_capacity(containers.len());
        let mut actions = Vec::new();

        for container in containers {
            seen.insert(container.key.clone());
            let used_percent = container
                .max_bytes
                .filter(|&m| m > 0)
                .map(|m| (container.current_bytes as f64 * 100.0) / m as f64);
            let cgroup_some = container.container_psi.effective_avg();

            // 1. Cooldown
            if let Some(MemoryRecordState::Cooldown { cooldown_until }) =
                self.records.get(&container.key)
            {
                let remaining = cooldown_until.saturating_sub(timestamp);
                if remaining > 0 {
                    decisions.push(MemoryContainerDecision {
                        key: container.key.clone(),
                        stage: GuardStage::Cooldown,
                        tier: 0,
                        applied_high_bytes: None,
                        used_percent,
                        high_samples: 0,
                        required_samples: min_samples,
                        low_samples: 0,
                        recovery_samples_required: rec_samples_req,
                        cooldown_remaining_seconds: remaining,
                    });
                    continue;
                }
                self.records.remove(&container.key);
            }

            // 2. Active state
            if let Some(MemoryRecordState::Active {
                tier,
                original_high_bytes,
                applied_high_bytes,
                escalation_since,
                escalation_samples,
                last_high,
                low_since,
                last_low,
                low_samples,
            }) = self.records.get(&container.key).cloned()
            {
                let mut cur_tier = tier.clamp(1, 3);
                let mut cur_applied = applied_high_bytes;
                let mut cur_esc_since = escalation_since;
                let mut cur_esc_samples = escalation_samples;
                let mut cur_last_high = last_high;
                let mut cur_low_since = low_since;
                let mut cur_last_low = last_low;
                let mut cur_low_samples = low_samples;

                let pressure_high = host_some.map_or(false, |h| h >= self.config.host_psi_threshold_percent)
                    && cgroup_some.map_or(false, |c| c >= self.config.container_psi_threshold_percent);
                let tier_usage_threshold =
                    (self.config.start_usage_percent - (cur_tier - 1) as f64 * 10.0).max(60.0);
                let is_memory_high_tier = used_percent.map_or(false, |u| u >= tier_usage_threshold)
                    || (container.current_bytes as f64 >= cur_applied as f64 * 0.95);

                if pressure_high && is_memory_high_tier && cur_tier < 3 {
                    if cur_last_high == 0
                        || timestamp <= cur_last_high
                        || timestamp - cur_last_high > max_gap
                    {
                        cur_esc_since = timestamp;
                        cur_esc_samples = 1;
                    } else {
                        cur_esc_samples += 1;
                    }
                    cur_last_high = timestamp;
                    if timestamp.saturating_sub(cur_esc_since) >= self.config.escalation_duration_seconds
                        && cur_esc_samples >= esc_samples_req
                    {
                        if let Some(max_b) = container.max_bytes {
                            let target = memory_tier_target_bytes(max_b, cur_tier + 1);
                            if target < cur_applied {
                                cur_tier += 1;
                                cur_applied = target;
                                cur_esc_since = 0;
                                cur_esc_samples = 0;
                                cur_last_high = 0;
                                actions.push(MemoryGuardAction::EscalateMemoryHigh {
                                    key: container.key.clone(),
                                    tier: cur_tier,
                                    target_bytes: cur_applied,
                                });
                            }
                        }
                    }
                } else if !pressure_high || !is_memory_high_tier {
                    cur_esc_since = 0;
                    cur_esc_samples = 0;
                    cur_last_high = 0;
                }

                let low = host_some.map_or(false, |h| h < self.config.recovery_psi_threshold_percent)
                    && cgroup_some
                        .map_or(false, |c| c < self.config.recovery_psi_threshold_percent);
                if low {
                    if cur_low_since == 0 || timestamp.saturating_sub(cur_last_low) > max_gap {
                        cur_low_since = timestamp;
                        cur_low_samples = 1;
                    } else {
                        cur_low_samples += 1;
                    }
                    cur_last_low = timestamp;
                } else {
                    cur_low_since = 0;
                    cur_last_low = 0;
                    cur_low_samples = 0;
                }

                if cur_low_samples >= rec_samples_req
                    && timestamp.saturating_sub(cur_low_since) >= self.config.recovery_duration_seconds
                    && used_percent.map_or(true, |u| u < 95.0)
                {
                    let cooldown_until = timestamp + self.config.cooldown_seconds;
                    self.records.insert(
                        container.key.clone(),
                        MemoryRecordState::Cooldown { cooldown_until },
                    );
                    reserved.remove(&container.key);
                    actions.push(MemoryGuardAction::RestoreMemoryHigh {
                        key: container.key.clone(),
                        original_high_bytes,
                        cooldown_until,
                    });
                    decisions.push(MemoryContainerDecision {
                        key: container.key.clone(),
                        stage: GuardStage::Restored,
                        tier: 0,
                        applied_high_bytes: None,
                        used_percent,
                        high_samples: 0,
                        required_samples: min_samples,
                        low_samples: cur_low_samples,
                        recovery_samples_required: rec_samples_req,
                        cooldown_remaining_seconds: self.config.cooldown_seconds,
                    });
                    continue;
                }

                self.records.insert(
                    container.key.clone(),
                    MemoryRecordState::Active {
                        tier: cur_tier,
                        original_high_bytes,
                        applied_high_bytes: cur_applied,
                        escalation_since: cur_esc_since,
                        escalation_samples: cur_esc_samples,
                        last_high: cur_last_high,
                        low_since: cur_low_since,
                        last_low: cur_last_low,
                        low_samples: cur_low_samples,
                    },
                );
                decisions.push(MemoryContainerDecision {
                    key: container.key.clone(),
                    stage: GuardStage::Active,
                    tier: cur_tier,
                    applied_high_bytes: Some(cur_applied),
                    used_percent,
                    high_samples: 0,
                    required_samples: min_samples,
                    low_samples: cur_low_samples,
                    recovery_samples_required: rec_samples_req,
                    cooldown_remaining_seconds: 0,
                });
                continue;
            }

            if !allow_new_limits {
                decisions.push(MemoryContainerDecision {
                    key: container.key.clone(),
                    stage: GuardStage::Normal,
                    tier: 0,
                    applied_high_bytes: None,
                    used_percent,
                    high_samples: 0,
                    required_samples: min_samples,
                    low_samples: 0,
                    recovery_samples_required: rec_samples_req,
                    cooldown_remaining_seconds: 0,
                });
                continue;
            }

            let Some(max_bytes) = container.max_bytes.filter(|&m| m >= MIN_MEMORY_MAX_BYTES) else {
                self.records.remove(&container.key);
                decisions.push(MemoryContainerDecision {
                    key: container.key.clone(),
                    stage: GuardStage::Unsupported,
                    tier: 0,
                    applied_high_bytes: None,
                    used_percent,
                    high_samples: 0,
                    required_samples: min_samples,
                    low_samples: 0,
                    recovery_samples_required: rec_samples_req,
                    cooldown_remaining_seconds: 0,
                });
                continue;
            };

            let tier1_target = memory_tier_target_bytes(max_bytes, 1);
            if let Some(orig) = container.original_high_bytes {
                if orig <= tier1_target {
                    self.records.remove(&container.key);
                    decisions.push(MemoryContainerDecision {
                        key: container.key.clone(),
                        stage: GuardStage::Normal,
                        tier: 0,
                        applied_high_bytes: None,
                        used_percent,
                        high_samples: 0,
                        required_samples: min_samples,
                        low_samples: 0,
                        recovery_samples_required: rec_samples_req,
                        cooldown_remaining_seconds: 0,
                    });
                    continue;
                }
            }

            let (Some(h_psi), Some(c_psi)) = (host_some, cgroup_some) else {
                self.records.remove(&container.key);
                decisions.push(MemoryContainerDecision {
                    key: container.key.clone(),
                    stage: GuardStage::SamplingUnavailable,
                    tier: 0,
                    applied_high_bytes: None,
                    used_percent,
                    high_samples: 0,
                    required_samples: min_samples,
                    low_samples: 0,
                    recovery_samples_required: rec_samples_req,
                    cooldown_remaining_seconds: 0,
                });
                continue;
            };

            let used = used_percent.unwrap_or(-1.0);
            let qualifies = used >= self.config.start_usage_percent
                && h_psi >= self.config.host_psi_threshold_percent
                && c_psi >= self.config.container_psi_threshold_percent;

            if !qualifies {
                self.records.remove(&container.key);
                let stage = if used >= self.config.start_usage_percent {
                    GuardStage::WaitingForPressure
                } else {
                    GuardStage::Normal
                };
                decisions.push(MemoryContainerDecision {
                    key: container.key.clone(),
                    stage,
                    tier: 0,
                    applied_high_bytes: None,
                    used_percent,
                    high_samples: 0,
                    required_samples: min_samples,
                    low_samples: 0,
                    recovery_samples_required: rec_samples_req,
                    cooldown_remaining_seconds: 0,
                });
                continue;
            }

            let (prev_samples, prev_since, prev_last) = match self.records.get(&container.key) {
                Some(MemoryRecordState::Candidate {
                    high_samples,
                    high_since,
                    last_high,
                }) => (*high_samples, *high_since, *last_high),
                _ => (0, 0, 0),
            };
            let (high_samples, high_since) = if prev_last == 0
                || timestamp <= prev_last
                || timestamp - prev_last > max_gap
            {
                (1, timestamp)
            } else {
                (prev_samples + 1, prev_since)
            };

            if high_samples >= min_samples
                && timestamp.saturating_sub(high_since) >= self.config.required_duration_seconds
            {
                if reserved.iter().any(|k| k != &container.key) {
                    self.records.insert(
                        container.key.clone(),
                        MemoryRecordState::Candidate {
                            high_samples,
                            high_since,
                            last_high: timestamp,
                        },
                    );
                    decisions.push(MemoryContainerDecision {
                        key: container.key.clone(),
                        stage: GuardStage::WaitingForOtherLimit,
                        tier: 0,
                        applied_high_bytes: None,
                        used_percent,
                        high_samples,
                        required_samples: min_samples,
                        low_samples: 0,
                        recovery_samples_required: rec_samples_req,
                        cooldown_remaining_seconds: 0,
                    });
                    continue;
                }

                self.records.insert(
                    container.key.clone(),
                    MemoryRecordState::Active {
                        tier: 1,
                        original_high_bytes: container.original_high_bytes,
                        applied_high_bytes: tier1_target,
                        escalation_since: 0,
                        escalation_samples: 0,
                        last_high: 0,
                        low_since: 0,
                        last_low: 0,
                        low_samples: 0,
                    },
                );
                reserved.insert(container.key.clone());
                actions.push(MemoryGuardAction::ApplyMemoryHigh {
                    key: container.key.clone(),
                    tier: 1,
                    target_bytes: tier1_target,
                });
                decisions.push(MemoryContainerDecision {
                    key: container.key.clone(),
                    stage: GuardStage::Active,
                    tier: 1,
                    applied_high_bytes: Some(tier1_target),
                    used_percent,
                    high_samples,
                    required_samples: min_samples,
                    low_samples: 0,
                    recovery_samples_required: rec_samples_req,
                    cooldown_remaining_seconds: 0,
                });
            } else {
                self.records.insert(
                    container.key.clone(),
                    MemoryRecordState::Candidate {
                        high_samples,
                        high_since,
                        last_high: timestamp,
                    },
                );
                decisions.push(MemoryContainerDecision {
                    key: container.key.clone(),
                    stage: GuardStage::Watching,
                    tier: 0,
                    applied_high_bytes: None,
                    used_percent,
                    high_samples,
                    required_samples: min_samples,
                    low_samples: 0,
                    recovery_samples_required: rec_samples_req,
                    cooldown_remaining_seconds: 0,
                });
            }
        }

        self.records.retain(|k, v| {
            seen.contains(k) || !matches!(v, MemoryRecordState::Candidate { .. })
        });

        (decisions, actions)
    }
}

// ============================================================================
// 3. IoGuardTracker
// ============================================================================

/// Configuration matching `client/io_guard.py` defaults and clamping bounds.
#[derive(Debug, Clone, PartialEq)]
pub struct IoGuardConfig {
    pub interval_seconds: f64,
    pub device_busy_threshold_percent: f64,
    pub recovery_busy_threshold_percent: f64,
    pub host_psi_threshold_percent: f64,
    pub recovery_host_psi_threshold_percent: f64,
    pub share_threshold: f64,
    pub min_bps: f64,
    pub min_iops: f64,
    pub required_duration_seconds: u64,
    pub recovery_duration_seconds: u64,
    pub escalation_duration_seconds: u64,
    pub cooldown_seconds: u64,
}

impl Default for IoGuardConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 300.0,
            device_busy_threshold_percent: 80.0,
            recovery_busy_threshold_percent: 60.0,
            host_psi_threshold_percent: 5.0,
            recovery_host_psi_threshold_percent: 2.0,
            share_threshold: 0.5,
            min_bps: 10.0 * 1024.0 * 1024.0,
            min_iops: 250.0,
            required_duration_seconds: 300,
            recovery_duration_seconds: 600,
            escalation_duration_seconds: 300,
            cooldown_seconds: 900,
        }
    }
}

impl IoGuardConfig {
    /// Return a clamped copy enforcing all `io_guard.py` bounds.
    pub fn normalized(&self) -> Self {
        let interval = finite_or(self.interval_seconds, 300.0).max(60.0);
        let busy = finite_or(self.device_busy_threshold_percent, 80.0).clamp(50.0, 99.0);
        let rec_busy = finite_or(self.recovery_busy_threshold_percent, 60.0).clamp(20.0, 90.0);
        let host_psi = finite_or(self.host_psi_threshold_percent, 5.0).clamp(0.1, 50.0);
        let rec_psi = finite_or(self.recovery_host_psi_threshold_percent, 2.0).clamp(0.0, host_psi);
        let share = finite_or(self.share_threshold, 0.5).clamp(0.2, 0.95);
        let min_bps = finite_or(self.min_bps, 10.0 * 1024.0 * 1024.0).max(1024.0);
        let min_iops = finite_or(self.min_iops, 250.0).max(10.0);
        let req_dur = self.required_duration_seconds.max(300);
        let rec_dur = self.recovery_duration_seconds.max(600);
        let esc_dur = self.escalation_duration_seconds.max(300);
        let cooldown = self.cooldown_seconds.max(300);
        Self {
            interval_seconds: interval,
            device_busy_threshold_percent: busy,
            recovery_busy_threshold_percent: rec_busy,
            host_psi_threshold_percent: host_psi,
            recovery_host_psi_threshold_percent: rec_psi,
            share_threshold: share,
            min_bps,
            min_iops,
            required_duration_seconds: req_dur,
            recovery_duration_seconds: rec_dur,
            escalation_duration_seconds: esc_dur,
            cooldown_seconds: cooldown,
        }
    }

    fn max_gap(&self) -> u64 {
        ((self.interval_seconds * 2.5) as u64).max(180)
    }

    fn min_samples(&self) -> usize {
        ceil_div_plus_one(self.required_duration_seconds, self.interval_seconds).max(2)
    }

    fn escalation_samples(&self) -> usize {
        ceil_div_plus_one(self.escalation_duration_seconds, self.interval_seconds).max(2)
    }

    fn recovery_samples(&self) -> usize {
        ceil_div_plus_one(self.recovery_duration_seconds, self.interval_seconds).max(3)
    }
}

/// Host block device sample derived from `/proc/diskstats`.
#[derive(Debug, Clone, PartialEq)]
pub struct HostDeviceSample {
    pub device: String,
    pub busy_percent: f64,
    pub total_bps: f64,
    pub total_iops: f64,
}

/// Measured cgroup `io.stat` throughput/IOPS rates for a single device.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct IoRates {
    pub rbps: f64,
    pub wbps: f64,
    pub riops: f64,
    pub wiops: f64,
}

impl IoRates {
    pub fn total_bps(&self) -> f64 {
        finite_or(self.rbps, 0.0).max(0.0) + finite_or(self.wbps, 0.0).max(0.0)
    }

    pub fn total_iops(&self) -> f64 {
        finite_or(self.riops, 0.0).max(0.0) + finite_or(self.wiops, 0.0).max(0.0)
    }

    fn max_merge(&self, other: &Self) -> Self {
        Self {
            rbps: finite_or(self.rbps, 0.0).max(finite_or(other.rbps, 0.0)).max(0.0),
            wbps: finite_or(self.wbps, 0.0).max(finite_or(other.wbps, 0.0)).max(0.0),
            riops: finite_or(self.riops, 0.0).max(finite_or(other.riops, 0.0)).max(0.0),
            wiops: finite_or(self.wiops, 0.0).max(finite_or(other.wiops, 0.0)).max(0.0),
        }
    }
}

/// Cgroup v2 `io.max` limit values (`None` represents `"max"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoMaxLimits {
    pub rbps: Option<u64>,
    pub wbps: Option<u64>,
    pub riops: Option<u64>,
    pub wiops: Option<u64>,
}

impl IoMaxLimits {
    /// Compute `io.max` target limits from baseline rates and tier ratio (0.50, 0.25, 0.10).
    pub fn target_from_baseline(baseline: &IoRates, original: &Self, ratio: f64) -> Self {
        let calc = |rate: f64, floor_rate: f64, orig: Option<u64>| -> Option<u64> {
            let r = finite_or(rate, 0.0).max(0.0);
            if r < floor_rate {
                return orig;
            }
            let val = ((r * ratio).floor() as u64).max(1);
            match orig {
                Some(old) => Some(val.min(old)),
                None => Some(val),
            }
        };
        const BPS_FLOOR: f64 = 1024.0 * 1024.0;
        const IOPS_FLOOR: f64 = 25.0;
        Self {
            rbps: calc(baseline.rbps, BPS_FLOOR, original.rbps),
            wbps: calc(baseline.wbps, BPS_FLOOR, original.wbps),
            riops: calc(baseline.riops, IOPS_FLOOR, original.riops),
            wiops: calc(baseline.wiops, IOPS_FLOOR, original.wiops),
        }
    }

    /// Return true if `self` is strictly tighter than `current` on at least one axis.
    pub fn is_strictly_tighter_than(&self, current: &Self) -> bool {
        let tighter_axis = |new: Option<u64>, old: Option<u64>| -> bool {
            match (new, old) {
                (Some(n), Some(o)) => n < o,
                (Some(_), None) => true,
                _ => false,
            }
        };
        tighter_axis(self.rbps, current.rbps)
            || tighter_axis(self.wbps, current.wbps)
            || tighter_axis(self.riops, current.riops)
            || tighter_axis(self.wiops, current.wiops)
    }
}

/// Per-container I/O observation input.
#[derive(Debug, Clone, PartialEq)]
pub struct IoContainerSample {
    pub key: String,
    /// Per-device measured rates from cgroup `io.stat`.
    pub device_rates: Vec<(String, IoRates)>,
    /// Current `io.max` per device (if omitted, treated as unlimited `"max"`).
    pub original_limits: HashMap<String, IoMaxLimits>,
}

#[derive(Debug, Clone, PartialEq)]
enum IoRecordState {
    Candidate {
        device: String,
        high_samples: usize,
        high_since: u64,
        last_high: u64,
        baseline_rates: IoRates,
    },
    Active {
        device: String,
        tier: u8,
        original: IoMaxLimits,
        applied: IoMaxLimits,
        baseline_rates: IoRates,
        last_step_at: u64,
        escalation_since: u64,
        escalation_samples: usize,
        last_high: u64,
        low_since: u64,
        last_low: u64,
        low_samples: usize,
    },
    Cooldown {
        cooldown_until: u64,
    },
}

/// Action emitted for a container during an I/O guard observation tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoGuardAction {
    ApplyIoMax {
        key: String,
        device: String,
        tier: u8,
        target: IoMaxLimits,
    },
    EscalateIoMax {
        key: String,
        device: String,
        tier: u8,
        target: IoMaxLimits,
    },
    RestoreIoMax {
        key: String,
        device: String,
        original: IoMaxLimits,
        cooldown_until: u64,
    },
}

/// Per-container status snapshot returned by `IoGuardTracker::observe`.
#[derive(Debug, Clone, PartialEq)]
pub struct IoContainerDecision {
    pub key: String,
    pub stage: GuardStage,
    pub device: Option<String>,
    pub tier: u8,
    pub applied: Option<IoMaxLimits>,
    pub high_samples: usize,
    pub required_samples: usize,
    pub low_samples: usize,
    pub recovery_samples_required: usize,
    pub cooldown_remaining_seconds: u64,
    pub pressure_basis: &'static str,
}

/// Stateful I/O guard tracker implementing `diskstats` busy % / host I/O PSI,
/// cgroup `io.stat` attribution, `io.max` tiered escalation, and recovery/cooldown.
#[derive(Debug, Clone)]
pub struct IoGuardTracker {
    config: IoGuardConfig,
    records: HashMap<String, IoRecordState>,
}

impl IoGuardTracker {
    pub fn new(config: IoGuardConfig) -> Self {
        Self {
            config: config.normalized(),
            records: HashMap::new(),
        }
    }

    pub fn config(&self) -> &IoGuardConfig {
        &self.config
    }

    fn host_io_pressure(&self, device_busy: f64, host_io_psi: Option<f64>) -> (bool, &'static str) {
        match sanitize_non_neg(host_io_psi) {
            None => (
                device_busy >= self.config.device_busy_threshold_percent,
                "device_busy_fallback_psi_unavailable",
            ),
            Some(psi) => (psi >= self.config.host_psi_threshold_percent, "host_io_psi"),
        }
    }

    /// Observe one tick across containers with host `diskstats` devices and optional host I/O PSI.
    pub fn observe(
        &mut self,
        timestamp: u64,
        host_ready: bool,
        host_devices: &[HostDeviceSample],
        host_io_psi: Option<f64>,
        containers: &[IoContainerSample],
        allow_new_limits: bool,
    ) -> (Vec<IoContainerDecision>, Vec<IoGuardAction>) {
        let max_gap = self.config.max_gap();
        let min_samples = self.config.min_samples();
        let esc_samples_req = self.config.escalation_samples();
        let rec_samples_req = self.config.recovery_samples();
        let host_psi = sanitize_non_neg(host_io_psi);
        let dev_map: HashMap<&str, &HostDeviceSample> = host_devices
            .iter()
            .map(|d| (d.device.as_str(), d))
            .collect();

        let mut seen: HashSet<String> = HashSet::with_capacity(containers.len());
        let mut reserved: HashSet<String> = self
            .records
            .iter()
            .filter_map(|(k, v)| match v {
                IoRecordState::Active { .. } => Some(k.clone()),
                _ => None,
            })
            .collect();

        let mut decisions = Vec::with_capacity(containers.len());
        let mut actions = Vec::new();

        for container in containers {
            seen.insert(container.key.clone());

            // 1. Cooldown
            if let Some(IoRecordState::Cooldown { cooldown_until }) =
                self.records.get(&container.key)
            {
                let remaining = cooldown_until.saturating_sub(timestamp);
                if remaining > 0 {
                    decisions.push(IoContainerDecision {
                        key: container.key.clone(),
                        stage: GuardStage::Cooldown,
                        device: None,
                        tier: 0,
                        applied: None,
                        high_samples: 0,
                        required_samples: min_samples,
                        low_samples: 0,
                        recovery_samples_required: rec_samples_req,
                        cooldown_remaining_seconds: remaining,
                        pressure_basis: "cooldown",
                    });
                    continue;
                }
                self.records.remove(&container.key);
            }

            // 2. Active state
            if let Some(IoRecordState::Active {
                device,
                tier,
                original,
                applied,
                baseline_rates,
                last_step_at,
                escalation_since,
                escalation_samples,
                last_high,
                low_since,
                last_low,
                low_samples,
            }) = self.records.get(&container.key).cloned()
            {
                let mut cur_tier = tier.clamp(1, 3);
                let mut cur_applied = applied;
                let mut cur_last_step = last_step_at;
                let mut cur_esc_since = escalation_since;
                let mut cur_esc_samples = escalation_samples;
                let mut cur_last_high = last_high;
                let mut cur_low_since = low_since;
                let mut cur_last_low = last_low;
                let mut cur_low_samples = low_samples;

                let dev_sample = dev_map.get(device.as_str()).copied();
                let busy = dev_sample.map_or(-1.0, |d| finite_or(d.busy_percent, -1.0));
                let (host_pressure_high, basis) = self.host_io_pressure(busy, host_psi);
                let observed = container
                    .device_rates
                    .iter()
                    .find(|(d, _)| d == &device)
                    .map(|(_, r)| *r)
                    .unwrap_or_default();

                let check_lower = |obs: f64, app: Option<u64>| -> bool {
                    match app {
                        None => true,
                        Some(limit) => obs <= (limit as f64 * 0.5).max(1.0),
                    }
                };
                let lower = check_lower(observed.rbps, cur_applied.rbps)
                    && check_lower(observed.wbps, cur_applied.wbps)
                    && check_lower(observed.riops, cur_applied.riops)
                    && check_lower(observed.wiops, cur_applied.wiops);
                let low_pressure = match host_psi {
                    Some(psi) => psi < self.config.recovery_host_psi_threshold_percent,
                    None => busy >= 0.0 && busy < self.config.recovery_busy_threshold_percent,
                };

                if lower && low_pressure {
                    if cur_low_since == 0
                        || timestamp <= cur_low_since
                        || timestamp.saturating_sub(cur_last_low) > max_gap
                    {
                        cur_low_since = timestamp;
                        cur_low_samples = 1;
                    } else {
                        cur_low_samples += 1;
                    }
                    cur_last_low = timestamp;
                } else {
                    cur_low_since = 0;
                    cur_last_low = 0;
                    cur_low_samples = 0;
                }

                if cur_low_samples >= rec_samples_req
                    && timestamp.saturating_sub(cur_low_since) >= self.config.recovery_duration_seconds
                {
                    let cooldown_until = timestamp + self.config.cooldown_seconds;
                    self.records.insert(
                        container.key.clone(),
                        IoRecordState::Cooldown { cooldown_until },
                    );
                    reserved.remove(&container.key);
                    actions.push(IoGuardAction::RestoreIoMax {
                        key: container.key.clone(),
                        device: device.clone(),
                        original,
                        cooldown_until,
                    });
                    decisions.push(IoContainerDecision {
                        key: container.key.clone(),
                        stage: GuardStage::Restored,
                        device: Some(device),
                        tier: 0,
                        applied: None,
                        high_samples: 0,
                        required_samples: min_samples,
                        low_samples: cur_low_samples,
                        recovery_samples_required: rec_samples_req,
                        cooldown_remaining_seconds: self.config.cooldown_seconds,
                        pressure_basis: basis,
                    });
                    continue;
                }

                // Escalation check
                let host_bps = dev_sample.map_or(0.0, |d| finite_or(d.total_bps, 0.0));
                let host_iops = dev_sample.map_or(0.0, |d| finite_or(d.total_iops, 0.0));
                let obs_bps = observed.total_bps();
                let obs_iops = observed.total_iops();
                let share = (if host_bps > 0.0 { obs_bps / host_bps } else { 0.0 })
                    .max(if host_iops > 0.0 { obs_iops / host_iops } else { 0.0 });
                let high = host_pressure_high
                    && share >= self.config.share_threshold
                    && (obs_bps >= self.config.min_bps || obs_iops >= self.config.min_iops);

                if high && cur_tier < 3 {
                    if cur_last_high == 0
                        || timestamp <= cur_last_high
                        || timestamp.saturating_sub(cur_last_high) > max_gap
                    {
                        cur_esc_since = timestamp;
                        cur_esc_samples = 1;
                    } else {
                        cur_esc_samples += 1;
                    }
                    cur_last_high = timestamp;
                    if timestamp.saturating_sub(cur_esc_since) >= self.config.escalation_duration_seconds
                        && cur_esc_samples >= esc_samples_req
                        && timestamp.saturating_sub(cur_last_step) >= self.config.escalation_duration_seconds
                    {
                        let ratio = if cur_tier == 1 { 0.25 } else { 0.10 };
                        let target = IoMaxLimits::target_from_baseline(&baseline_rates, &original, ratio);
                        if target.is_strictly_tighter_than(&cur_applied) {
                            cur_tier += 1;
                            cur_applied = target;
                            cur_last_step = timestamp;
                            cur_esc_since = 0;
                            cur_esc_samples = 0;
                            cur_last_high = 0;
                            actions.push(IoGuardAction::EscalateIoMax {
                                key: container.key.clone(),
                                device: device.clone(),
                                tier: cur_tier,
                                target,
                            });
                        }
                    }
                } else {
                    cur_esc_since = 0;
                    cur_esc_samples = 0;
                    cur_last_high = 0;
                }

                self.records.insert(
                    container.key.clone(),
                    IoRecordState::Active {
                        device: device.clone(),
                        tier: cur_tier,
                        original,
                        applied: cur_applied,
                        baseline_rates,
                        last_step_at: cur_last_step,
                        escalation_since: cur_esc_since,
                        escalation_samples: cur_esc_samples,
                        last_high: cur_last_high,
                        low_since: cur_low_since,
                        last_low: cur_last_low,
                        low_samples: cur_low_samples,
                    },
                );
                decisions.push(IoContainerDecision {
                    key: container.key.clone(),
                    stage: GuardStage::Active,
                    device: Some(device),
                    tier: cur_tier,
                    applied: Some(cur_applied),
                    high_samples: 0,
                    required_samples: min_samples,
                    low_samples: cur_low_samples,
                    recovery_samples_required: rec_samples_req,
                    cooldown_remaining_seconds: 0,
                    pressure_basis: basis,
                });
                continue;
            }

            if !allow_new_limits {
                self.records.remove(&container.key);
                decisions.push(IoContainerDecision {
                    key: container.key.clone(),
                    stage: GuardStage::Normal,
                    device: None,
                    tier: 0,
                    applied: None,
                    high_samples: 0,
                    required_samples: min_samples,
                    low_samples: 0,
                    recovery_samples_required: rec_samples_req,
                    cooldown_remaining_seconds: 0,
                    pressure_basis: "disabled",
                });
                continue;
            }

            if !host_ready {
                decisions.push(IoContainerDecision {
                    key: container.key.clone(),
                    stage: GuardStage::SamplingUnavailable,
                    device: None,
                    tier: 0,
                    applied: None,
                    high_samples: 0,
                    required_samples: min_samples,
                    low_samples: 0,
                    recovery_samples_required: rec_samples_req,
                    cooldown_remaining_seconds: 0,
                    pressure_basis: "warming",
                });
                continue;
            }

            // 3. Candidate attribution across devices
            let mut pressured: Vec<(f64, &str, IoRates, &'static str)> = Vec::new();
            for (dev, rates) in &container.device_rates {
                let Some(dev_stats) = dev_map.get(dev.as_str()).copied() else {
                    continue;
                };
                let busy = finite_or(dev_stats.busy_percent, -1.0);
                let (host_high, basis) = self.host_io_pressure(busy, host_psi);
                if !host_high {
                    continue;
                }
                let host_bps = finite_or(dev_stats.total_bps, 0.0);
                let host_iops = finite_or(dev_stats.total_iops, 0.0);
                let bytes_rate = rates.total_bps();
                let iops_rate = rates.total_iops();
                let share = (if host_bps > 0.0 { bytes_rate / host_bps } else { 0.0 })
                    .max(if host_iops > 0.0 { iops_rate / host_iops } else { 0.0 });
                if share >= self.config.share_threshold
                    && (bytes_rate >= self.config.min_bps || iops_rate >= self.config.min_iops)
                {
                    pressured.push((share, dev.as_str(), *rates, basis));
                }
            }

            if let Some((_, device, observed_rates, basis)) = pressured
                .into_iter()
                .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
            {
                let (prev_samples, prev_since, prev_last, prev_baseline) = match self.records.get(&container.key) {
                    Some(IoRecordState::Candidate {
                        device: prev_dev,
                        high_samples,
                        high_since,
                        last_high,
                        baseline_rates,
                    }) if prev_dev == device => (*high_samples, *high_since, *last_high, *baseline_rates),
                    _ => (0, 0, 0, IoRates::default()),
                };

                let (high_samples, high_since) = if prev_last == 0
                    || timestamp <= prev_last
                    || timestamp - prev_last > max_gap
                {
                    (1, timestamp)
                } else {
                    (prev_samples + 1, prev_since)
                };
                let baseline_rates = prev_baseline.max_merge(&observed_rates);

                if high_samples >= min_samples
                    && timestamp.saturating_sub(high_since) >= self.config.required_duration_seconds
                {
                    if reserved.iter().any(|k| k != &container.key) {
                        self.records.insert(
                            container.key.clone(),
                            IoRecordState::Candidate {
                                device: device.to_string(),
                                high_samples,
                                high_since,
                                last_high: timestamp,
                                baseline_rates,
                            },
                        );
                        decisions.push(IoContainerDecision {
                            key: container.key.clone(),
                            stage: GuardStage::WaitingForOtherLimit,
                            device: Some(device.to_string()),
                            tier: 0,
                            applied: None,
                            high_samples,
                            required_samples: min_samples,
                            low_samples: 0,
                            recovery_samples_required: rec_samples_req,
                            cooldown_remaining_seconds: 0,
                            pressure_basis: basis,
                        });
                        continue;
                    }

                    let original = container
                        .original_limits
                        .get(device)
                        .copied()
                        .unwrap_or_default();
                    let target = IoMaxLimits::target_from_baseline(&baseline_rates, &original, 0.50);
                    if target.is_strictly_tighter_than(&original) {
                        self.records.insert(
                            container.key.clone(),
                            IoRecordState::Active {
                                device: device.to_string(),
                                tier: 1,
                                original,
                                applied: target,
                                baseline_rates,
                                last_step_at: timestamp,
                                escalation_since: 0,
                                escalation_samples: 0,
                                last_high: 0,
                                low_since: 0,
                                last_low: 0,
                                low_samples: 0,
                            },
                        );
                        reserved.insert(container.key.clone());
                        actions.push(IoGuardAction::ApplyIoMax {
                            key: container.key.clone(),
                            device: device.to_string(),
                            tier: 1,
                            target,
                        });
                        decisions.push(IoContainerDecision {
                            key: container.key.clone(),
                            stage: GuardStage::Active,
                            device: Some(device.to_string()),
                            tier: 1,
                            applied: Some(target),
                            high_samples,
                            required_samples: min_samples,
                            low_samples: 0,
                            recovery_samples_required: rec_samples_req,
                            cooldown_remaining_seconds: 0,
                            pressure_basis: basis,
                        });
                        continue;
                    }
                }

                self.records.insert(
                    container.key.clone(),
                    IoRecordState::Candidate {
                        device: device.to_string(),
                        high_samples,
                        high_since,
                        last_high: timestamp,
                        baseline_rates,
                    },
                );
                decisions.push(IoContainerDecision {
                    key: container.key.clone(),
                    stage: GuardStage::Watching,
                    device: Some(device.to_string()),
                    tier: 0,
                    applied: None,
                    high_samples,
                    required_samples: min_samples,
                    low_samples: 0,
                    recovery_samples_required: rec_samples_req,
                    cooldown_remaining_seconds: 0,
                    pressure_basis: basis,
                });
            } else {
                self.records.remove(&container.key);
                let waiting_for_psi = host_psi
                    .map_or(false, |p| p < self.config.host_psi_threshold_percent)
                    && container.device_rates.iter().any(|(dev, _)| {
                        dev_map
                            .get(dev.as_str())
                            .map_or(false, |d| d.busy_percent >= self.config.device_busy_threshold_percent)
                    });
                let stage = if waiting_for_psi {
                    GuardStage::WaitingForHostPsi
                } else {
                    GuardStage::Normal
                };
                decisions.push(IoContainerDecision {
                    key: container.key.clone(),
                    stage,
                    device: container.device_rates.first().map(|(d, _)| d.clone()),
                    tier: 0,
                    applied: None,
                    high_samples: 0,
                    required_samples: min_samples,
                    low_samples: 0,
                    recovery_samples_required: rec_samples_req,
                    cooldown_remaining_seconds: 0,
                    pressure_basis: if host_psi.is_some() {
                        "host_io_psi"
                    } else {
                        "device_busy_fallback_psi_unavailable"
                    },
                });
            }
        }

        self.records.retain(|k, v| {
            seen.contains(k) || !matches!(v, IoRecordState::Candidate { .. })
        });

        (decisions, actions)
    }
}

#[cfg(test)]
mod tests;
