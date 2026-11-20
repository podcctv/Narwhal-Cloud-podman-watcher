use std::fmt;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

pub const DEFAULT_STATE_PATH: &str = "/var/lib/narwhal-monitor/manual-bandwidth-limits.json";
pub const STATE_PATH_ENV: &str = "NARWHAL_MANUAL_BANDWIDTH_STATE";
pub const PREF_DOWNLOAD: u16 = 49150;
pub const PREF_UPLOAD: u16 = 49151;
pub const PREF_RANGE_START: u16 = 49150;
pub const PREF_RANGE_END: u16 = 65535;
pub const MAX_POLICIES: usize = 256;
pub const MAX_RATE_MBPS: u32 = 100_000;
pub const AUTO_THRESHOLD_PERCENT: u32 = 80;
pub const AUTO_TRIGGER_SECONDS: u64 = 300;
pub const AUTO_TIER_PERCENTAGES: [u32; 3] = [50, 25, 5];
pub const AUTO_MINIMUM_MBPS: u32 = 1;
pub const AUTO_RECOVERY_PERCENT: u32 = 50;
pub const AUTO_RECOVERY_SECONDS: u64 = 600;
pub(crate) const DEFAULT_CMD_TIMEOUT: Duration = Duration::from_secs(8);
pub(crate) const DEFAULT_OUTPUT_LIMIT: usize = 2000;
pub(crate) const MAX_INVENTORY_OUTPUT: usize = 8 * 1024 * 1024;
pub(crate) const MAX_INVENTORY_ITEMS: usize = 4096;
pub(crate) const PRUNE_DEPARTED_AFTER_SECS: u64 = 86_400;

pub(crate) static TEMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// 1. Errors and core enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BandwidthError {
    Policy(String),
    Mutation {
        message: String,
        rollback_state: String,
    },
}

pub type BandwidthPolicyError = BandwidthError;

impl BandwidthError {
    pub fn policy(msg: impl Into<String>) -> Self {
        Self::Policy(msg.into())
    }

    pub fn mutation(msg: impl Into<String>, rollback_state: impl Into<String>) -> Self {
        Self::Mutation {
            message: msg.into(),
            rollback_state: rollback_state.into(),
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Policy(m) => m,
            Self::Mutation { message, .. } => message,
        }
    }

    pub fn rollback_state(&self) -> Option<&str> {
        match self {
            Self::Policy(_) => None,
            Self::Mutation { rollback_state, .. } => Some(rollback_state.as_str()),
        }
    }
}

impl fmt::Display for BandwidthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for BandwidthError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    Host,
    Container,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Container => "container",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeKind {
    Incus,
    Podman,
    Runman,
}

impl RuntimeKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "incus" => Some(Self::Incus),
            "podman" => Some(Self::Podman),
            "runman" => Some(Self::Runman),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Incus => "incus",
            Self::Podman => "podman",
            Self::Runman => "runman",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    Download,
    Upload,
}

impl Direction {
    pub const BOTH: [Direction; 2] = [Direction::Download, Direction::Upload];

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "download" => Some(Self::Download),
            "upload" => Some(Self::Upload),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Upload => "upload",
        }
    }

    pub fn tc_direction(self) -> &'static str {
        match self {
            Self::Download => "ingress",
            Self::Upload => "egress",
        }
    }

    pub fn default_pref(self) -> u16 {
        match self {
            Self::Download => PREF_DOWNLOAD,
            Self::Upload => PREF_UPLOAD,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetnsError {
    NotFound,
    Unavailable(String),
}

impl fmt::Display for NetnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "network namespace not found"),
            Self::Unavailable(msg) => write!(f, "{msg}"),
        }
    }
}
