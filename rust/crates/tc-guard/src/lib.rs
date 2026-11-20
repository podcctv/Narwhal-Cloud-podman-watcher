#![forbid(unsafe_code)]

//! Pure-Rust migration of `client/manual_bandwidth.py`: safe, opt-in `tc`
//! `clsact` bandwidth policing for a host interface or isolated container
//! network namespaces (`incus`, `podman`, `runman`), including deterministic
//! filter handles, kernel readback verification, auto-throttle tier state
//! machine, and atomic JSON state persistence.

mod auto_throttle;
mod filter;
mod json;
mod policy;
mod reconcile;
mod runner;
mod state;
mod tc_ops;
mod types;
mod verify;

pub use auto_throttle::*;
pub use filter::*;
pub use json::*;
pub use policy::*;
pub use reconcile::*;
pub use runner::*;
pub use state::*;
pub use tc_ops::*;
pub use types::*;
pub use verify::*;

#[allow(unused_imports)]
pub(crate) use auto_throttle::{compute_automatic_limits, host_link_snapshot, HostLinkInfo};
#[allow(unused_imports)]
pub(crate) use filter::contains_word;
#[allow(unused_imports)]
pub(crate) use json::{format_f64_json, round3, truncate_chars};
#[allow(unused_imports)]
pub(crate) use policy::{
    is_safe_sysfs_iface, is_valid_container_id, is_valid_container_name, is_valid_hex64_lower,
    is_valid_incus_project, is_valid_runtime_bin, is_valid_uuid,
};
#[allow(unused_imports)]
pub(crate) use reconcile::{active_bandwidth_limits, resolve_container_cached};
#[allow(unused_imports)]
pub(crate) use tc_ops::{filter_listing, rollback_bandwidth_mutation, RollbackOperation};
#[allow(unused_imports)]
pub(crate) use types::{
    DEFAULT_CMD_TIMEOUT, DEFAULT_OUTPUT_LIMIT, MAX_INVENTORY_ITEMS, MAX_INVENTORY_OUTPUT,
    PRUNE_DEPARTED_AFTER_SECS, TEMP_FILE_SEQ,
};
#[allow(unused_imports)]
pub(crate) use verify::{
    call_with_prefix, canonical_project, parse_link_indices, project_matches,
};

#[cfg(test)]
#[allow(unused_imports)]
use std::{
    collections::{BTreeMap, HashMap},
    env, fs,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

#[cfg(test)]
#[allow(unused_imports)]
use runtime_drivers::ContainerSample;

#[cfg(test)]
mod tests;
