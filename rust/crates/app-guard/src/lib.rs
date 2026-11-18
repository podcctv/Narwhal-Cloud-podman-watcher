#![forbid(unsafe_code)]

//! Pure-Rust, `std`-only operations, security, audit, and policy subsystems
//! for Narwhal Cloud Container Watcher.
//!
//! Migrated from:
//! - `client/incus_health.py` & `client/operations.py` (`incus_health`)
//! - `client/socks_detector.py` & `client/agent.py` panel pairing helpers (`socks_detector`)
//! - `client/disk_cleanup.py` & `client/disk_cleanup_worker.py` (`disk_cleanup`)
//! - `client/security_banner.py` (`security_banner`)

#[allow(unused_imports)]
pub(crate) use proc_probe::json_escape;
#[allow(unused_imports)]
pub(crate) use runtime_drivers::JsonVal;

mod util;
pub mod disk_cleanup;
pub mod incus_health;
pub mod security_banner;
pub mod socks_detector;

#[cfg(test)]
mod tests;
