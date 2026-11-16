#![forbid(unsafe_code)]

//! Pure-`std`, `#![forbid(unsafe_code)]` protocol, service, binary, micro-burst,
//! and sensitive-drop guards for Narwhal Cloud Container Watcher.
//!
//! Migrated from:
//! - `client/vmess_guard.py` and `client/agent.py` protocol guard helpers (`vmess`)
//! - `client/speedtest_guard.py` and `client/agent.py` speedtest alert helper (`speedtest`)
//! - `client/pasarguard_guard.py` (`pasarguard`)
//! - `client/microburst_guard.py` (`microburst`)
//! - `client/file_guard.py` (`file_drop`)

pub mod file_drop;
pub mod microburst;
pub mod pasarguard;
pub mod speedtest;
pub mod util;
pub mod vmess;
