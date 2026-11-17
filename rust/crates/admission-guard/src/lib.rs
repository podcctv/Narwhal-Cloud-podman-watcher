#![forbid(unsafe_code)]

//! Pure-`std`, `#![forbid(unsafe_code)]` container admission protection crate.
//!
//! Migrates `client/admission_policy.py`, `client/admission_observe.py`,
//! `client/admission_linux.py`, and `client/admission_guard.py`, matching
//! `docs/admission-protection.md`, `server/admission_api.py`,
//! `tests/test_admission.py`, and `tests/admission_linux_probe.py`.

use std::fmt;
use std::io::{self, ErrorKind};

pub mod guard;
pub mod linux;
pub mod observe;
pub mod policy;
pub mod sni;

use observe::UnsupportedNetwork;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    UnsupportedNetwork(UnsupportedNetwork),
    Timeout(String),
    PermissionDenied(String),
    DependencyUnavailable(String),
    Runtime(String),
    Value(String),
    Other(String),
}

impl AdmissionError {
    pub fn from_io(err: io::Error) -> Self {
        match err.kind() {
            ErrorKind::PermissionDenied => Self::PermissionDenied(err.to_string()),
            ErrorKind::NotFound => Self::DependencyUnavailable(err.to_string()),
            ErrorKind::TimedOut | ErrorKind::WouldBlock => Self::Timeout(err.to_string()),
            _ => Self::Runtime(err.to_string()),
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::UnsupportedNetwork(u) => u.message.as_str(),
            Self::Timeout(m)
            | Self::PermissionDenied(m)
            | Self::DependencyUnavailable(m)
            | Self::Runtime(m)
            | Self::Value(m)
            | Self::Other(m) => m.as_str(),
        }
    }
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for AdmissionError {}

pub use guard::{
    build_event_payload_json, build_status_payload_json, compute_desired_config_hash,
    deterministic_queue_base, failure_details, handle_cli_args, normalized_alert,
    release_owned, release_owned_with, AdmissionController, AdmissionJournal, Guard, GuardRecord,
    SniViolationEvent, DEFAULT_ADMISSION_JOURNAL,
};
pub use sni::{
    evaluate_inbound_sni, is_allowed_sni, normalize_sni, SniDecision, SniParse, SNI_WHITELIST,
};

/// Convenience alias for `release_owned()` using default journal and nft runner.
pub fn release_owned_default() -> Result<(), AdmissionError> {
    release_owned()
}
pub use linux::{
    is_valid_table_name, packet, rules, LiveNftRunner, Nft, NftRunner, NoopQueueBackend,
    QueueBackend,
};
#[cfg(unix)]
pub use linux::SubprocessNfqBackend;
pub use observe::{
    decode, incarnation, incarnation_from_root, snapshot, snapshot_with_transports, sockets,
    sockets_from_dir, ContainerDescriptor, ContainerSnapshot, SocketObservation,
};
pub use policy::{address, source_limit_from_env, Policy, TcpFlow};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use net_guard::{ClosureCommandRunner, IncusTransport, RunmanTransport};
    use runtime_drivers::JsonVal;

    fn flow(n: u16) -> TcpFlow {
        (
            "10.9.0.2".to_string(),
            443,
            "192.0.2.1".to_string(),
            10000 + n,
        )
    }

    fn sample_policy(state: &mut Policy, count: u16, now: i64, inbound: &[&str]) -> bool {
        let flows: BTreeSet<TcpFlow> = (0..count).map(flow).collect();
        let in_vec: Vec<String> = inbound.iter().map(|s| (*s).to_string()).collect();
        let live_set: BTreeSet<String> = in_vec.iter().cloned().collect();
        state.observe(&flows, &in_vec, &live_set, Some(now), true, "boot:net:pid")
    }

    fn make_limited_policy() -> Policy {
        let mut state = Policy::new(None, 0);
        for stamp in (1000..1121).step_by(10) {
            sample_policy(&mut state, 1001, stamp, &[]);
        }
        assert!(state.is_limited());
        state
    }

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!(
            "narwhal_admission_guard_{}_{}",
            tag,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    fn build_ipv4_tcp_packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut raw = vec![0u8; 24];
        raw[0] = 0x45;
        raw[9] = 6;
        raw[12..16].copy_from_slice(&src);
        raw[16..20].copy_from_slice(&dst);
        raw[20..22].copy_from_slice(&sport.to_be_bytes());
        raw[22..24].copy_from_slice(&dport.to_be_bytes());
        raw
    }

    struct MockNftRunner {
        pub live_sources: BTreeSet<String>,
        pub apply_fail: bool,
        pub apply_calls: Vec<(String, bool, usize, Vec<u16>)>,
        pub admit_calls: Vec<(String, String)>,
        pub removed_tables: Vec<String>,
    }

    impl MockNftRunner {
        fn new(live_sources: BTreeSet<String>) -> Self {
            Self {
                live_sources,
                apply_fail: false,
                apply_calls: Vec::new(),
                admit_calls: Vec::new(),
                removed_tables: Vec::new(),
            }
        }
    }

    #[derive(Clone)]
    struct SharedMockNftRunner(Arc<Mutex<MockNftRunner>>);

    impl SharedMockNftRunner {
        fn new(live_sources: BTreeSet<String>) -> Self {
            Self(Arc::new(Mutex::new(MockNftRunner::new(live_sources))))
        }
    }

    impl NftRunner for SharedMockNftRunner {
        fn run(&mut self, args: &[String], data: Option<&str>) -> Result<String, AdmissionError> {
            let mut m = self.0.lock().unwrap();
            if args.len() >= 2 && args[1] == "--check" {
                return Ok(String::new());
            }
            if args.len() >= 2 && args[1] == "-f" {
                if m.apply_fail {
                    return Err(AdmissionError::Runtime(
                        "simulated atomic write failure".to_string(),
                    ));
                }
                let script = data.unwrap_or("");
                let limited = script.contains("jump outgoing");
                let table = script
                    .lines()
                    .find_map(|l| l.strip_prefix("add table inet "))
                    .unwrap_or("")
                    .to_string();
                m.apply_calls.push((table, limited, 0, Vec::new()));
                return Ok(String::new());
            }
            if args.len() >= 3 && args[1] == "add" && args[2] == "element" {
                let table = args.get(4).cloned().unwrap_or_default();
                let ip = args.get(7).cloned().unwrap_or_default();
                m.admit_calls.push((table, ip));
                return Ok(String::new());
            }
            if args.len() >= 3 && args[1] == "delete" && args[2] == "table" {
                let table = args.get(4).cloned().unwrap_or_default();
                m.removed_tables.push(table);
                return Ok(String::new());
            }
            if args.len() >= 3 && args[1] == "-j" && args[2] == "list" {
                if args.get(3).map(String::as_str) == Some("table") {
                    let elems: Vec<String> = m
                        .live_sources
                        .iter()
                        .map(|ip| format!("\"{ip}\""))
                        .collect();
                    let json = format!(
                        "{{\"nftables\":[{{\"metainfo\":{{\"version\":\"1.0\"}}}},{{\"table\":{{\"family\":\"inet\",\"name\":\"{}\",\"handle\":1}}}},{{\"set\":{{\"family\":\"inet\",\"name\":\"sources4\",\"table\":\"{}\",\"handle\":2,\"elem\":[{}]}}}}]}}",
                        args.get(5).map(String::as_str).unwrap_or("nwguard_0000000000000000"),
                        args.get(5).map(String::as_str).unwrap_or("nwguard_0000000000000000"),
                        elems.join(",")
                    );
                    return Ok(json);
                }
                return Ok("{\"nftables\":[]}".to_string());
            }
            Ok(String::new())
        }
    }

    #[test]
    fn test_strict_trigger_and_gap() {
        let mut state = Policy::new(None, 0);
        for stamp in (1000..1301).step_by(10) {
            sample_policy(&mut state, 1000, stamp, &[]);
        }
        assert!(!state.is_limited());
        sample_policy(&mut state, 1001, 1310, &[]);
        state.observe(
            &BTreeSet::new(),
            &[],
            &BTreeSet::new(),
            Some(1320),
            false,
            "",
        );
        for stamp in (1330..1441).step_by(10) {
            sample_policy(&mut state, 1001, stamp, &[]);
        }
        assert!(!state.is_limited());
        sample_policy(&mut state, 1001, 1450, &[]);
        assert!(state.is_limited());
    }

    #[test]
    fn test_renew_exact500_once_and_minimum_period() {
        let mut state = make_limited_policy();
        let deadline = state.review_at.expect("review_at");
        for stamp in (1130..=deadline).step_by(10) {
            sample_policy(&mut state, 500, stamp, &[]);
        }
        assert_eq!(state.extensions, 1);
        assert_eq!(state.review_at, Some(deadline + 1800));
        sample_policy(&mut state, 500, deadline + 10, &[]);
        assert_eq!(state.extensions, 1);
        for stamp in ((deadline + 20)..=(deadline + 1800)).step_by(10) {
            sample_policy(&mut state, 499, stamp, &[]);
        }
        assert!(!state.is_limited());
    }

    #[test]
    fn test_missing_restart_out_of_order_cannot_release() {
        let state = make_limited_policy();
        let deadline = state.review_at.expect("review_at");
        let saved = state.to_json_val();
        let mut restored = Policy::new(Some(&saved), 0);
        sample_policy(&mut restored, 0, deadline, &[]);
        assert!(restored.is_limited());
        sample_policy(&mut restored, 0, deadline - 10, &[]);
        assert_eq!(restored.sampled_at, Some(deadline));
        for stamp in ((deadline + 10)..=(deadline + 120)).step_by(10) {
            sample_policy(&mut restored, 0, stamp, &[]);
        }
        assert!(!restored.is_limited());
    }

    #[test]
    fn test_source_ip_count_is_observation_only_and_sample_stays_bounded() {
        let mut state = Policy::new(None, 0);
        let sources = [
            "192.0.2.1",
            "2001:db8::1",
            "192.0.2.2",
            "2001:db8::2",
            "192.0.2.3",
            "2001:db8::3",
        ];
        sample_policy(&mut state, 1, 1000, &sources);
        let cur_ips: Vec<&str> = state.sources.iter().map(|s| s.ip.as_str()).collect();
        assert_eq!(cur_ips, &sources[..5]);
        assert!(!state.observe_source(sources[5], 1001, false).unwrap());
        assert_eq!(state.blocked_packets, 0);
        assert!(!state
            .observe_source("::ffff:192.0.2.1", 1002, false)
            .unwrap());

        let saved = state.to_json_val();
        let mut restored = Policy::new(Some(&saved), 0);
        let rev: Vec<&str> = sources.iter().copied().rev().collect();
        sample_policy(&mut restored, 1, 1010, &rev);
        let restored_ips: Vec<&str> = restored.sources.iter().map(|s| s.ip.as_str()).collect();
        assert_eq!(restored_ips, &sources[..5]);

        sample_policy(&mut restored, 1, 1020, &sources[1..5]);
        assert!(restored.observe_source(sources[5], 1021, false).unwrap());
        assert_eq!(restored.sources.last().unwrap().ip, sources[5]);
    }

    #[test]
    fn test_pending_reservations_prevent_burst_and_stale_admission() {
        let mut state = make_limited_policy();
        sample_policy(&mut state, 499, 1130, &[]);
        assert!(state.admit_tcp(&flow(9000), 1131));
        assert!(state.admit_tcp(&flow(9000), 1132));
        assert!(!state.admit_tcp(&flow(9001), 1132));
        assert!(!state.admit_tcp(&flow(9002), 1161));
    }

    #[test]
    fn test_observation_sample_is_bounded_without_denial_counters() {
        let mut state = Policy::new(None, 0);
        let init: Vec<String> = (1..6).map(|n| format!("192.0.2.{n}")).collect();
        state.seed(&init, 1000);
        for n in 1..101 {
            let _ = state.observe_source(&format!("198.51.100.{n}"), 1001, false);
        }
        assert_eq!(state.sources.len(), 5);
        assert!(state.blocked.is_empty());
        assert_eq!(state.blocked_packets, 0);
    }

    #[test]
    fn test_half_open_syn_recv_is_not_a_source_sample_or_concurrency_flow() {
        let dir = temp_test_dir("sockets_syn_recv");
        let tcp = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1
   1: 0200090A:01BB 010200C0:3039 01 00000000:00000000 00:00000000 00000000 0 0 2
   2: 0200090A:01BB 016433C6:303A 03 00000000:00000000 00:00000000 00000000 0 0 3
";
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        fs::write(dir.join("tcp"), tcp).unwrap();
        for other in ["tcp6", "udp", "udp6"] {
            fs::write(dir.join(other), header).unwrap();
        }
        let obs = sockets_from_dir(123, &dir, || Ok("boot:net:pid".to_string())).unwrap();
        assert_eq!(obs.epoch, "boot:net:pid");
        assert_eq!(obs.flows.len(), 1);
        assert_eq!(obs.inbound, vec!["192.0.2.1".to_string()]);
        assert_eq!(obs.listening, vec![443]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_runman_admission_proves_current_generation_pid_and_owned_veth() {
        let vm_id = "11111111-2222-3333-4444-555555555555";
        let generation = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let mut container = ContainerDescriptor::new("runman", "default", vm_id);
        container.instance_id = generation.to_string();
        container.pid = Some(4242);
        container.network_addresses = vec!["10.9.0.2".to_string()];

        struct FakeIncus;
        impl IncusTransport for FakeIncus {
            fn request(
                &mut self,
                _m: &str,
                _p: &str,
                _b: Option<&JsonVal>,
                _e: Option<&str>,
            ) -> Result<(JsonVal, Option<String>), String> {
                Err("unused".to_string())
            }
        }

        struct FakeRunman {
            gen_id: String,
        }
        impl RunmanTransport for FakeRunman {
            fn request(
                &mut self,
                _m: &str,
                _p: &str,
                _b: Option<&[u8]>,
            ) -> Result<(u16, Vec<u8>), String> {
                let body = format!(
                    "{{\"ok\":true,\"running\":true,\"isolated\":false,\"interface_up\":true,\"instance_id\":\"{}\",\"init_pid\":4242}}",
                    self.gen_id
                );
                Ok((200, body.into_bytes()))
            }
        }

        let mut runner = ClosureCommandRunner(|args: &[String], _stdin: Option<&str>| {
            if args.len() >= 2 && args[0] == "nsenter" && args[1] == "-t" {
                (
                    true,
                    r#"[{"ifname":"eth0","ifindex":2,"link_index":7,"addr_info":[{"local":"10.9.0.2","scope":"global"}]}]"#
                        .to_string(),
                )
            } else if args == ["ip", "-j", "link", "show"] {
                (true, r#"[{"ifname":"veth-rm123","ifindex":7}]"#.to_string())
            } else {
                (true, r#"[{"linkinfo":{"info_kind":"veth"}}]"#.to_string())
            }
        });

        let mut incus = FakeIncus;
        let mut runman = FakeRunman {
            gen_id: generation.to_string(),
        };
        let result = snapshot_with_transports(
            &container,
            &BTreeMap::new(),
            &mut runner,
            &mut incus,
            &mut runman,
            true,
            |_| {
                Ok(SocketObservation {
                    epoch: "boot:net:4242".to_string(),
                    flows: BTreeSet::new(),
                    inbound: Vec::new(),
                    listening: Vec::new(),
                })
            },
            |_| Ok("boot:net:4242".to_string()),
        )
        .expect("runman snapshot");

        assert_eq!(result.instance_id, generation);
        assert_eq!(result.pid, Some(4242));
        assert_eq!(result.ips, vec!["10.9.0.2".to_string()]);
        assert_eq!(result.interfaces, vec!["veth-rm123".to_string()]);

        // Also verify replaced generation rejection:
        let mut bad_runman = FakeRunman {
            gen_id: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff".to_string(),
        };
        let err = snapshot_with_transports(
            &container,
            &BTreeMap::new(),
            &mut runner,
            &mut incus,
            &mut bad_runman,
            true,
            |_| unreachable!(),
            |_| unreachable!(),
        )
        .expect_err("must reject replaced generation");
        assert!(err.message().contains("changed") || err.message().contains("generation"));
    }

    #[test]
    fn test_failed_write_then_restart_retries_desired_configuration() {
        let dir = temp_test_dir("failed_write_restart");
        let journal = AdmissionJournal::new(dir.join("state.json"));
        let mut live_set = BTreeSet::new();
        live_set.insert("192.0.2.1".to_string());
        let mock_runner = SharedMockNftRunner::new(live_set);
        let g = Guard::new(
            journal.clone(),
            Nft::new(mock_runner.clone()),
            NoopQueueBackend::new(),
            Some(10),
        )
        .unwrap();

        let c = ContainerDescriptor::new("incus", "default", "test");
        let snap = ContainerSnapshot {
            instance_id: "a".repeat(36),
            ips: vec!["10.9.0.2".to_string()],
            interfaces: vec!["br-test".to_string()],
            epoch: "boot:net:pid".to_string(),
            flows: (0..1001).map(flow).collect(),
            inbound: vec!["192.0.2.1".to_string()],
            listening_ports: Vec::new(),
            pid: Some(1234),
            observed_at: 1000,
            shared_network: false,
        };
        g.update(&c, &snap, Some(1000)).unwrap();
        g.with_inner(|inner| {
            let st = inner.states.values_mut().next().unwrap();
            st.above_since = Some(890);
        });

        mock_runner.0.lock().unwrap().apply_fail = true;
        let mut snap2 = snap.clone();
        snap2.observed_at = 1010;
        assert!(g.update(&c, &snap2, Some(1010)).is_err());
        g.failed(&c, 1010, None, "enforcement");

        mock_runner.0.lock().unwrap().apply_fail = false;
        let restored = Guard::new(
            journal,
            Nft::new(mock_runner.clone()),
            NoopQueueBackend::new(),
            Some(10),
        )
        .unwrap();
        let mut snap3 = snap;
        snap3.observed_at = 1020;
        let result = restored.update(&c, &snap3, Some(1020)).unwrap();
        assert_eq!(result.get("limited"), Some(&JsonVal::Bool(true)));
        assert_eq!(
            result.get("state"),
            Some(&JsonVal::Str("enforced".to_string()))
        );
        assert!(mock_runner.0.lock().unwrap().apply_calls.last().unwrap().1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_rules_forward_scope_and_no_bypass() {
        let table = format!("nwguard_{}", "a".repeat(16));
        let ips = vec!["10.9.0.2".to_string(), "2001:db8::2".to_string()];
        let ifaces = vec!["br-test".to_string()];
        let text = rules(&table, &ips, 20000, &[], true, &[], &ifaces, 0, 120, &[]).unwrap();
        assert!(text.contains("oifname { \"br-test\" } ip daddr"));
        assert!(text.contains("iifname { \"br-test\" } ip6 saddr"));
        assert!(text.contains("ct state new queue num 20000"));
        assert!(text.contains("ct state new queue num 20001"));
        for forbidden in [
            "flush ruleset",
            "hook input",
            "hook output",
            "bypass",
            "reject with tcp reset",
            "sources4",
            "sources6",
            "saddr @sources",
        ] {
            assert!(!text.contains(forbidden), "unexpected {forbidden}");
        }
        let unrestricted = rules(
            &table,
            &["10.9.0.2".to_string()],
            20000,
            &[],
            false,
            &[],
            &ifaces,
            0,
            120,
            &[],
        )
        .unwrap();
        assert!(!unrestricted.contains("queue num"));
        assert!(unrestricted.contains("incoming return"));
        assert!(rules(
            &table,
            &["10.9.0.2".to_string()],
            20000,
            &[],
            false,
            &[],
            &[],
            0,
            120,
            &[],
        )
        .is_err());
    }

    #[test]
    fn test_packet_parser() {
        let mut raw = build_ipv4_tcp_packet([192, 0, 2, 1], [10, 9, 0, 2], 123, 443);
        assert_eq!(
            packet(&raw).unwrap(),
            ("192.0.2.1".to_string(), "10.9.0.2".to_string(), 6, 123, 443)
        );
        raw[6] = 1;
        assert!(packet(&raw).is_err());

        // IPv6 with Hop-by-Hop extension header (proto 0 -> TCP 6):
        let mut raw6 = vec![0u8; 52];
        raw6[0] = 0x60;
        raw6[6] = 0; // Hop-by-Hop
        raw6[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        raw6[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        raw6[40] = 6; // next header = TCP
        raw6[41] = 0; // length = (0 + 1) * 8 = 8 bytes
        raw6[48..50].copy_from_slice(&1234u16.to_be_bytes());
        raw6[50..52].copy_from_slice(&8443u16.to_be_bytes());
        assert_eq!(
            packet(&raw6).unwrap(),
            (
                "2001:db8::1".to_string(),
                "2001:db8::2".to_string(),
                6,
                1234,
                8443
            )
        );
    }

    #[test]
    fn test_failed_sample_breaks_duration_and_has_safe_failure_code() {
        let dir = temp_test_dir("failed_sample");
        let journal = AdmissionJournal::new(dir.join("state.json"));
        let mut live_set = BTreeSet::new();
        live_set.insert("192.0.2.1".to_string());
        let mock_runner = SharedMockNftRunner::new(live_set);
        let g = Guard::new(
            journal,
            Nft::new(mock_runner),
            NoopQueueBackend::new(),
            Some(10),
        )
        .unwrap();
        let c = ContainerDescriptor::new("incus", "default", "test");
        let snap = ContainerSnapshot {
            instance_id: "a".repeat(36),
            ips: vec!["10.9.0.2".to_string()],
            interfaces: vec!["br-test".to_string()],
            epoch: "boot:net:pid".to_string(),
            flows: (0..1001).map(flow).collect(),
            inbound: vec!["192.0.2.1".to_string()],
            listening_ports: Vec::new(),
            pid: Some(1234),
            observed_at: 1000,
            shared_network: false,
        };
        g.update(&c, &snap, Some(1000)).unwrap();
        let sensitive = AdmissionError::Runtime("sensitive command output".to_string());
        g.failed(&c, 1010, Some(&sensitive), "enforcement");
        g.with_inner(|inner| {
            let st = inner.states.values().next().unwrap();
            assert_eq!(st.above_since, Some(0));
        });
        let status = g.status_at(&c, 1010);
        assert_eq!(
            status.get("state"),
            Some(&JsonVal::Str("unverified".to_string()))
        );
        assert_eq!(
            status.get("failure_code"),
            Some(&JsonVal::Str("firewall_apply_failed".to_string()))
        );
        assert_eq!(
            status.get("failure_stage"),
            Some(&JsonVal::Str("enforcement".to_string()))
        );
        let err_msg = status.get("error").and_then(JsonVal::as_str).unwrap_or("");
        assert!(!err_msg.contains("sensitive"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_source_ip_count_never_blocks_but_tcp_cap_still_limits_new_flows() {
        let dir = temp_test_dir("observe_only_tcp_cap");
        let journal = AdmissionJournal::new(dir.join("state.json"));
        let sources: Vec<String> = (1..6).map(|n| format!("192.0.2.{n}")).collect();
        let mock_runner = SharedMockNftRunner::new(sources.iter().cloned().collect());
        let g = Guard::new(
            journal,
            Nft::new(mock_runner),
            NoopQueueBackend::new(),
            Some(0),
        )
        .unwrap();
        let c = ContainerDescriptor::new("incus", "default", "test");
        let now = 2000;
        let snap = ContainerSnapshot {
            instance_id: "a".repeat(36),
            ips: vec!["10.9.0.2".to_string()],
            interfaces: vec!["br-test".to_string()],
            epoch: "boot:net:pid".to_string(),
            flows: (0..500).map(flow).collect(),
            inbound: sources,
            listening_ports: Vec::new(),
            pid: Some(1234),
            observed_at: now,
            shared_network: false,
        };
        g.update(&c, &snap, Some(now)).unwrap();
        let queue = g.with_inner(|inner| {
            let st = inner.states.values_mut().next().unwrap();
            st.limited = Some(false);
            inner.records.values().next().unwrap().queue
        });
        let raw = build_ipv4_tcp_packet([198, 51, 100, 6], [10, 9, 0, 2], 123, 443);
        assert!(g.decision_at(queue, &raw, now).unwrap());
        g.with_inner(|inner| {
            let st = inner.states.values_mut().next().unwrap();
            assert!(!st.blocked.contains_key("198.51.100.6"));
            assert_eq!(st.sources.len(), 5);
            st.limited = Some(true);
        });
        assert!(!g.decision_at(queue, &raw, now).unwrap());
        g.with_inner(|inner| {
            let st = inner.states.values().next().unwrap();
            assert_eq!(st.tcp_denied, 1);
            assert!(!st.blocked.contains_key("198.51.100.6"));
        });
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_source_limit_enforced_blocks_eleventh_source_and_emits_alert() {
        let dir = temp_test_dir("eleventh_source_blocked");
        let journal = AdmissionJournal::new(dir.join("state.json"));
        let sources: Vec<String> = (1..11).map(|n| format!("192.0.2.{n}")).collect();
        let mock_runner = SharedMockNftRunner::new(sources.iter().cloned().collect());
        let g = Guard::new(
            journal,
            Nft::new(mock_runner),
            NoopQueueBackend::new(),
            Some(10),
        )
        .unwrap();
        let c = ContainerDescriptor::new("incus", "default", "test");
        let now = 3000;
        let snap = ContainerSnapshot {
            instance_id: "a".repeat(36),
            ips: vec!["10.9.0.2".to_string()],
            interfaces: vec!["br-test".to_string()],
            epoch: "boot:net:pid".to_string(),
            flows: (0..10).map(flow).collect(),
            inbound: sources,
            listening_ports: Vec::new(),
            pid: Some(1234),
            observed_at: now,
            shared_network: false,
        };
        g.update(&c, &snap, Some(now)).unwrap();
        let queue = g.with_inner(|inner| {
            assert_eq!(inner.states.values().next().unwrap().sources.len(), 10);
            inner.records.values().next().unwrap().queue
        });
        assert_eq!(g.source_limit(), 10);

        let raw11 = build_ipv4_tcp_packet([198, 51, 100, 11], [10, 9, 0, 2], 123, 443);
        assert!(!g.decision_at(queue, &raw11, now).unwrap());
        assert!(!g.decision_at(queue, &raw11, now).unwrap());
        g.with_inner(|inner| {
            let st = inner.states.values().next().unwrap();
            assert_eq!(st.blocked_packets, 2);
            assert_eq!(st.blocked["198.51.100.11"].packets, 2);
        });

        let raw1 = build_ipv4_tcp_packet([192, 0, 2, 1], [10, 9, 0, 2], 123, 443);
        assert!(g.decision_at(queue, &raw1, now).unwrap());

        let alerts = g.alerts_at(&c, now);
        assert_eq!(alerts.len(), 1);
        assert_eq!(
            alerts[0].get("type").and_then(JsonVal::as_str),
            Some("inbound_source_blocked")
        );
        assert!(alerts[0]
            .get("title")
            .and_then(JsonVal::as_str)
            .unwrap()
            .contains("10"));
        assert!(alerts[0]
            .get("message")
            .and_then(JsonVal::as_str)
            .unwrap()
            .contains("198.51.100.11"));

        g.with_inner(|inner| {
            let st = inner.states.values_mut().next().unwrap();
            for i in 2..11 {
                st.admit_source(&format!("192.0.2.{i}"), now + 50).unwrap();
            }
            let (accepted, changed) = st.admit_source("198.51.100.12", now + 130).unwrap();
            assert!(accepted);
            assert!(changed);
            assert_eq!(st.sources.len(), 10);
            let ips: Vec<&str> = st.sources.iter().map(|x| x.ip.as_str()).collect();
            assert!(ips.contains(&"198.51.100.12"));
            assert!(!ips.contains(&"192.0.2.1"));
        });
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scanner_on_closed_port_and_tentative_syn_probation_expiry() {
        let dir = temp_test_dir("scanner_probation");
        let journal = AdmissionJournal::new(dir.join("state.json"));
        let mock_runner = SharedMockNftRunner::new(BTreeSet::new());
        let g = Guard::new(
            journal,
            Nft::new(mock_runner.clone()),
            NoopQueueBackend::new(),
            Some(10),
        )
        .unwrap();
        let c = ContainerDescriptor::new("incus", "default", "test-probation");
        let now = 4000;
        let biz_sources: Vec<String> = (1..10).map(|i| format!("192.0.2.{i}")).collect();
        let mut snap = ContainerSnapshot {
            instance_id: "c".repeat(36),
            ips: vec!["10.9.0.2".to_string()],
            interfaces: vec!["br-test".to_string()],
            epoch: "boot:net:pid".to_string(),
            flows: BTreeSet::new(),
            inbound: biz_sources.clone(),
            listening_ports: vec![45556],
            pid: Some(1234),
            observed_at: now,
            shared_network: false,
        };
        g.update(&c, &snap, Some(now)).unwrap();
        let queue = g.with_inner(|inner| inner.records.values().next().unwrap().queue);

        // Scanner hits closed port 80 -> accepted without consuming a slot
        for i in 1..=20u16 {
            let raw_closed =
                build_ipv4_tcp_packet([198, 51, 100, (i as u8)], [10, 9, 0, 2], 10000 + i, 80);
            assert!(g.decision_at(queue, &raw_closed, now).unwrap());
        }
        g.with_inner(|inner| {
            assert_eq!(inner.states.values().next().unwrap().sources.len(), 9);
        });

        // Scanner sends SYN to listening port 45556 -> enters probation (unconfirmed)
        let raw_scan = build_ipv4_tcp_packet([198, 51, 100, 99], [10, 9, 0, 2], 54321, 45556);
        assert!(g.decision_at(queue, &raw_scan, now).unwrap());
        assert!(mock_runner.0.lock().unwrap().admit_calls.is_empty());

        // Even if nft.live returns the probe IP or stale IP, observe() must NOT promote unconfirmed probe
        {
            let mut m = mock_runner.0.lock().unwrap();
            for s in &biz_sources {
                m.live_sources.insert(s.clone());
            }
            m.live_sources.insert("198.51.100.99".to_string());
            m.live_sources.insert("104.28.152.143".to_string());
        }
        snap.observed_at = now + 5;
        g.update(&c, &snap, Some(now + 5)).unwrap();
        let status_payload = g.status_at(&c, now + 5);
        assert_eq!(
            status_payload
                .get("confirmed_sources")
                .and_then(JsonVal::as_arr)
                .unwrap()
                .len(),
            9
        );
        assert_eq!(
            status_payload
                .get("probation_sources")
                .and_then(JsonVal::as_arr)
                .unwrap()
                .len(),
            1
        );

        // Expire probation probe (advance past PROBATION_GAP = 15s)
        g.with_inner(|inner| {
            let st = inner.states.values_mut().next().unwrap();
            for s in &mut st.sources {
                if s.ip == "198.51.100.99" {
                    s.first_seen = now - 20;
                }
            }
        });

        // 10th real business client connects and succeeds
        let raw_biz10 = build_ipv4_tcp_packet([192, 0, 2, 10], [10, 9, 0, 2], 54322, 45556);
        assert!(g.decision_at(queue, &raw_biz10, now + 6).unwrap());
        let mut all_10 = biz_sources;
        all_10.push("192.0.2.10".to_string());
        snap.inbound = all_10;
        snap.observed_at = now + 6;
        g.update(&c, &snap, Some(now + 6)).unwrap();

        // Now all 10 slots are confirmed; 11th source is blocked
        let raw_11 = build_ipv4_tcp_packet([198, 51, 100, 111], [10, 9, 0, 2], 54323, 45556);
        assert!(!g.decision_at(queue, &raw_11, now + 6).unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_receipt_normalization_and_expiry_rules() {
        let now = 5000;
        let raw_json = format!(
            r#"{{
                "type": "inbound_source_blocked",
                "runtime": "podman",
                "container_name": "customer",
                "instance_id": "{}",
                "admission": {{
                    "state": "enforced",
                    "observed_at": {now},
                    "source_limit_enforced": false,
                    "sources": [{{"ip": "192.0.2.1", "first_seen": 1000}}],
                    "password": "NEVER-SEND",
                    "blocked": {{"2001:db8::1": {{"packets": 2, "last_seen": 1000}}}}
                }}
            }}"#,
            "a".repeat(64)
        );
        let val = JsonVal::parse(&raw_json).unwrap();
        let norm = normalized_alert(&val, now).unwrap();
        let serialized = net_guard::json_val_to_string(&norm, false);
        assert!(!serialized.contains("NEVER-SEND"));
        let adm = norm.get("admission").unwrap();
        assert_eq!(adm.get_i64("source_limit"), Some(5));
        assert_eq!(adm.get_bool("source_limit_enforced"), Some(false));

        // Expired observed_at rejected for enforced alerts:
        assert!(normalized_alert(&val, now + 100).is_err());

        // Unverified alert strips raw error text:
        let unv_json = format!(
            r#"{{
                "type": "admission_unverified",
                "runtime": "incus",
                "project": "default",
                "container_name": "customer",
                "admission": {{
                    "state": "unverified",
                    "observed_at": {now},
                    "failure_stage": "enforcement",
                    "failure_code": "firewall_apply_failed",
                    "error": "secret command output",
                    "sources": [],
                    "blocked": {{}}
                }}
            }}"#
        );
        let unv_val = JsonVal::parse(&unv_json).unwrap();
        let unv_norm = normalized_alert(&unv_val, now).unwrap();
        let unv_str = net_guard::json_val_to_string(&unv_norm, false);
        assert!(unv_norm
            .get_str("message")
            .unwrap()
            .contains("防火墙应用/验证未通过"));
        assert!(!unv_str.contains("secret command output"));

        // Runman canonical UUID validation:
        let rm_json = format!(
            r#"{{
                "type": "admission_unverified",
                "runtime": "runman",
                "project": "default",
                "container_name": "11111111-2222-3333-4444-555555555555",
                "instance_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "admission": {{
                    "state": "unverified",
                    "observed_at": {now},
                    "sources": [],
                    "blocked": {{}}
                }}
            }}"#
        );
        assert!(normalized_alert(&JsonVal::parse(&rm_json).unwrap(), now).is_ok());
        let bad_rm = rm_json.replace("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "not-a-generation");
        assert!(normalized_alert(&JsonVal::parse(&bad_rm).unwrap(), now).is_err());
    }

    #[test]
    fn test_guard_rename_collision_expiry_retire_and_controller_batch() {
        let dir = temp_test_dir("rename_collision_retire");
        let journal = AdmissionJournal::new(dir.join("state.json"));
        let mock_runner = SharedMockNftRunner::new(BTreeSet::new());
        let g = Arc::new(
            Guard::new(
                journal.clone(),
                Nft::new(mock_runner.clone()),
                NoopQueueBackend::new(),
                Some(10),
            )
            .unwrap(),
        );

        let c1 = ContainerDescriptor::new("incus", "default", "old-name");
        let now = 6000;
        let snap1 = ContainerSnapshot {
            instance_id: "d".repeat(36),
            ips: vec!["10.9.0.2".to_string()],
            interfaces: vec!["br-test".to_string()],
            epoch: "boot:net:777".to_string(),
            flows: BTreeSet::new(),
            inbound: vec!["192.0.2.1".to_string()],
            listening_ports: vec![443],
            pid: Some(555),
            observed_at: now,
            shared_network: false,
        };
        g.update(&c1, &snap1, Some(now)).unwrap();

        // Rename of same immutable instance preserves slot order & queue:
        let c1_renamed = ContainerDescriptor::new("incus", "default", "new-name");
        let mut snap1_renamed = snap1.clone();
        snap1_renamed.observed_at = now + 5;
        let res_renamed = g.update(&c1_renamed, &snap1_renamed, Some(now + 5)).unwrap();
        assert_eq!(res_renamed.get("state"), Some(&JsonVal::Str("enforced".to_string())));
        g.with_inner(|inner| {
            assert_eq!(inner.records.len(), 1);
            assert_eq!(inner.states.values().next().unwrap().sources[0].ip, "192.0.2.1");
        });

        // Different instance claiming overlapping (ip, iface) fails closed:
        let c2 = ContainerDescriptor::new("incus", "default", "other-container");
        let mut snap2 = snap1_renamed.clone();
        snap2.instance_id = "e".repeat(36);
        assert!(g.update(&c2, &snap2, Some(now + 5)).is_err());

        // Stale enforced receipt (>30s) transitions to unverified stale_sample without emitting security alert:
        let stale_status = g.status_at(&c1_renamed, now + 40);
        assert_eq!(stale_status.get("state"), Some(&JsonVal::Str("unverified".to_string())));
        assert_eq!(stale_status.get("failure_code"), Some(&JsonVal::Str("stale_sample".to_string())));
        assert!(g.alerts_at(&c1_renamed, now + 40).is_empty());

        // Concrete unverified failure receipt is preserved even after 120s:
        let fail_err = AdmissionError::Runtime("apply err".to_string());
        g.failed(&c1_renamed, now + 45, Some(&fail_err), "enforcement");
        let unv_later = g.status_at(&c1_renamed, now + 200);
        assert_eq!(
            unv_later.get("failure_code"),
            Some(&JsonVal::Str("firewall_apply_failed".to_string()))
        );
        assert!(g.alerts_at(&c1_renamed, now + 200).is_empty());

        // retire_exited_from_proc removes exited PID record and table:
        let proc_dir = dir.join("proc");
        fs::create_dir_all(&proc_dir).unwrap();
        g.retire_exited_from_proc(&proc_dir).unwrap();
        g.with_inner(|inner| {
            assert!(inner.records.is_empty());
        });

        // AdmissionController batch overlap conflict fails both containers closed:
        let ctrl = AdmissionController::new(Arc::clone(&g));
        let ca = ContainerDescriptor::new("incus", "default", "ct-a");
        let cb = ContainerDescriptor::new("incus", "default", "ct-b");
        ctrl.run_batch(
            &[ca.clone(), cb.clone()],
            |c| {
                Ok(ContainerSnapshot {
                    instance_id: if c.name == "ct-a" {
                        "a".repeat(36)
                    } else {
                        "b".repeat(36)
                    },
                    ips: vec!["10.9.0.50".to_string()],
                    interfaces: vec!["br-shared".to_string()],
                    epoch: "boot:net:100".to_string(),
                    flows: BTreeSet::new(),
                    inbound: Vec::new(),
                    listening_ports: Vec::new(),
                    pid: Some(100),
                    observed_at: now + 300,
                    shared_network: false,
                })
            },
            now + 300,
        );
        assert_eq!(
            g.status_at(&ca, now + 300).get("failure_code"),
            Some(&JsonVal::Str("ambiguous_ownership".to_string()))
        );
        assert_eq!(
            g.status_at(&cb, now + 300).get("failure_code"),
            Some(&JsonVal::Str("ambiguous_ownership".to_string()))
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
