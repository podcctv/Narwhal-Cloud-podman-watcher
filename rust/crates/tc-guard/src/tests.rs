use super::*;
use std::collections::VecDeque;

fn temp_dir(label: &str) -> PathBuf {
    let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = env::temp_dir().join(format!(
        "narwhal_tc_guard_{label}_{}_{seq}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

const HOST: &str = "node-a";
const NODE: &str = "enrollment-a";

fn base_policy_json() -> &'static str {
    r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","revision":1,"limits":[{"scope":"host","interface":"eth0","upload_mbps":50,"download_mbps":80}]}"#
}

#[derive(Default)]
struct MockRunner {
    cmd_log: Vec<Vec<String>>,
    handler: Option<Box<dyn FnMut(&[&str], usize) -> (i32, String)>>,
    bins: HashMap<String, String>,
    ifindices: HashMap<String, Result<u32, String>>,
    netns: HashMap<u32, Result<u64, NetnsError>>,
    proc_stats: HashMap<u32, Result<String, String>>,
    texts: HashMap<PathBuf, String>,
    dirs: HashMap<PathBuf, Vec<String>>,
    links: HashMap<PathBuf, String>,
    now: u64,
}

impl MockRunner {
    fn new(now: u64) -> Self {
        Self {
            now,
            ..Default::default()
        }
    }
}

impl TcRunner for MockRunner {
    fn run_cmd(&mut self, args: &[&str], output_limit: usize) -> (i32, String) {
        self.cmd_log
            .push(args.iter().map(|s| (*s).to_string()).collect());
        if let Some(ref mut f) = self.handler {
            f(args, output_limit)
        } else {
            (1, "unmocked command".to_string())
        }
    }

    fn which(&mut self, binary: &str) -> Option<String> {
        self.bins.get(binary).cloned()
    }

    fn host_ifindex(&mut self, interface: &str) -> Result<u32, String> {
        self.ifindices
            .get(interface)
            .cloned()
            .unwrap_or_else(|| Err("not found".to_string()))
    }

    fn netns_inode(&mut self, pid: u32) -> Result<u64, NetnsError> {
        self.netns
            .get(&pid)
            .cloned()
            .unwrap_or(Err(NetnsError::NotFound))
    }

    fn read_proc_stat(&mut self, pid: u32) -> Result<String, String> {
        self.proc_stats
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| Err("not found".to_string()))
    }

    fn read_text(&mut self, path: &Path) -> std::io::Result<String> {
        self.texts.get(path).cloned().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "mock file not found")
        })
    }

    fn list_dir(&mut self, path: &Path) -> std::io::Result<Vec<String>> {
        self.dirs.get(path).cloned().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "mock dir not found")
        })
    }

    fn read_link_basename(&mut self, path: &Path) -> std::io::Result<String> {
        self.links.get(path).cloned().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "mock symlink not found")
        })
    }

    fn now_unix(&self) -> u64 {
        self.now
    }
}

// --- 1. Policy validation tests ---

#[test]
fn test_validate_policy_accepts_valid_host_and_defaults_auto_throttle() {
    let p = validate_policy(base_policy_json(), HOST, NODE).expect("valid host policy");
    assert_eq!(p.schema, 1);
    assert_eq!(p.revision, 1);
    assert!(p.auto_throttle_enabled);
    assert_eq!(p.limits.len(), 1);
    assert_eq!(p.limits[0].scope, Scope::Host);
    assert_eq!(p.limits[0].interface, "eth0");
    assert_eq!(p.limits[0].upload_mbps, 50);
    assert_eq!(p.limits[0].download_mbps, 80);
}

#[test]
fn test_validate_policy_rejects_identity_schema_and_rate_errors() {
    // Host/node mismatch
    let bad_node = r#"{"schema":1,"host_id":"node-a","expected_node_id":"other","limits":[]}"#;
    assert_eq!(
        validate_policy(bad_node, HOST, NODE).unwrap_err().message(),
        "bandwidth policy host identity mismatch"
    );
    // Schema != 1 (float 1.0 or 2 or bool)
    for bad_schema in [
        r#"{"schema":2,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[]}"#,
        r#"{"schema":1.0,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[]}"#,
        r#"{"schema":true,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[]}"#,
    ] {
        assert_eq!(
            validate_policy(bad_schema, HOST, NODE)
                .unwrap_err()
                .message(),
            "unsupported bandwidth policy"
        );
    }
    // Float rate 1.0 rejected (strict int check matching Python `type(v) is int`)
    let float_rate = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0","upload_mbps":1.0,"download_mbps":80}]}"#;
    assert_eq!(
        validate_policy(float_rate, HOST, NODE)
            .unwrap_err()
            .message(),
        "invalid rate"
    );
    // Bool rate rejected
    let bool_rate = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0","upload_mbps":true,"download_mbps":80}]}"#;
    assert_eq!(
        validate_policy(bool_rate, HOST, NODE)
            .unwrap_err()
            .message(),
        "invalid rate"
    );
    // Out of range (> 100_000 Mbps)
    let over_rate = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0","upload_mbps":100001,"download_mbps":0}]}"#;
    assert_eq!(
        validate_policy(over_rate, HOST, NODE)
            .unwrap_err()
            .message(),
        "rate is outside the supported range"
    );
    // Both zero
    let zero_rates = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0","upload_mbps":0,"download_mbps":0}]}"#;
    assert_eq!(
        validate_policy(zero_rates, HOST, NODE)
            .unwrap_err()
            .message(),
        "at least one direction needs a non-zero rate"
    );
}

#[test]
fn test_validate_policy_limits_count_and_interfaces_and_runtimes() {
    // Max 256 policies
    let mut items = Vec::new();
    for i in 0..257 {
        items.push(format!(
            r#"{{"scope":"container","runtime":"podman","project":"","container_name":"c{i}","container_id":"id{i}","upload_mbps":10,"download_mbps":0}}"#
        ));
    }
    let too_many = format!(
        r#"{{"schema":1,"host_id":"{HOST}","expected_node_id":"{NODE}","limits":[{}]}}"#,
        items.join(",")
    );
    assert_eq!(
        validate_policy(&too_many, HOST, NODE)
            .unwrap_err()
            .message(),
        "invalid bandwidth policy list"
    );

    // Invalid host interface (> 15 chars or bad char)
    let bad_iface = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0_too_long_16","upload_mbps":10,"download_mbps":10}]}"#;
    assert_eq!(
        validate_policy(bad_iface, HOST, NODE)
            .unwrap_err()
            .message(),
        "invalid host interface"
    );

    // Reject unsupported runtime (`docker`)
    let bad_rt = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"container","runtime":"docker","project":"","container_name":"c1","container_id":"abc","upload_mbps":10,"download_mbps":0}],"auto_throttle":{"enabled":false}}"#;
    assert_eq!(
        validate_policy(bad_rt, HOST, NODE).unwrap_err().message(),
        "only Incus, Podman, and Runman containers can be limited"
    );

    // Accept incus, podman, runman
    for rt in ["incus", "podman", "runman"] {
        let ok_rt = format!(
            r#"{{"schema":1,"host_id":"{HOST}","expected_node_id":"{NODE}","limits":[{{"scope":"container","runtime":"{rt}","project":"default","container_name":"vm-1","container_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","upload_mbps":5,"download_mbps":10}}],"auto_throttle":{{"enabled":false}}}}"#
        );
        let parsed = validate_policy(&ok_rt, HOST, NODE).expect("supported runtime");
        assert_eq!(parsed.limits[0].runtime, rt);
    }

    // Duplicate target
    let dup = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0","upload_mbps":10,"download_mbps":0},{"scope":"host","interface":"eth0","upload_mbps":20,"download_mbps":0}]}"#;
    assert_eq!(
        validate_policy(dup, HOST, NODE).unwrap_err().message(),
        "duplicate bandwidth target"
    );

    // Multiple host interfaces
    let two_hosts = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[{"scope":"host","interface":"eth0","upload_mbps":10,"download_mbps":0},{"scope":"host","interface":"eth1","upload_mbps":20,"download_mbps":0}]}"#;
    assert_eq!(
        validate_policy(two_hosts, HOST, NODE)
            .unwrap_err()
            .message(),
        "only one host interface can be configured"
    );

    // auto_throttle enabled requires 1 host limit
    let auto_no_host = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[],"auto_throttle":{"enabled":true}}"#;
    assert_eq!(
        validate_policy(auto_no_host, HOST, NODE)
            .unwrap_err()
            .message(),
        "automatic container limiting requires one host bandwidth interface"
    );
}

// --- 2. Handle determinism & /proc/stat parsing ---

#[test]
fn test_filter_handle_determinism_matches_python_sha256_contract() {
    assert_eq!(filter_handle("node-a:host:eth0", Direction::Download), "0x6f3bc15e");
    assert_eq!(filter_handle("node-a:host:eth0", Direction::Upload), "0x691d5461");
    assert_eq!(
        filter_handle_str("node-a:container:podman\0\0proxy\0abc123", "download"),
        "0x6ce74db8"
    );
    assert_ne!(
        filter_handle("node-a:host:eth0", Direction::Download),
        filter_handle("node-a:host:eth1", Direction::Download)
    );
}

#[test]
fn test_parse_proc_start_ticks_handles_spaces_in_comm() {
    let mut parts = vec!["S"];
    parts.extend(std::iter::repeat("0").take(18));
    parts.push("987654");
    let stat = format!("12 (a process (with) spaces) {}", parts.join(" "));
    assert_eq!(parse_proc_start_ticks(&stat).unwrap(), "987654");
    assert!(parse_proc_start_ticks("12 malformed").is_err());
}

// --- 3. tc command generation & output parsing ---

#[test]
fn test_tc_command_generation_and_listing_parsing() {
    let cmd = build_tc_filter_command(
        &["nsenter".into(), "--target".into(), "42".into(), "--net".into()],
        "eth0",
        Direction::Download,
        "add",
        49150,
        "0x6f3bc15e",
        80,
    );
    assert_eq!(
        cmd,
        vec![
            "nsenter", "--target", "42", "--net", "tc", "filter", "add", "dev", "eth0",
            "ingress", "protocol", "all", "pref", "49150", "handle", "0x6f3bc15e",
            "matchall", "action", "police", "rate", "80mbit", "burst", "256k",
            "conform-exceed", "drop"
        ]
    );

    let upload_del =
        build_tc_filter_del_command(&[], "ens3", Direction::Upload, 49151, "0x691d5461");
    assert_eq!(
        upload_del,
        vec![
            "tc", "filter", "del", "dev", "ens3", "egress", "protocol", "all", "pref",
            "49151", "handle", "0x691d5461"
        ]
    );

    // Multi-filter tc output with foreign filter + owned filter
    let listing = "\
filter protocol all pref 49150 matchall chain 0 \n\
filter protocol all pref 49150 matchall chain 0 handle 0xdeadbeef \n\
  police 0x1 rate 100Mbit burst 256Kb mtu 2Kb action drop/pipe\n\
filter protocol all pref 49152 matchall chain 0 \n\
filter protocol all pref 49152 matchall chain 0 handle 0x6f3bc15e \n\
  police 0x2 rate 80Mbit burst 256Kb mtu 2Kb action drop/pipe\n";

    assert!(filter_present(listing, "0x6f3bc15e", 49152));
    assert!(!filter_present(listing, "0x6f3bc15e", 49150));
    assert_eq!(filter_preference(listing, "0x6f3bc15e"), Some(49152));
    assert_eq!(filter_preference(listing, "0x60000000"), None);
    assert!(filter_has_police_action(listing, "0x6f3bc15e", 49152, Some(80)));
    assert!(!filter_has_police_action(listing, "0x6f3bc15e", 49152, Some(50)));
    assert!(!filter_has_police_action(listing, "0x6f3bc15e", 49150, Some(100)));

    let occ = occupied_preferences(listing);
    assert!(occ.contains(&49150));
    assert!(occ.contains(&49152));
    assert_eq!(next_free_preference(listing, Direction::Download, None), 49151);
    assert_eq!(next_free_preference(listing, Direction::Upload, None), 49151);
}

#[test]
fn test_parse_police_rate_units_and_precision() {
    let gbit = "filter protocol all pref 49150 matchall handle 0x6f3bc15e\n  police 0x1 rate 1Gbit burst 256Kb";
    assert!(filter_has_police_action(gbit, "0x6f3bc15e", 49150, Some(1000)));

    let kbit = "filter protocol all pref 49150 matchall handle 0x6f3bc15e\n  police 0x1 rate 1500Kbit/s burst 256Kb";
    let parsed = parse_police_rate_mbps(kbit).expect("parsed rate");
    assert!((parsed - 1.5).abs() < 1e-6);

    let bps = "filter protocol all pref 49150 matchall handle 0x6f3bc15e\n  police 0x1 rate 80Mbps burst 256Kb";
    assert!(filter_has_police_action(bps, "0x6f3bc15e", 49150, Some(80)));
    assert!(!filter_has_police_action(bps, "0x6f3bc15e", 49150, Some(81)));
}

#[test]
fn test_apply_filter_retries_eexist_collision_and_verifies_readback() {
    let mut runner = MockRunner::new(1000);
    let handle = filter_handle("node-a:host:eth0", Direction::Download);
    let mut add_attempts = 0usize;
    let expected_handle = handle.clone();

    runner.handler = Some(Box::new(move |args, _| {
        if args == ["tc", "qdisc", "show", "dev", "eth0"] {
            return (0, "qdisc clsact ffff: parent ffff:fff1".to_string());
        }
        if args == ["tc", "filter", "show", "dev", "eth0", "ingress"] {
            return match add_attempts {
                0 => (0, String::new()),
                1 => (
                    0,
                    "filter protocol all pref 49150 matchall handle 0xdeadbeef\n  police 0x1 rate 100Mbit burst 256Kb"
                        .to_string(),
                ),
                _ => (
                    0,
                    format!(
                        "filter protocol all pref 49151 matchall handle {expected_handle}\n  police 0x1 rate 80Mbit burst 256Kb"
                    ),
                ),
            };
        }
        if args[0] == "tc" && args[1] == "filter" && args[2] == "add" {
            add_attempts += 1;
            if add_attempts == 1 {
                return (2, "Error: NLM_F_EXCL: File exists".to_string());
            }
            return (0, String::new());
        }
        (1, "unexpected".to_string())
    }));

    let pref = apply_filter(
        &[],
        "eth0",
        "node-a:host:eth0",
        Direction::Download,
        80,
        false,
        None,
        &mut runner,
    )
    .expect("retried to 49151");
    assert_eq!(pref, 49151);
    let adds = runner
        .cmd_log
        .iter()
        .filter(|c| c.get(2).map(String::as_str) == Some("add"))
        .count();
    assert_eq!(adds, 2);
}

#[test]
fn test_apply_filter_refuses_unowned_existing_handle_and_handles_change_eexist() {
    let handle = filter_handle("node-a:host:eth0", Direction::Download);

    // 1. Existing handle when previously_owned == false -> refused
    let mut runner = MockRunner::new(1000);
    let h1 = handle.clone();
    runner.handler = Some(Box::new(move |args, _| {
        if args == ["tc", "qdisc", "show", "dev", "eth0"] {
            return (0, "qdisc clsact ffff:".to_string());
        }
        if args == ["tc", "filter", "show", "dev", "eth0", "ingress"] {
            return (
                0,
                format!("filter protocol all pref 49150 matchall handle {h1}\n  police 0x1 rate 80Mbit"),
            );
        }
        (1, "unexpected".into())
    }));
    let err = apply_filter(
        &[],
        "eth0",
        "node-a:host:eth0",
        Direction::Download,
        80,
        false,
        None,
        &mut runner,
    )
    .unwrap_err();
    assert_eq!(
        err.message(),
        "reserved filter identity already exists; left unchanged"
    );

    // 2. Owned handle updated via `tc filter change` returning EEXIST -> verified via readback
    let mut runner2 = MockRunner::new(1000);
    let h2 = handle.clone();
    runner2.handler = Some(Box::new(move |args, _| {
        if args == ["tc", "qdisc", "show", "dev", "eth0"] {
            return (0, "qdisc clsact ffff:".to_string());
        }
        if args == ["tc", "filter", "show", "dev", "eth0", "ingress"] {
            return (
                0,
                format!("filter protocol all pref 49150 matchall handle {h2}\n  police 0x1 rate 60Mbit"),
            );
        }
        if args[0] == "tc" && args[1] == "filter" && args[2] == "change" {
            return (2, "RTNETLINK answers: File exists".to_string());
        }
        (1, "unexpected".into())
    }));
    let pref = apply_filter(
        &[],
        "eth0",
        "node-a:host:eth0",
        Direction::Download,
        60,
        true,
        Some(49150),
        &mut runner2,
    )
    .expect("verified change EEXIST via readback");
    assert_eq!(pref, 49150);
}

// --- 4. Auto-throttle tier state machine & recovery ---

#[test]
fn test_auto_tier_rates_and_advance_direction_escalation_and_recovery() {
    assert_eq!(auto_tier_rates(100), vec![50, 25, 5, 1]);
    assert_eq!(auto_tier_rates(20), vec![10, 5, 1]);
    assert_eq!(auto_tier_rates(10), vec![5, 2, 1]);
    assert_eq!(auto_tier_rates(2), vec![1]);
    assert_eq!(auto_tier_rates(1), Vec::<u32>::new());
    assert_eq!(auto_tier_rates(100_000), vec![50_000, 25_000, 5_000, 1]);

    let mut rec = DirectionThrottleState::default();
    // Below 80% threshold (79 Mbps < 80 Mbps): stays at stage 0
    advance_direction(&mut rec, 100, 79.9, 1000, 300);
    assert_eq!(rec.stage, 0);
    assert_eq!(rec.high_seconds, 0);

    // First 200s >= 80%: accumulates high_seconds without triggering yet
    advance_direction(&mut rec, 100, 80.0, 1200, 200);
    assert_eq!(rec.stage, 0);
    assert_eq!(rec.high_seconds, 200);

    // Next 100s >= 80% -> 300s total -> triggers Stage 1 (50 Mbps)
    advance_direction(&mut rec, 100, 85.0, 1300, 100);
    assert_eq!(rec.stage, 1);
    assert_eq!(rec.high_seconds, 0);
    assert_eq!(rec.low_seconds, 0);

    // Sustained >= 80% of 50 (40 Mbps) for 300s -> Stage 2 (25 Mbps)
    advance_direction(&mut rec, 100, 42.0, 1600, 300);
    assert_eq!(rec.stage, 2);

    // Sustained >= 80% of 25 (20 Mbps) for 300s -> Stage 3 (5 Mbps)
    advance_direction(&mut rec, 100, 21.0, 1900, 300);
    assert_eq!(rec.stage, 3);

    // Sustained >= 80% of 5 (4 Mbps) for 300s -> Stage 4 (1 Mbps min)
    advance_direction(&mut rec, 100, 4.0, 2200, 300);
    assert_eq!(rec.stage, 4);

    // Dip to 0.4 Mbps (< 50% of 1 = 0.5 Mbps): needs 600s to step down
    advance_direction(&mut rec, 100, 0.4, 2500, 300);
    assert_eq!(rec.stage, 4);
    assert_eq!(rec.low_seconds, 300);

    // Spike to 0.6 Mbps resets low_seconds
    advance_direction(&mut rec, 100, 0.6, 2600, 100);
    assert_eq!(rec.stage, 4);
    assert_eq!(rec.low_seconds, 0);

    // Sustained 600s below recovery threshold steps back down 4 -> 3 -> 2 -> 1 -> 0
    advance_direction(&mut rec, 100, 0.2, 2900, 300);
    advance_direction(&mut rec, 100, 0.2, 3200, 300);
    assert_eq!(rec.stage, 3);
    advance_direction(&mut rec, 100, 1.0, 3800, 600);
    assert_eq!(rec.stage, 2);
    advance_direction(&mut rec, 100, 10.0, 4400, 600);
    assert_eq!(rec.stage, 1);
    advance_direction(&mut rec, 100, 20.0, 5000, 600);
    assert_eq!(rec.stage, 0);

    // Changing base_mbps resets stage cleanly
    advance_direction(&mut rec, 100, 90.0, 5300, 300);
    assert_eq!(rec.stage, 1);
    advance_direction(&mut rec, 200, 10.0, 5600, 300);
    assert_eq!(rec.stage, 0);
    assert_eq!(rec.base_mbps, Some(200));
}

// --- 5. Atomic JSON state persistence & last_status_json ---

#[test]
fn test_atomic_state_persistence_and_last_status_json() {
    let dir = temp_dir("state");
    let path = dir.join("nested").join("manual-bandwidth-limits.json");

    // Missing file -> unconfigured default
    let initial_status = last_status_json(&path);
    let parsed = JsonValue::parse(&initial_status).expect("valid json");
    assert_eq!(parsed.get("state").and_then(JsonValue::as_str), Some("unconfigured"));
    assert_eq!(parsed.get("revision").and_then(JsonValue::as_strict_i64), Some(0));

    // Corrupt file -> falls back cleanly
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "{not-valid-json").unwrap();
    assert_eq!(read_state(&path).entries.len(), 0);

    // Wrong schema -> falls back cleanly
    fs::write(&path, r#"{"schema":2,"entries":{"a":{}}}"#).unwrap();
    assert_eq!(read_state(&path).entries.len(), 0);

    // Persist valid state & read back
    let mut st = BandwidthState::default();
    st.host_id = HOST.to_string();
    st.expected_node_id = NODE.to_string();
    st.revision = 7;
    st.status = Some(
        ReconcileStatus {
            revision: 7,
            state: "applied".to_string(),
            ..Default::default()
        }
        .to_json_val(),
    );
    write_state_atomic(&path, &st).expect("atomic write");
    let loaded = read_state(&path);
    assert_eq!(loaded.revision, 7);
    let status_after = JsonValue::parse(&last_status_json(&path)).unwrap();
    assert_eq!(status_after.get("state").and_then(JsonValue::as_str), Some("applied"));
    assert_eq!(status_after.get("revision").and_then(JsonValue::as_strict_i64), Some(7));

    #[cfg(unix)]
    {
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let _ = fs::remove_dir_all(&dir);
}

// --- 6. End-to-end reconcile_with_runner & reconcile_live tests ---

#[test]
fn test_reconcile_apply_update_remove_host_only_uses_owned_filters() {
    let dir = temp_dir("host_apply_remove");
    let state_path = dir.join("state.json");
    let mut runner = MockRunner::new(2000);
    runner.ifindices.insert("eth0".to_string(), Ok(2));

    let dl_handle = filter_handle("node-a:host:eth0", Direction::Download);
    let ul_handle = filter_handle("node-a:host:eth0", Direction::Upload);

    let mut ingress_listing = String::new();
    let mut egress_listing = String::new();
    let mut has_clsact = false;

    let dl_h = dl_handle.clone();
    let ul_h = ul_handle.clone();
    let state_ref = std::cell::RefCell::new((has_clsact, ingress_listing.clone(), egress_listing.clone()));

    runner.handler = Some(Box::new(move |args, _| {
        let mut s = state_ref.borrow_mut();
        if args == ["tc", "qdisc", "show", "dev", "eth0"] {
            return if s.0 {
                (0, "qdisc clsact ffff:".to_string())
            } else {
                (0, "qdisc noqueue 0: root".to_string())
            };
        }
        if args == ["tc", "qdisc", "add", "dev", "eth0", "clsact"] {
            s.0 = true;
            return (0, String::new());
        }
        if args == ["tc", "filter", "show", "dev", "eth0", "ingress"] {
            return (0, s.1.clone());
        }
        if args == ["tc", "filter", "show", "dev", "eth0", "egress"] {
            return (0, s.2.clone());
        }
        if args.len() >= 16 && args[0] == "tc" && args[1] == "filter" && (args[2] == "add" || args[2] == "change") {
            let dir = args[5];
            let pref = args[9];
            let handle = args[11];
            let rate = args[16];
            let block = format!("filter protocol all pref {pref} matchall handle {handle}\n  police 0x1 rate {rate} burst 256Kb\n");
            if dir == "ingress" {
                assert_eq!(handle, dl_h);
                s.1 = block;
            } else {
                assert_eq!(handle, ul_h);
                s.2 = block;
            }
            return (0, String::new());
        }
        if args.len() >= 12 && args[0] == "tc" && args[1] == "filter" && args[2] == "del" {
            let dir = args[5];
            if dir == "ingress" {
                s.1.clear();
            } else {
                s.2.clear();
            }
            return (0, String::new());
        }
        (1, format!("unexpected command: {args:?}"))
    }));
    let _ = (&mut has_clsact, &mut ingress_listing, &mut egress_listing);

    let policy_no_auto = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","revision":1,"limits":[{"scope":"host","interface":"eth0","upload_mbps":50,"download_mbps":80}],"auto_throttle":{"enabled":false}}"#;
    let res = reconcile_with_runner(
        &ReconcileRequest {
            policy_json: policy_no_auto,
            host_id: HOST,
            node_id: NODE,
            containers: &[],
            state_path: &state_path,
            traffic_samples: &[],
            sample_at: 0,
            sample_interval_seconds: 300,
            bridge_inventory: &[],
        },
        &mut runner,
    );
    assert_eq!(res.state, "applied");
    assert_eq!(res.items.len(), 2);
    let active = res.active_limits.as_ref().unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].upload_mbps, 50);
    assert_eq!(active[0].download_mbps, 80);

    // Verify persisted JSON
    let saved = read_state(&state_path);
    assert_eq!(saved.entries["host:eth0"].directions, vec!["download", "upload"]);

    // Now clear limits -> removes only owned filters and becomes unconfigured
    let empty_policy = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","revision":2,"limits":[]}"#;
    let res2 = reconcile_with_runner(
        &ReconcileRequest {
            policy_json: empty_policy,
            host_id: HOST,
            node_id: NODE,
            containers: &[],
            state_path: &state_path,
            traffic_samples: &[],
            sample_at: 0,
            sample_interval_seconds: 300,
            bridge_inventory: &[],
        },
        &mut runner,
    );
    assert_eq!(res2.state, "unconfigured");
    assert!(read_state(&state_path).entries.is_empty());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_reconcile_container_rejects_shared_netns_and_applies_isolated_runman() {
    let dir = temp_dir("container_isolation");
    let state_path = dir.join("state.json");
    let vm_id = "11111111-2222-3333-4444-555555555555";
    let gen1 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let gen2 = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";

    let policy = format!(
        r#"{{"schema":1,"host_id":"{HOST}","expected_node_id":"{NODE}","revision":1,"limits":[{{"scope":"container","runtime":"runman","project":"default","container_name":"{vm_id}","container_id":"{gen1}","upload_mbps":5,"download_mbps":10}}],"auto_throttle":{{"enabled":false}}}}"#
    );

    let mut runner = MockRunner::new(3000);
    runner.netns.insert(1, Ok(1));
    runner.netns.insert(42, Ok(42));
    runner.netns.insert(43, Ok(42)); // shares netns 42!
    runner.proc_stats.insert(
        42,
        Ok(format!("42 (vm) S {} 987654", vec!["0"; 18].join(" "))),
    );

    let shared_containers = vec![
        ContainerInput {
            runtime: "runman".into(),
            runtime_bin: "runman".into(),
            project: "default".into(),
            name: vm_id.into(),
            id: vm_id.into(),
            instance_id: gen1.into(),
            status: "running".into(),
            pid: Some(42),
        },
        ContainerInput {
            runtime: "runman".into(),
            runtime_bin: "runman".into(),
            project: "default".into(),
            name: "other-vm".into(),
            id: "other-vm".into(),
            instance_id: gen2.into(),
            status: "running".into(),
            pid: Some(43),
        },
    ];

    let fail_res = reconcile_with_runner(
        &ReconcileRequest {
            policy_json: &policy,
            host_id: HOST,
            node_id: NODE,
            containers: &shared_containers,
            state_path: &state_path,
            traffic_samples: &[],
            sample_at: 0,
            sample_interval_seconds: 300,
            bridge_inventory: &[],
        },
        &mut runner,
    );
    assert_eq!(fail_res.state, "failed");
    assert!(fail_res.items[0]
        .message
        .as_deref()
        .unwrap()
        .contains("shared container network namespace"));
    assert!(runner.cmd_log.is_empty());

    // Now isolate peer 43 onto netns 43 and verify tc is applied inside container netns
    runner.netns.insert(43, Ok(43));
    let owner_key = format!("{HOST}:container:runman\0default\0{vm_id}\0{gen1}");
    let dl_h = filter_handle(&owner_key, Direction::Download);
    let ul_h = filter_handle(&owner_key, Direction::Upload);
    let tc_state = std::cell::RefCell::new((false, String::new(), String::new()));

    runner.handler = Some(Box::new(move |args, _| {
        let mut s = tc_state.borrow_mut();
        if args == ["nsenter", "--target", "42", "--net", "ip", "-j", "route", "show", "default"] {
            return (0, r#"[{"dev":"eth0"}]"#.to_string());
        }
        if args == ["nsenter", "--target", "42", "--net", "ip", "-j", "link", "show", "dev", "eth0"] {
            return (0, r#"[{"ifindex":2,"link_index":7}]"#.to_string());
        }
        if args == ["nsenter", "--target", "42", "--net", "tc", "qdisc", "show", "dev", "eth0"] {
            return (0, if s.0 { "qdisc clsact".into() } else { "qdisc noqueue".into() });
        }
        if args == ["nsenter", "--target", "42", "--net", "tc", "qdisc", "add", "dev", "eth0", "clsact"] {
            s.0 = true;
            return (0, String::new());
        }
        if args == ["nsenter", "--target", "42", "--net", "tc", "filter", "show", "dev", "eth0", "ingress"] {
            return (0, s.1.clone());
        }
        if args == ["nsenter", "--target", "42", "--net", "tc", "filter", "show", "dev", "eth0", "egress"] {
            return (0, s.2.clone());
        }
        if args.len() >= 20 && args[4] == "tc" && args[5] == "filter" && args[6] == "add" {
            let dir = args[9];
            let pref = args[13];
            let handle = args[15];
            let rate = args[20];
            let block = format!("filter protocol all pref {pref} matchall handle {handle}\n  police 0x1 rate {rate} burst 256Kb\n");
            if dir == "ingress" {
                assert_eq!(handle, dl_h);
                s.1 = block;
            } else {
                assert_eq!(handle, ul_h);
                s.2 = block;
            }
            return (0, String::new());
        }
        (1, format!("unexpected: {args:?}"))
    }));

    let ok_res = reconcile_with_runner(
        &ReconcileRequest {
            policy_json: &policy,
            host_id: HOST,
            node_id: NODE,
            containers: &shared_containers,
            state_path: &state_path,
            traffic_samples: &[],
            sample_at: 0,
            sample_interval_seconds: 300,
            bridge_inventory: &[],
        },
        &mut runner,
    );
    assert_eq!(ok_res.state, "applied");
    assert_eq!(ok_res.items.len(), 2);
    assert_eq!(ok_res.active_limits.as_ref().unwrap()[0].download_mbps, 10);
    assert_eq!(ok_res.active_limits.as_ref().unwrap()[0].upload_mbps, 5);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_reconcile_auto_throttle_maps_runman_bridge_and_applies_tier1() {
    let dir = temp_dir("auto_bridge");
    let state_path = dir.join("state.json");
    let vm_id = "11111111-2222-3333-4444-555555555555";
    let gen1 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    let policy = format!(
        r#"{{"schema":1,"host_id":"{HOST}","expected_node_id":"{NODE}","revision":1,"limits":[{{"scope":"host","interface":"eth0","upload_mbps":20,"download_mbps":20}}],"auto_throttle":{{"enabled":true}}}}"#
    );
    let containers = vec![ContainerInput {
        runtime: "runman".into(),
        runtime_bin: "runman".into(),
        project: "default".into(),
        name: vm_id.into(),
        id: vm_id.into(),
        instance_id: gen1.into(),
        status: "running".into(),
        pid: Some(42),
    }];
    let samples = vec![TrafficSampleInput {
        runtime: "runman".into(),
        project: "default".into(),
        container_name: vm_id.into(),
        container_id: gen1.into(),
        traffic_counters_available: true,
        net_tx_bps: Some(3_000_000.0), // 24 Mbps >= 80% of 20 Mbps
        net_rx_bps: Some(0.0),
    }];
    let bridges = vec![BridgeInterfaceInput {
        name: "rmbr0".into(),
        kind: "bridge".into(),
        runtimes: vec!["runman".into()],
    }];

    let mut runner = MockRunner::new(1000);
    runner.ifindices.insert("eth0".into(), Ok(2));
    runner.netns.insert(1, Ok(1));
    runner.netns.insert(42, Ok(42));
    runner.proc_stats.insert(
        42,
        Ok(format!("42 (vm) S {} 987654", vec!["0"; 18].join(" "))),
    );

    let tc_map = std::cell::RefCell::new(HashMap::<String, String>::new());
    runner.handler = Some(Box::new(move |args, _| {
        if args == ["ip", "-j", "link", "show"] {
            return (
                0,
                r#"[{"ifindex":2,"ifname":"eth0"},{"ifindex":7,"ifname":"rv1","master":"rmbr0"}]"#
                    .to_string(),
            );
        }
        if args == ["ip", "-j", "route", "show", "default"] {
            return (0, r#"[{"dev":"eth0"}]"#.to_string());
        }
        if args == ["nsenter", "--target", "42", "--net", "ip", "-j", "route", "show", "default"] {
            return (0, r#"[{"dev":"eth0"}]"#.to_string());
        }
        if args == ["nsenter", "--target", "42", "--net", "ip", "-j", "link", "show", "dev", "eth0"] {
            return (0, r#"[{"ifindex":3,"link_index":7}]"#.to_string());
        }
        if args.ends_with(&["tc", "qdisc", "show", "dev", "eth0"]) {
            return (0, "qdisc clsact ffff:".to_string());
        }
        if args.len() >= 6 && args.contains(&"filter") && args.contains(&"show") {
            let key = args.join(" ");
            return (0, tc_map.borrow().get(&key).cloned().unwrap_or_default());
        }
        if let Some(pos) = args.iter().position(|&x| x == "add") {
            if pos > 0 && args[pos - 1] == "filter" {
                let dev = args[pos + 2];
                let dir = args[pos + 3];
                let pref = args[pos + 7];
                let handle = args[pos + 9];
                let rate = args[pos + 14];
                let show_key = if args[0] == "nsenter" {
                    format!("nsenter --target 42 --net tc filter show dev {dev} {dir}")
                } else {
                    format!("tc filter show dev {dev} {dir}")
                };
                tc_map.borrow_mut().insert(
                    show_key,
                    format!("filter protocol all pref {pref} matchall handle {handle}\n  police 0x1 rate {rate} burst 256Kb\n"),
                );
                return (0, String::new());
            }
        }
        (1, format!("unexpected: {args:?}"))
    }));

    let res = reconcile_with_runner(
        &ReconcileRequest {
            policy_json: &policy,
            host_id: HOST,
            node_id: NODE,
            containers: &containers,
            state_path: &state_path,
            traffic_samples: &samples,
            sample_at: 1000,
            sample_interval_seconds: 300,
            bridge_inventory: &bridges,
        },
        &mut runner,
    );
    assert_eq!(res.state, "applied");
    let auto = res.auto_throttle.as_ref().unwrap();
    assert_eq!(auto.state, "limited");
    assert_eq!(auto.mapped_containers, Some(1));
    assert_eq!(auto.items[0].container_id, gen1);
    assert_eq!(auto.items[0].upload_mbps, 10);

    let container_active = res
        .active_limits
        .as_ref()
        .unwrap()
        .iter()
        .find(|a| a.scope == "container")
        .expect("auto container limit applied");
    assert_eq!(container_active.upload_mbps, 10);
    assert_eq!(container_active.download_mbps, 0);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_reconcile_partial_cleanup_failure_rolls_back_and_blocks_replacement() {
    let dir = temp_dir("partial_cleanup");
    let state_path = dir.join("state.json");

    // Pre-populate state with an owned host:eth0 filter at interface_index 2
    let mut init_state = BandwidthState::default();
    init_state.host_id = HOST.to_string();
    init_state.expected_node_id = NODE.to_string();
    let mut rates = BTreeMap::new();
    rates.insert("download".into(), 80);
    rates.insert("upload".into(), 50);
    let mut prefs = BTreeMap::new();
    prefs.insert("download".into(), 49150);
    prefs.insert("upload".into(), 49151);
    let mut confirmed = BTreeMap::new();
    confirmed.insert("download".into(), 100);
    confirmed.insert("upload".into(), 100);
    init_state.entries.insert(
        "host:eth0".into(),
        StoredEntry {
            key: "host:eth0".into(),
            owner_key: "node-a:host:eth0".into(),
            expected_node_id: NODE.into(),
            scope: "host".into(),
            interface: "eth0".into(),
            interface_index: 2,
            namespace_inode: "host".into(),
            directions: vec!["download".into(), "upload".into()],
            rates_mbps: rates,
            filter_prefs: prefs,
            confirmed_at: confirmed,
            last_confirmed_at: 100,
            ..Default::default()
        },
    );
    write_state_atomic(&state_path, &init_state).unwrap();

    let dl_handle = filter_handle("node-a:host:eth0", Direction::Download);
    let ul_handle = filter_handle("node-a:host:eth0", Direction::Upload);

    let mut runner = MockRunner::new(2000);
    runner.ifindices.insert("eth0".into(), Ok(2));

    let mut script = VecDeque::from(vec![
        // remove download: show ingress (present), del ingress (ok), show ingress (gone)
        (0, format!("filter protocol all pref 49150 matchall handle {dl_handle}\n  police 0x1 rate 80Mbit")),
        (0, String::new()),
        (0, String::new()),
        // remove upload: show egress (present), del egress (fails!)
        (0, format!("filter protocol all pref 49151 matchall handle {ul_handle}\n  police 0x1 rate 50Mbit")),
        (1, "second direction failed".to_string()),
        // rollback download: qdisc show, filter show ingress (empty), filter add ingress (ok), filter show ingress (readback 80Mbit)
        (0, "qdisc clsact ffff:".to_string()),
        (0, String::new()),
        (0, String::new()),
        (0, format!("filter protocol all pref 49150 matchall handle {dl_handle}\n  police 0x1 rate 80Mbit")),
    ]);
    runner.handler = Some(Box::new(move |_, _| {
        script.pop_front().unwrap_or((1, "exhausted".into()))
    }));

    let empty_policy = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","revision":2,"limits":[]}"#;
    let res = reconcile_with_runner(
        &ReconcileRequest {
            policy_json: empty_policy,
            host_id: HOST,
            node_id: NODE,
            containers: &[],
            state_path: &state_path,
            traffic_samples: &[],
            sample_at: 0,
            sample_interval_seconds: 300,
            bridge_inventory: &[],
        },
        &mut runner,
    );
    assert_eq!(res.state, "failed");
    let rb = res.rollback.as_ref().unwrap();
    assert_eq!(rb.state, "verified");
    assert!(rb.attempted);
    assert_eq!(rb.results.as_ref().unwrap()[0].direction, "cleanup");
    assert!(read_state(&state_path).entries.contains_key("host:eth0"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_reconcile_live_rejects_invalid_policy_without_touching_state() {
    let dir = temp_dir("live_reject");
    let state_path = dir.join("missing.json");
    let res = reconcile_live(&ReconcileRequest {
        policy_json: r#"{"schema":1,"host_id":"other","expected_node_id":"enrollment-a","limits":[]}"#,
        host_id: HOST,
        node_id: NODE,
        containers: &[],
        state_path: &state_path,
        traffic_samples: &[],
        sample_at: 0,
        sample_interval_seconds: 300,
        bridge_inventory: &[],
    });
    assert_eq!(res.state, "rejected");
    assert!(!state_path.exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_merge_automatic_limits_respects_stricter_cap() {
    let manual = vec![NormalizedLimit {
        scope: Scope::Container,
        interface: String::new(),
        runtime: "podman".into(),
        project: "".into(),
        container_name: "c1".into(),
        container_id: "id1".into(),
        upload_mbps: 15,
        download_mbps: 40,
    }];
    let auto = vec![
        NormalizedLimit {
            scope: Scope::Container,
            interface: String::new(),
            runtime: "podman".into(),
            project: "".into(),
            container_name: "c1".into(),
            container_id: "id1".into(),
            upload_mbps: 20, // manual 15 is stricter
            download_mbps: 10, // auto 10 is stricter
        },
        NormalizedLimit {
            scope: Scope::Container,
            interface: String::new(),
            runtime: "incus".into(),
            project: "default".into(),
            container_name: "c2".into(),
            container_id: "c2".into(),
            upload_mbps: 5,
            download_mbps: 0,
        },
    ];
    let merged = merge_automatic_limits(&manual, &auto);
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].upload_mbps, 15);
    assert_eq!(merged[0].download_mbps, 10);
    assert_eq!(merged[1].container_name, "c2");
    assert_eq!(merged[1].upload_mbps, 5);
}

#[test]
fn test_sysfs_and_proc_route_fallbacks() {
    let mut runner = MockRunner::new(1000);
    runner.dirs.insert(
        PathBuf::from("/sys/class/net"),
        vec!["eth0".into(), "rv1".into(), "..".into()],
    );
    runner
        .texts
        .insert(PathBuf::from("/sys/class/net/eth0/ifindex"), "2\n".into());
    runner
        .texts
        .insert(PathBuf::from("/sys/class/net/rv1/ifindex"), "7\n".into());
    runner
        .links
        .insert(PathBuf::from("/sys/class/net/rv1/master"), "rmbr0".into());
    runner.texts.insert(
        PathBuf::from("/proc/net/route"),
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t01010101\t0003\t0\t0\t100\t00000000\n".into(),
    );
    runner.texts.insert(
        PathBuf::from("/proc/net/ipv6_route"),
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000064 00000000 00000000 00000003 eth1\n".into(),
    );

    let (links, defaults, err) = host_link_snapshot(&mut runner);
    assert!(err.is_empty());
    assert_eq!(links.get(&2).unwrap().ifname, "eth0");
    assert_eq!(links.get(&7).unwrap().master_name, "rmbr0");
    assert!(defaults.contains("eth0"));
    assert!(defaults.contains("eth1"));
}

#[test]
fn test_runman_identity_and_container_sample_conversion() {
    let vm_id = "11111111-2222-3333-4444-555555555555";
    let gen1 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let sample = ContainerSample {
        id: vm_id.into(),
        stable_id: vm_id.into(),
        name: vm_id.into(),
        image: "ubuntu".into(),
        runtime: "runman".into(),
        runtime_bin: "runman".into(),
        project: "default".into(),
        pid: Some(42),
        status: "running".into(),
        instance_id: gen1.into(),
        network_addresses: vec![],
        pid_metrics_json: None,
        socket_tables_json: None,
        cgroup_metrics_json: None,
    };
    let converted = ContainerInput::from(&sample);
    assert_eq!(
        converted.identity(),
        (
            "runman".into(),
            "default".into(),
            vm_id.into(),
            gen1.into()
        )
    );
}

#[test]
fn test_running_container_inventory_incus_podman_and_runman_strict() {
    let mut runner = MockRunner::new(1000);
    // Runman alone needs no external binary
    let runman_ok = vec![ContainerInput {
        runtime: "runman".into(),
        runtime_bin: "runman".into(),
        project: "default".into(),
        name: "vm".into(),
        id: "vm".into(),
        instance_id: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".into(),
        status: "running".into(),
        pid: Some(42),
    }];
    let peers = running_container_inventory(&runman_ok, &mut runner).expect("runman peer");
    assert_eq!(
        peers,
        vec![PeerEntry {
            runtime: "runman".into(),
            project: "default".into(),
            container_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            pid: 42,
        }]
    );

    let mut runman_bad = runman_ok.clone();
    runman_bad[0].pid = None;
    let err = running_container_inventory(&runman_bad, &mut runner).unwrap_err();
    assert!(err.message().contains("inventory is incomplete"));

    // Incus CSV + Podman ps/inspect
    let pod_id = "a".repeat(64);
    let pod_id_clone = pod_id.clone();
    let mut mixed_runner = MockRunner::new(1000);
    mixed_runner.bins.insert("incus".into(), "/usr/bin/incus".into());
    mixed_runner.bins.insert("podman".into(), "/usr/bin/podman".into());
    mixed_runner.handler = Some(Box::new(move |args, _| {
        if args == [
            "/usr/bin/incus",
            "list",
            "--all-projects",
            "type=container",
            "status=running",
            "--format=csv",
            "--columns=nepst",
        ] {
            return (0, "web,prod,55,RUNNING,CONTAINER\n".to_string());
        }
        if args == ["/usr/bin/podman", "ps", "--no-trunc", "--format", "{{.ID}}"] {
            return (0, pod_id_clone.clone());
        }
        if args[0] == "/usr/bin/podman" && args[1] == "inspect" {
            return (0, format!("{pod_id_clone}|66"));
        }
        (1, "unexpected".into())
    }));

    let mixed = running_container_inventory(&[], &mut mixed_runner).expect("mixed peers");
    assert_eq!(mixed.len(), 2);
    assert_eq!(mixed[0].runtime, "incus");
    assert_eq!(mixed[0].pid, 55);
    assert_eq!(mixed[1].runtime, "podman");
    assert_eq!(mixed[1].pid, 66);

    // Malformed Incus row rejected
    let mut bad_incus = MockRunner::new(1000);
    bad_incus.bins.insert("incus".into(), "/usr/bin/incus".into());
    bad_incus.handler = Some(Box::new(|_, _| {
        (0, "c1,other,43,STOPPED,CONTAINER\n".to_string())
    }));
    let err2 = running_container_inventory(&[], &mut bad_incus).unwrap_err();
    assert!(err2.message().contains("Incus inventory could not be verified"));
}

#[test]
fn test_podman_pid_fallback_and_container_isolation_errors() {
    let mut runner = MockRunner::new(1000);
    let item = NormalizedLimit {
        scope: Scope::Container,
        interface: String::new(),
        runtime: "podman".into(),
        project: String::new(),
        container_name: "proxy".into(),
        container_id: "abc123".into(),
        upload_mbps: 5,
        download_mbps: 10,
    };
    let matched = ContainerInput {
        runtime: "podman".into(),
        runtime_bin: "podman".into(),
        project: String::new(),
        name: "proxy".into(),
        id: "abc123".into(),
        instance_id: String::new(),
        status: "running".into(),
        pid: None,
    };
    runner.handler = Some(Box::new(|_, _| (0, "abc123456789|42".to_string())));
    assert_eq!(container_process_pid(&item, &matched, &mut runner).unwrap(), 42);

    runner.handler = Some(Box::new(|_, _| (0, "def456789abc|42".to_string())));
    assert!(container_process_pid(&item, &matched, &mut runner).is_err());

    // Host network namespace rejected before running tc
    let dir = temp_dir("host_netns_reject");
    let state_path = dir.join("state.json");
    let pod_id = "a".repeat(64);
    let policy = format!(
        r#"{{"schema":1,"host_id":"{HOST}","expected_node_id":"{NODE}","revision":1,"limits":[{{"scope":"container","runtime":"podman","project":"","container_name":"proxy","container_id":"{pod_id}","upload_mbps":5,"download_mbps":10}}],"auto_throttle":{{"enabled":false}}}}"#
    );
    let containers = vec![ContainerInput {
        runtime: "podman".into(),
        runtime_bin: "podman".into(),
        project: String::new(),
        name: "proxy".into(),
        id: pod_id.clone(),
        instance_id: String::new(),
        status: "running".into(),
        pid: Some(42),
    }];

    let mut host_ns_runner = MockRunner::new(1000);
    host_ns_runner.bins.insert("podman".into(), "/usr/bin/podman".into());
    host_ns_runner.netns.insert(1, Ok(1));
    host_ns_runner.netns.insert(42, Ok(1)); // same as host!
    host_ns_runner.proc_stats.insert(
        42,
        Ok(format!("42 (pod) S {} 12345", vec!["0"; 18].join(" "))),
    );
    let pod_clone = pod_id.clone();
    host_ns_runner.handler = Some(Box::new(move |args, _| {
        if args[1] == "ps" {
            return (0, pod_clone.clone());
        }
        if args[1] == "inspect" {
            return (0, format!("{pod_clone}|42"));
        }
        (1, "unexpected".into())
    }));
    let res = reconcile_with_runner(
        &ReconcileRequest {
            policy_json: &policy,
            host_id: HOST,
            node_id: NODE,
            containers: &containers,
            state_path: &state_path,
            traffic_samples: &[],
            sample_at: 0,
            sample_interval_seconds: 300,
            bridge_inventory: &[],
        },
        &mut host_ns_runner,
    );
    assert_eq!(res.state, "failed");
    assert!(res.items[0]
        .message
        .as_deref()
        .unwrap()
        .contains("host network namespace"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_reconcile_temporary_target_failure_preserves_existing_limit() {
    let dir = temp_dir("preserve_existing");
    let state_path = dir.join("state.json");
    let mut init_state = BandwidthState::default();
    init_state.host_id = HOST.into();
    init_state.expected_node_id = NODE.into();
    let mut rates = BTreeMap::new();
    rates.insert("download".into(), 80);
    init_state.entries.insert(
        "host:eth0".into(),
        StoredEntry {
            key: "host:eth0".into(),
            owner_key: "node-a:host:eth0".into(),
            expected_node_id: NODE.into(),
            scope: "host".into(),
            interface: "eth0".into(),
            interface_index: 2,
            namespace_inode: "host".into(),
            directions: vec!["download".into()],
            rates_mbps: rates,
            ..Default::default()
        },
    );
    write_state_atomic(&state_path, &init_state).unwrap();

    // eth0 temporarily unresolvable -> host_ifindex fails
    let mut runner = MockRunner::new(2000);
    let res = reconcile_with_runner(
        &ReconcileRequest {
            policy_json: base_policy_json(),
            host_id: HOST,
            node_id: NODE,
            containers: &[],
            state_path: &state_path,
            traffic_samples: &[],
            sample_at: 0,
            sample_interval_seconds: 300,
            bridge_inventory: &[],
        },
        &mut runner,
    );
    assert_eq!(res.state, "failed");
    assert!(runner.cmd_log.is_empty());
    assert!(read_state(&state_path).entries.contains_key("host:eth0"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_reconcile_state_write_failure_rolls_back_new_filters() {
    let dir = temp_dir("write_fail_rb");
    // Using an existing directory as state_path forces write_state_atomic rename to fail cross-platform
    let state_path_dir = dir.join("state_is_dir");
    fs::create_dir_all(&state_path_dir).unwrap();

    let mut runner = MockRunner::new(2000);
    runner.ifindices.insert("eth0".into(), Ok(2));
    let dl_h = filter_handle("node-a:host:eth0", Direction::Download);
    let ul_h = filter_handle("node-a:host:eth0", Direction::Upload);
    let tc_state = std::cell::RefCell::new((false, String::new(), String::new()));

    runner.handler = Some(Box::new(move |args, _| {
        let mut s = tc_state.borrow_mut();
        if args == ["tc", "qdisc", "show", "dev", "eth0"] {
            return (0, if s.0 { "qdisc clsact".into() } else { "qdisc noqueue".into() });
        }
        if args == ["tc", "qdisc", "add", "dev", "eth0", "clsact"] {
            s.0 = true;
            return (0, String::new());
        }
        if args == ["tc", "filter", "show", "dev", "eth0", "ingress"] {
            return (0, s.1.clone());
        }
        if args == ["tc", "filter", "show", "dev", "eth0", "egress"] {
            return (0, s.2.clone());
        }
        if args.len() >= 16 && args[0] == "tc" && args[1] == "filter" && args[2] == "add" {
            let dir = args[5];
            let pref = args[9];
            let handle = args[11];
            let rate = args[16];
            let block = format!("filter protocol all pref {pref} matchall handle {handle}\n  police 0x1 rate {rate} burst 256Kb\n");
            if dir == "ingress" {
                assert_eq!(handle, dl_h);
                s.1 = block;
            } else {
                assert_eq!(handle, ul_h);
                s.2 = block;
            }
            return (0, String::new());
        }
        if args.len() >= 12 && args[0] == "tc" && args[1] == "filter" && args[2] == "del" {
            let dir = args[5];
            if dir == "ingress" {
                s.1.clear();
            } else {
                s.2.clear();
            }
            return (0, String::new());
        }
        (1, format!("unexpected: {args:?}"))
    }));

    let policy_no_auto = r#"{"schema":1,"host_id":"node-a","expected_node_id":"enrollment-a","revision":1,"limits":[{"scope":"host","interface":"eth0","upload_mbps":50,"download_mbps":80}],"auto_throttle":{"enabled":false}}"#;
    let res = reconcile_with_runner(
        &ReconcileRequest {
            policy_json: policy_no_auto,
            host_id: HOST,
            node_id: NODE,
            containers: &[],
            state_path: &state_path_dir,
            traffic_samples: &[],
            sample_at: 0,
            sample_interval_seconds: 300,
            bridge_inventory: &[],
        },
        &mut runner,
    );
    assert_eq!(res.state, "failed");
    let rb = res.rollback.as_ref().unwrap();
    assert_eq!(rb.state, "verified");
    assert!(rb.attempted);
    assert_eq!(rb.restored, Some(2));
    assert!(res.message.as_deref().unwrap().contains("本地 tc 所有权状态保存失败"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_reconcile_unverified_old_cleanup_blocks_replacing_same_target() {
    let dir = temp_dir("block_replace");
    let state_path = dir.join("state.json");
    let mut init_state = BandwidthState::default();
    init_state.host_id = HOST.into();
    init_state.expected_node_id = NODE.into();
    let mut rates = BTreeMap::new();
    rates.insert("download".into(), 80);
    let mut prefs = BTreeMap::new();
    prefs.insert("download".into(), 49150);
    let mut confirmed = BTreeMap::new();
    confirmed.insert("download".into(), 100);
    // Stored entry has invalid interface_index=0 so removal cannot verify disappeared interface
    init_state.entries.insert(
        "host:eth0".into(),
        StoredEntry {
            key: "host:eth0".into(),
            owner_key: "node-a:host:eth0".into(),
            expected_node_id: NODE.into(),
            scope: "host".into(),
            interface: "eth0".into(),
            interface_index: 0,
            namespace_inode: "host".into(),
            directions: vec!["download".into()],
            rates_mbps: rates,
            filter_prefs: prefs,
            confirmed_at: confirmed,
            last_confirmed_at: 100,
            ..Default::default()
        },
    );
    write_state_atomic(&state_path, &init_state).unwrap();

    // First call: ifindex fails -> preserve; instead make host_ifindex succeed with index 3,
    // wait: if host_ifindex succeeds with 3 != 0, remove_entry assumes old device disappeared!
    // Use a container entry whose netns_inode is Unavailable during cleanup to block replacement:
    let vm_id = "11111111-2222-3333-4444-555555555555";
    let gen1 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let key = format!("container:runman\0default\0{vm_id}\0{gen1}");
    init_state.entries.clear();
    init_state.entries.insert(
        key.clone(),
        StoredEntry {
            key: key.clone(),
            owner_key: format!("{HOST}:{key}"),
            expected_node_id: NODE.into(),
            scope: "container".into(),
            runtime: "runman".into(),
            project: "default".into(),
            container_name: vm_id.into(),
            container_id: gen1.into(),
            prefix: vec!["nsenter".into(), "--target".into(), "99".into(), "--net".into()],
            pid: 99, // old dead/unreadable pid with Unavailable error
            interface: "eth0".into(),
            interface_index: 2,
            namespace_inode: "99".into(),
            directions: vec!["download".into()],
            rates_mbps: BTreeMap::from([("download".into(), 80)]),
            filter_prefs: BTreeMap::from([("download".into(), 49150)]),
            confirmed_at: BTreeMap::from([("download".into(), 100)]),
            last_confirmed_at: 100,
            ..Default::default()
        },
    );
    write_state_atomic(&state_path, &init_state).unwrap();

    let policy = format!(
        r#"{{"schema":1,"host_id":"{HOST}","expected_node_id":"{NODE}","revision":2,"limits":[{{"scope":"container","runtime":"runman","project":"default","container_name":"{vm_id}","container_id":"{gen1}","upload_mbps":5,"download_mbps":10}}],"auto_throttle":{{"enabled":false}}}}"#
    );
    let containers = vec![ContainerInput {
        runtime: "runman".into(),
        runtime_bin: "runman".into(),
        project: "default".into(),
        name: vm_id.into(),
        id: vm_id.into(),
        instance_id: gen1.into(),
        status: "running".into(),
        pid: Some(42),
    }];
    let mut runner = MockRunner::new(2000);
    runner.netns.insert(1, Ok(1));
    runner.netns.insert(42, Ok(42));
    runner
        .netns
        .insert(99, Err(NetnsError::Unavailable("permission denied".into())));
    runner.proc_stats.insert(
        42,
        Ok(format!("42 (vm) S {} 987654", vec!["0"; 18].join(" "))),
    );
    runner.handler = Some(Box::new(|args, _| {
        if args == ["nsenter", "--target", "42", "--net", "ip", "-j", "route", "show", "default"] {
            return (0, r#"[{"dev":"eth0"}]"#.to_string());
        }
        if args == ["nsenter", "--target", "42", "--net", "ip", "-j", "link", "show", "dev", "eth0"] {
            return (0, r#"[{"ifindex":3,"link_index":7}]"#.to_string());
        }
        (1, "tc must not be called".into())
    }));

    let res = reconcile_with_runner(
        &ReconcileRequest {
            policy_json: &policy,
            host_id: HOST,
            node_id: NODE,
            containers: &containers,
            state_path: &state_path,
            traffic_samples: &[],
            sample_at: 0,
            sample_interval_seconds: 300,
            bridge_inventory: &[],
        },
        &mut runner,
    );
    assert_eq!(res.state, "failed");
    assert!(res.items.iter().any(|i| {
        i.message
            .as_deref()
            .unwrap_or("")
            .contains("旧的 tc 所有限额")
    }));
    assert_eq!(read_state(&state_path).entries[&key].interface_index, 2);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_active_limits_legacy_fallback_and_reconcile_live_samples() {
    let mut entries = BTreeMap::new();
    entries.insert(
        "host:eth0".to_string(),
        StoredEntry {
            key: "host:eth0".into(),
            scope: "host".into(),
            interface: "eth0".into(),
            last_confirmed_at: 555,
            ..Default::default()
        },
    );
    let prev_status = JsonValue::parse(
        r#"{"items":[{"scope":"host","interface":"eth0","target":"eth0","direction":"upload","rate_mbps":25,"state":"applied"}]}"#,
    )
    .unwrap();
    let active = active_bandwidth_limits(&entries, Some(&prev_status));
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].upload_mbps, 25);
    assert_eq!(active[0].download_mbps, 0);

    let dir = temp_dir("live_samples");
    let state_path = dir.join("missing.json");
    let res = reconcile_live_samples(
        r#"{"schema":2,"host_id":"node-a","expected_node_id":"enrollment-a","limits":[]}"#,
        HOST,
        NODE,
        &[],
        &state_path,
        &[],
        0,
        300,
        &[],
    );
    assert_eq!(res.state, "rejected");
    assert!(default_state_path().to_string_lossy().contains("manual-bandwidth-limits.json"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_podman_default_project_matches_empty_peer_project() {
    let mut runner = MockRunner::new(1000);
    let podman_id = "a".repeat(64);
    let policy_json = format!(
        r#"{{"schema":1,"host_id":"{HOST}","expected_node_id":"{NODE}","revision":1,"limits":[{{"scope":"container","runtime":"podman","project":"default","container_name":"web","container_id":"{podman_id}","upload_mbps":25,"download_mbps":0}}]}}"#
    );
    let containers = vec![ContainerInput {
        runtime: "podman".into(),
        runtime_bin: "podman".into(),
        project: "default".into(),
        name: "web".into(),
        id: podman_id.clone(),
        instance_id: String::new(),
        status: "running".into(),
        pid: Some(200),
    }];
    let handle = filter_handle(
        &format!("{HOST}:container:podman\0default\0web\0{podman_id}"),
        Direction::Upload,
    );
    let cid = podman_id.clone();
    let added = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let added_cb = added.clone();
    runner.handler = Some(Box::new(move |args, _| {
        if args == ["podman", "ps", "--no-trunc", "--format", "{{.ID}}"] {
            return (0, cid.clone());
        }
        if args == ["podman", "inspect", "--format", "{{.Id}}|{{.State.Pid}}", &cid] {
            return (0, format!("{cid}|200"));
        }
        if args
            == [
                "nsenter",
                "--target",
                "200",
                "--net",
                "ip",
                "-j",
                "route",
                "show",
                "default",
            ]
        {
            return (0, r#"[{"dev":"eth0"}]"#.into());
        }
        if args
            == [
                "nsenter",
                "--target",
                "200",
                "--net",
                "ip",
                "-j",
                "link",
                "show",
                "dev",
                "eth0",
            ]
        {
            return (0, r#"[{"ifname":"eth0","ifindex":2,"link_index":9}]"#.into());
        }
        if args == ["nsenter", "--target", "200", "--net", "tc", "qdisc", "show", "dev", "eth0"]
        {
            return (0, "qdisc clsact ffff: parent ffff:fff1".into());
        }
        if args
            == [
                "nsenter",
                "--target",
                "200",
                "--net",
                "tc",
                "filter",
                "show",
                "dev",
                "eth0",
                "egress",
            ]
        {
            if added_cb.load(Ordering::SeqCst) {
                return (
                    0,
                    format!(
                        "filter protocol all pref 49151 matchall handle {handle}\n  police 0x1 rate 25Mbit burst 256Kb"
                    ),
                );
            }
            return (0, String::new());
        }
        if args.starts_with(&[
            "nsenter",
            "--target",
            "200",
            "--net",
            "tc",
            "filter",
            "add",
        ]) {
            added_cb.store(true, Ordering::SeqCst);
            return (0, String::new());
        }
        (1, format!("unexpected: {args:?}"))
    }));
    runner.bins.insert("podman".into(), "podman".into());
    runner.netns.insert(1, Ok(100));
    runner.netns.insert(200, Ok(200));
    runner
        .proc_stats
        .insert(200, Ok("200 (podman) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 20 0 1 0 5555 0 0".into()));

    let dir = temp_dir("podman_proj_match");
    let state_path = dir.join("state.json");
    let status = reconcile_with_runner(
        &ReconcileRequest {
            policy_json: &policy_json,
            host_id: HOST,
            node_id: NODE,
            containers: &containers,
            state_path: &state_path,
            traffic_samples: &[],
            sample_at: 1000,
            sample_interval_seconds: 60,
            bridge_inventory: &[],
        },
        &mut runner,
    );
    assert_eq!(status.state, "applied", "status: {:?}", status);
    let _ = fs::remove_dir_all(&dir);
}
