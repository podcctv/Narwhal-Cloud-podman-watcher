use super::*;
use net_guard::ClosureCommandRunner;
use std::env;

#[test]
fn test_normalize_load_and_save_policy() {
    let dir = env::temp_dir().join(format!("narwhal-speedtest-pol-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("policy.json");

    assert!(load_policy(Some(&path)).is_none());

    let raw = JsonVal::parse(
        r#"{"revision":1,"services":["ookla","iperf3_server"],"runtimes":["runman"]}"#,
    )
    .unwrap();
    let norm = normalize_policy(&raw);
    assert_eq!(norm.runtimes, vec!["runman"]);
    assert_eq!(norm.services, vec!["iperf3_server", "ookla"]);

    let (ok, msg) = save_policy(&raw, Some(&path));
    assert!(ok, "save failed: {msg}");
    let loaded = load_policy(Some(&path)).expect("loaded policy");
    assert!(!loaded.invalid);
    assert_eq!(loaded.revision, 1);
    assert_eq!(loaded.services, vec!["iperf3_server", "ookla"]);

    // Reject unsupported runtime such as docker
    let bad_rt = JsonVal::parse(
        r#"{"revision":2,"services":["ookla"],"runtimes":["docker"]}"#,
    )
    .unwrap();
    let (ok_bad, _) = save_policy(&bad_rt, Some(&path));
    assert!(!ok_bad);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_leaseweb_domain_and_sentinel_targets_and_parsers() {
    assert_eq!(
        valid_leaseweb_domain("SpeedTest.HKG12.HK.LeaseWeb.Net."),
        "speedtest.hkg12.hk.leaseweb.net"
    );
    assert_eq!(valid_leaseweb_domain("speedtest.leaseweb.net"), "");
    assert_eq!(valid_leaseweb_domain("evil.com"), "");

    let sentinels = domain_sentinel_targets(&["fast.com", "speedtest.net"]);
    assert_eq!(sentinels.len(), 4);
    assert_eq!(sentinels[0], DomainTarget::new("fast.com", "192.0.2.1"));
    assert_eq!(sentinels[1], DomainTarget::new("fast.com", "2001:db8::1"));
    assert_eq!(sentinels[2], DomainTarget::new("speedtest.net", "192.0.2.2"));
    assert_eq!(sentinels[3], DomainTarget::new("speedtest.net", "2001:db8::2"));

    let script = r#"
SPEEDTEST_TOS_CT_IP="203.0.113.5"
SPEEDTEST_TOS_CU_IP="1.1.1.1"
SPEEDTEST_TOS_CM_IP="8.8.8.8"
INTERNATIONAL_IPERF_TARGETS=(
  'HK|HongKong|10G|speedtest.hkg12.hk.leaseweb.net|5201|5210|speedtest.tyo11.jp.leaseweb.net|1|speedtest.sin1.sg.leaseweb.net'
)
"#;
    let (domains, ips) = parse_tcpquality_script(script);
    assert_eq!(
        domains,
        vec![
            "speedtest.hkg12.hk.leaseweb.net",
            "speedtest.sin1.sg.leaseweb.net",
            "speedtest.tyo11.jp.leaseweb.net"
        ]
    );
    // 203.0.113.5 is documentation range (not global), while 1.1.1.1 and 8.8.8.8 are global
    assert_eq!(ips, vec!["1.1.1.1", "8.8.8.8"]);

    let nodes_tsv = "type\tfamily\tid\tcarrier\tprov\tip\tport\ttarget\n\
                     tos\t4\t1\t电信\tBJ\t1.0.0.1\t80\tcn-beijing\n\
                     tos\t4\t2\t联通\tSH\t8.8.4.4\t80\tcn-shanghai\n\
                     speedtest\t4\t3\t移动\tGZ\t9.9.9.9\t80\tcn-guangzhou\n";
    let inv = parse_tcpquality_nodes(nodes_tsv);
    assert_eq!(inv.target_ips, vec!["1.0.0.1", "8.8.4.4", "9.9.9.9"]);
    assert_eq!(
        inv.regions,
        vec!["cn-beijing", "cn-guangzhou", "cn-shanghai"]
    );
}

#[test]
fn test_reconcile_container_and_speedtest_attempt_alert() {
    let dir = env::temp_dir().join(format!("narwhal-speedtest-rec-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let net_ns_dir = dir.join("200").join("ns");
    fs::create_dir_all(&net_ns_dir).unwrap();
    fs::write(net_ns_dir.join("net"), "net:[4026532200]").unwrap();

    let identity = "incus\0default\0c1\0id1";
    let digest = &sha256_hex(identity.as_bytes())[..12];
    let marker = format!("narwhal-speedtest-guard-v1-{digest}");
    let table = format!("narwhal_speedtest_{digest}");

    let tools = NetToolPaths {
        nsenter_bin: Some("/usr/bin/nsenter".to_string()),
        nft_bin: Some("/usr/bin/nft".to_string()),
        ..Default::default()
    };

    let mut host_runner = ClosureCommandRunner(|args: &[String], _stdin: Option<&str>| {
        let cmd = &args[6..];
        if cmd == ["-a", "list", "table", "inet", &table] {
            (
                true,
                format!(
                    "chain output {{\n  ip daddr 192.0.2.1 counter packets 4 bytes 240 drop comment \"{marker}-domain-fast.com-192.0.2.1\"\n  ip6 daddr 2001:db8::1 counter packets 0 bytes 0 drop comment \"{marker}-domain-fast.com-2001:db8::1\"\n  ip daddr 192.0.2.2 counter packets 0 bytes 0 drop comment \"{marker}-domain-www.fast.com-192.0.2.2\"\n  ip6 daddr 2001:db8::2 counter packets 0 bytes 0 drop comment \"{marker}-domain-www.fast.com-2001:db8::2\"\n}}\n"
                ),
            )
        } else if cmd == ["-j", "list", "tables"] {
            (true, "{\"nftables\":[]}".to_string())
        } else if cmd == ["--check", "-f", "-"] || cmd == ["-f", "-"] {
            (true, String::new())
        } else {
            (false, "unexpected".to_string())
        }
    });

    let mut guest = |_script: &str| (true, "hosts_policy_readback_ok\n".to_string());
    let policy = SpeedtestPolicy {
        revision: 3,
        services: vec!["fast".to_string()],
        runtimes: vec!["incus".to_string()],
        invalid: false,
    };
    let input = SpeedtestContainerInput {
        runtime: "incus",
        name: "c1",
        project: "default",
        identity,
        pid: 200,
        namespace_epoch: "epoch-200",
        network_shared: false,
        image: "alpine",
        listeners: &[],
        listener_inventory_complete: true,
        policy: &policy,
        observed_at: Some(1700000000),
    };
    let mut caches = SpeedtestReconcileCaches::default();
    let mut epoch_fn = |_pid: u32| "epoch-200".to_string();

    let status = reconcile_container_with(
        &input,
        Some(&mut guest),
        None,
        &mut caches,
        &tools,
        &mut host_runner,
        &dir,
        &mut epoch_fn,
    );
    assert_eq!(status.state, "blocked");
    assert_eq!(status.hosts_state, "blocked");
    assert_eq!(status.domain_targets_state, "blocked");
    assert_eq!(status.blocked_domains, vec!["fast.com", "www.fast.com"]);
    assert_eq!(
        status.blocked_attempts,
        vec![BlockedSpeedtestAttempt {
            service: "fast".to_string(),
            target: "fast.com".to_string(),
            packets: 4,
        }]
    );

    let ctx = AlertContainerContext {
        runtime: "incus".to_string(),
        project: "default".to_string(),
        name: "c1".to_string(),
        instance_id: "id1".to_string(),
        ..Default::default()
    };
    let alert = build_speedtest_attempt_blocked_alert(&status, &ctx).expect("alert emitted");
    assert_eq!(alert.alert_type, "speedtest_attempt_blocked");
    assert!(alert.message.contains("FAST.com（fast.com）"));

    let _ = fs::remove_dir_all(&dir);
}

struct MockFetcher {
    script: String,
    nodes: String,
}

impl HttpsFetcher for MockFetcher {
    fn fetch_https(&mut self, url: &str, _allowed_host: &str) -> Result<String, String> {
        if url.contains("runTcpQuality") {
            if self.script.is_empty() {
                Err("offline".to_string())
            } else {
                Ok(self.script.clone())
            }
        } else if self.nodes.is_empty() {
            Err("offline".to_string())
        } else {
            Ok(self.nodes.clone())
        }
    }
}

struct MockResolver;

impl DnsResolver for MockResolver {
    fn resolve_domain(&mut self, _domain: &str) -> Vec<IpAddr> {
        vec!["23.105.0.1".parse().unwrap()]
    }
}

#[test]
fn test_tcpquality_target_inventory_fresh_and_cache() {
    let dir = env::temp_dir().join(format!("narwhal-tq-inv-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let cache_file = dir.join("target-cache.json");

    let mut fetcher = MockFetcher {
        script: "INTERNATIONAL_IPERF_TARGETS=(\n'HK|HongKong|10G|speedtest.hkg12.hk.leaseweb.net|5201|5210|speedtest.tyo11.jp.leaseweb.net|1|speedtest.sin1.sg.leaseweb.net'\n)\n".to_string(),
        nodes: "type\tfamily\tid\tcarrier\tprov\tip\tport\ttarget\n\
                tos\t4\t1\t电信\tBJ\t1.0.0.1\t80\tcn-beijing\n\
                tos\t4\t2\t联通\tSH\t8.8.4.4\t80\tcn-shanghai\n\
                speedtest\t4\t3\t移动\tGZ\t9.9.9.9\t80\tcn-guangzhou\n".to_string(),
    };
    let mut resolver = MockResolver;
    let mut state = TargetInventoryCacheState::default();

    let inv = tcpquality_target_inventory_with(
        1_700_000_000,
        true,
        &cache_file,
        &mut state,
        &mut fetcher,
        &mut resolver,
    );
    assert_eq!(inv.state, "fresh");
    assert_eq!(inv.source, "tcpquality_script+getNodes");
    assert!(inv.target_ips.contains(&"23.105.0.1".to_string()));
    assert!(inv.target_ips.contains(&"1.0.0.1".to_string()));
    assert!(cache_file.is_file());

    let disk_cached = read_target_cache(&cache_file).expect("read target cache");
    assert_eq!(disk_cached.state, "stale");
    assert_eq!(disk_cached.domains.len(), 3);

    let _ = fs::remove_dir_all(&dir);
}
