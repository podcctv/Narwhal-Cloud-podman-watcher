    use super::*;
    use net_guard::ClosureCommandRunner;
    use std::env;

    fn sample_vmess_config() -> ConfiguredProtocol {
        ConfiguredProtocol {
            pid: 120,
            process: "xray".to_string(),
            protocol: "vmess".to_string(),
            port: 443,
            listen: "0.0.0.0".to_string(),
            transports: Some(vec!["tcp".to_string()]),
            port_config_complete: false,
            config_file: "/etc/xray/config.json".to_string(),
        }
    }

    fn sample_vmess_listener() -> ServiceListener {
        ServiceListener {
            pid: 120,
            process: "xray".to_string(),
            proto: "tcp".to_string(),
            local: "0.0.0.0:443".to_string(),
            port: 443,
            application_protocols: vec!["vmess".to_string()],
            application_protocol_evidence: "config_matches_live_pid_and_port".to_string(),
            protocol_port_config_complete_protocols: Vec::new(),
            protocol_process_scan_complete: true,
            vmess_process_scan_complete: true,
            speedtest_process_scan_complete: false,
        }
    }

    #[test]
    fn test_plan_matching_vless_exclusion_and_shared_ports() {
        let cfg = sample_vmess_config();
        let lst = sample_vmess_listener();

        // 1. Exact config + live listener match -> candidate
        let r1 = plan("incus", &[cfg.clone()], &[lst.clone()], &[], "complete", None, None, "vmess");
        assert_eq!(r1.state, "candidate");
        assert_eq!(
            r1.blocked_endpoints,
            vec![GuardEndpoint::new_attributed("tcp", 443, 120, "xray")]
        );

        // 2. VLESS inbound is never a VMess block target and is release_eligible
        let mut vless_cfg = cfg.clone();
        vless_cfg.protocol = "vless".to_string();
        let mut vless_lst = lst.clone();
        vless_lst.application_protocols = vec!["vless".to_string()];
        let r2 = plan("incus", &[vless_cfg.clone()], &[vless_lst], &[], "complete", None, None, "vmess");
        assert!(!r2.detected);
        assert!(r2.blocked_endpoints.is_empty());
        assert!(r2.release_eligible);

        // 3. Shared configured port (VMess + VLESS on same PID/port) -> unverified shared_configured_port
        let r3 = plan(
            "incus",
            &[cfg.clone(), vless_cfg],
            &[lst.clone()],
            &[],
            "complete",
            None,
            None,
            "vmess",
        );
        assert_eq!(r3.state, "unverified");
        assert!(r3.blocked_endpoints.is_empty());
        assert_eq!(r3.pending_endpoints[0].reason, "shared_configured_port");

        // 4. Shared live listener -> shared_live_listener
        let mut other_lst = lst.clone();
        other_lst.pid = 121;
        other_lst.process = "other".to_string();
        other_lst.application_protocols = vec!["vless".to_string()];
        let r4 = plan(
            "incus",
            &[cfg.clone()],
            &[lst.clone(), other_lst],
            &[],
            "complete",
            None,
            None,
            "vmess",
        );
        assert_eq!(r4.state, "unverified");
        assert_eq!(r4.pending_endpoints[0].reason, "shared_live_listener");

        // 5. Loopback-only listener -> internal_only
        let mut lo_lst = lst.clone();
        lo_lst.local = "127.0.0.1:443".to_string();
        let r5 = plan("podman", &[cfg.clone()], &[lo_lst], &[], "complete", None, None, "vmess");
        assert_eq!(r5.state, "internal_only");
        assert!(r5.blocked_endpoints.is_empty());

        // 6. Runman supported, Docker rejected
        let r_runman = plan("runman", &[cfg.clone()], &[lst.clone()], &[], "complete", None, None, "vmess");
        assert_eq!(r_runman.state, "candidate");
        let r_docker = plan("docker", &[cfg], &[lst], &[], "complete", None, None, "vmess");
        assert_eq!(r_docker.state, "unverified");
        assert_eq!(r_docker.reason, "runtime_not_supported");
    }

    #[test]
    fn test_scoped_process_scan_states_and_unverified_reason_priority() {
        let cfg = sample_vmess_config();
        let lst = sample_vmess_listener();

        // Complete process 120 can be blocked even when unrelated process 121 is partial
        let states = vec![
            ProcessScanState {
                pid: 120,
                process: "xray".to_string(),
                state: "complete".to_string(),
                start_ticks: "900".to_string(),
                ..Default::default()
            },
            ProcessScanState {
                pid: 121,
                process: "v2ray".to_string(),
                state: "partial".to_string(),
                start_ticks: "901".to_string(),
                ..Default::default()
            },
        ];
        let r_ok = plan(
            "incus",
            &[cfg.clone()],
            &[lst.clone()],
            &[],
            "partial",
            Some(&states),
            Some(true),
            "vmess",
        );
        assert_eq!(r_ok.state, "candidate");
        assert_eq!(r_ok.blocked_endpoints[0].port, 443);

        // Missing start_ticks prevents block unless port_config_complete is true
        let no_ticks = vec![ProcessScanState {
            pid: 120,
            process: "xray".to_string(),
            state: "complete".to_string(),
            start_ticks: String::new(),
            ..Default::default()
        }];
        let r_no_ticks = plan(
            "incus",
            &[cfg],
            &[lst],
            &[],
            "complete",
            Some(&no_ticks),
            Some(true),
            "vmess",
        );
        assert_eq!(r_no_ticks.state, "unverified");
        assert_eq!(
            r_no_ticks.pending_endpoints[0].reason,
            "process_start_generation_unavailable"
        );

        // Reason priority helper
        let p_plan = ProtocolGuardPlan {
            reason: "listener_inventory_incomplete".to_string(),
            ..Default::default()
        };
        let p_states = vec![
            ProcessScanState {
                pid: 120,
                process: "xray".to_string(),
                state: "partial".to_string(),
                reason: "config_process_clock_unavailable".to_string(),
                ..Default::default()
            },
            ProcessScanState {
                pid: 121,
                process: "sing-box".to_string(),
                state: "partial".to_string(),
                reason: "config_path_not_found_or_unreadable".to_string(),
                ..Default::default()
            },
        ];
        let p_eps = vec![PendingEndpoint {
            pid: Some(120),
            port: 443,
            proto: None,
            process: Some("xray".to_string()),
            reason: String::new(),
        }];
        assert_eq!(
            vmess_unverified_reason_key(&p_plan, &p_states, &p_eps),
            "config_process_clock_unavailable"
        );
    }

    #[test]
    fn test_clock_snapshot_and_predates_process() {
        let fields = std::iter::once("S")
            .chain(std::iter::repeat("0").take(18))
            .chain(std::iter::once("60570000"))
            .collect::<Vec<&str>>()
            .join(" ");
        let snapshot = format!(
            "120 (xray worker ) helper) {fields}\n\n@@UPTIME@@\n604700.00 500.00\n\
             @@TARGET_TIMENS@@\nboottime 1000 0\n@@SELF_TIMENS@@\nboottime 0 0\n\
             @@TARGET_TIME_NS@@\n43:43\n@@SELF_TIME_NS@@\n42:42\n"
        );
        let bound = evaluate_clock_snapshot_detailed(
            &snapshot,
            "60570000",
            1_700_001_000.0,
            1_700_001_000.01,
            100.0,
        )
        .expect("valid clock snapshot");
        assert!((bound - 1_700_000_999.97).abs() < 1e-4);
        assert!(protocol_config_predates_process(
            "1:2:100:stable|1700000800|1700000800",
            Some(bound)
        ));
        assert!(!protocol_config_predates_process(
            "1:2:100:stable|1700000998|1700000998",
            Some(bound)
        ));

        // Conflicting offsets in same namespace must be rejected
        let (norm, reason) =
            normalize_proc_boottime_for_target(1000.0, "boottime 1 0", "boottime 0 0", "42:42", "42:42");
        assert!(norm.is_none());
        assert_eq!(reason, "time_namespace_offset_inconsistent");
    }

    #[test]
    fn test_reconcile_apply_readback_and_release() {
        let dir = env::temp_dir().join(format!("narwhal-vmess-rec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let net_ns_dir = dir.join("120").join("ns");
        fs::create_dir_all(&net_ns_dir).unwrap();
        fs::write(net_ns_dir.join("net"), "net:[4026532000]").unwrap();

        let identity = "podman\0\0fixture\0container-id";
        let digest = &sha256_hex(identity.as_bytes())[..12];
        let marker = format!("narwhal-vmess-guard-v1-{digest}");
        let table = format!("narwhal_vmess_{digest}");

        let tools = NetToolPaths {
            nsenter_bin: Some("/usr/bin/nsenter".to_string()),
            nft_bin: Some("/usr/bin/nft".to_string()),
            ..Default::default()
        };

        let applied_script = std::cell::RefCell::new(String::new());
        let is_applied = std::cell::Cell::new(false);
        let marker_clone = marker.clone();
        let mut runner = ClosureCommandRunner(|args: &[String], stdin: Option<&str>| {
            let cmd = &args[6..];
            if cmd == ["-a", "list", "table", "inet", &table] {
                if is_applied.get() {
                    (true, format!("{marker_clone}-tcp-443"))
                } else {
                    (false, String::new())
                }
            } else if cmd == ["-j", "list", "tables"] {
                (true, "{\"nftables\":[]}".to_string())
            } else if cmd == ["--check", "-f", "-"] {
                (true, String::new())
            } else if cmd == ["-f", "-"] {
                *applied_script.borrow_mut() = stdin.unwrap_or("").to_string();
                is_applied.set(true);
                (true, String::new())
            } else if cmd == ["delete", "table", "inet", &table] {
                is_applied.set(false);
                (true, String::new())
            } else {
                (false, "unexpected".to_string())
            }
        });

        let mut epoch_fn = |_pid: u32| "epoch-1".to_string();
        let eps = vec![GuardEndpoint::new_port("tcp", 443)];
        let req = ReconcileRequest::new(120, identity, "epoch-1", Some(&eps));
        let res = reconcile_with(&req, &tools, &mut runner, &dir, &mut epoch_fn);
        assert_eq!(res.state, "blocked");
        assert_eq!(res.blocked_endpoints, vec![GuardEndpoint::new_port("tcp", 443)]);
        assert!(applied_script.borrow().contains(&format!("add chain inet {table} input")));
        assert!(applied_script.borrow().contains("meta l4proto tcp tcp dport 443 drop"));
        assert!(applied_script.borrow().contains(&format!("{marker}-tcp-443")));

        // Release when live_listeners has only VLESS on 443 -> cleared
        let vless_listener = ServiceListener {
            pid: 120,
            process: "xray".to_string(),
            proto: "tcp".to_string(),
            local: "0.0.0.0:443".to_string(),
            port: 443,
            application_protocols: vec!["vless".to_string()],
            application_protocol_evidence: "config_matches_live_pid_and_port".to_string(),
            ..Default::default()
        };
        let rel_req = ReconcileRequest {
            pid: 120,
            identity,
            expected_epoch: "epoch-1",
            endpoints: Some(&[]),
            destination_ips: None,
            domain_targets: None,
            host_network: false,
            release_if_absent: true,
            live_listeners: Some(&[vless_listener]),
            preserve_existing: false,
            application_protocol: "vmess",
        };
        let rel_res = reconcile_with(&rel_req, &tools, &mut runner, &dir, &mut epoch_fn);
        assert_eq!(rel_res.state, "cleared");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_alerts_and_evidence_chain_and_failure_reasons() {
        assert_eq!(
            firewall_failure_reason(
                Some("Operation not permitted at /secret/container/path"),
                "firewall_apply_failed"
            ),
            "firewall_permission_denied"
        );
        assert_eq!(
            firewall_failure_reason(
                Some("Operation not supported by kernel"),
                "firewall_apply_failed"
            ),
            "firewall_kernel_unsupported"
        );
        assert_eq!(
            firewall_failure_reason(
                Some("syntax error near /private/config"),
                "firewall_apply_failed"
            ),
            "firewall_rule_validation_failed"
        );

        assert_eq!(
            vmess_endpoint_label(Some("tcp"), 443, Some(120), Some("xray"), false),
            "xray（容器内 PID 120）监听 TCP/443"
        );
        assert_eq!(
            vmess_endpoint_label(Some("tcp"), 443, Some(120), Some("xray"), true),
            "xray（容器内 PID 120），待核实 TCP/443"
        );

        let mut status = ProtocolGuardPlan {
            detected: true,
            protocol: "vmess".to_string(),
            state: "blocked".to_string(),
            blocked_endpoints: vec![GuardEndpoint::new_attributed("tcp", 443, 120, "xray")],
            configured_endpoints: vec![sample_vmess_config()],
            ..Default::default()
        };
        status.configured_endpoints[0].port_config_complete = true;
        finalize_protocol_guard_evidence(&mut status);
        let ec = status.evidence_chain.as_ref().unwrap();
        assert_eq!(ec.configuration, "confirmed");
        assert_eq!(ec.firewall_readback, "confirmed");

        let ctx = AlertContainerContext {
            runtime: "runman".to_string(),
            project: "default".to_string(),
            name: "11111111-2222-3333-4444-555555555555".to_string(),
            instance_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_string(),
            ..Default::default()
        };
        let vmess_alert = build_vmess_alert(&status, &[], &ctx).expect("vmess alert");
        assert_eq!(vmess_alert.alert_type, "vmess_port_blocked");
        assert!(vmess_alert.message.contains("VLESS + Reality + Vision"));

        let mut trojan_status = status.clone();
        trojan_status.protocol = "trojan".to_string();
        let trojan_alert = build_trojan_alert(&trojan_status, &[], &ctx).expect("trojan alert");
        assert_eq!(trojan_alert.alert_type, "trojan_port_blocked");
    }
