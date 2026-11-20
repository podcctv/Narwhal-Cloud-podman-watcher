    use super::*;

    #[test]
    fn test_parse_poll_actions_and_receipt_serialization() {
        let poll_json = r#"{
            "ok": true,
            "actions": [
                {
                    "id": 42,
                    "action_type": "cpu_limit",
                    "runtime": "runman",
                    "project": "default",
                    "container_name": "runman-abc.service",
                    "params": {
                        "unit": "runman-abc.service",
                        "cpu_quota_percent": 50
                    }
                },
                {
                    "id": 43,
                    "action_type": "tcp_ping",
                    "params": {
                        "samples": 2,
                        "targets": [
                            {"id": "t1", "host": "example.com", "port": 443}
                        ]
                    }
                }
            ]
        }"#;

        let actions = parse_poll_actions(poll_json).expect("parse poll actions");
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].id, 42);
        assert_eq!(actions[0].action_type, "cpu_limit");
        assert_eq!(
            actions[0].params.get("cpu_quota_percent").and_then(JsonValue::as_i64),
            Some(50)
        );
        assert_eq!(actions[1].id, 43);
        assert_eq!(actions[1].action_type, "tcp_ping");

        let receipt = ActionReceipt::succeeded_with_data(
            43,
            "tcp_ping",
            "probed \"1\" target\nline2",
            "{\"results\":[]}",
        );
        let serialized = receipt.to_result_json("host-1", "node-9");
        let parsed = parse_json(&serialized).expect("valid receipt JSON");
        assert_eq!(parsed.get("action_id").and_then(JsonValue::as_i64), Some(43));
        assert_eq!(parsed.get("host_id").and_then(JsonValue::as_str), Some("host-1"));
        assert_eq!(parsed.get("node_id").and_then(JsonValue::as_str), Some("node-9"));
        assert_eq!(parsed.get("ok").and_then(JsonValue::as_bool), Some(true));
        assert_eq!(
            parsed.get("status").and_then(JsonValue::as_str),
            Some("succeeded")
        );
        assert_eq!(
            parsed.get("message").and_then(JsonValue::as_str),
            Some("probed \"1\" target\nline2")
        );
        assert!(parsed.get("data").and_then(|d| d.get("results")).is_some());
    }

    #[test]
    fn test_action_json_parse_rejects_malformed_input() {
        assert!(ActionRequest::from_json("{\"action_type\":\"tcp_ping\"}").is_err());
        assert!(ActionRequest::from_json("{\"id\":1}").is_err());
        assert!(ActionRequest::from_json("{\"id\":1,\"action_type\":\"tcp_ping\"} trailing").is_err());
        assert!(parse_json("{\"a\":\"\\uD800\"}").is_err());
    }

    #[test]
    fn test_managed_upgrade_validation_rejects_bad_revision_version_and_traversal() {
        let bad_rev = ActionRequest::from_json(
            r#"{"id":1,"action_type":"managed_upgrade","params":{"revision":"../etc/passwd","version":"1.8.44"}}"#,
        )
        .unwrap();
        let r1 = execute_action(&bad_rev);
        assert!(!r1.ok);
        assert_eq!(r1.status, "failed");

        let uppercase_rev = ActionRequest::from_json(
            r#"{"id":2,"action_type":"managed_upgrade","params":{"revision":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","version":"1.8.44"}}"#,
        )
        .unwrap();
        let r2 = execute_action(&uppercase_rev);
        assert!(!r2.ok);

        let bad_ver = ActionRequest::from_json(
            r#"{"id":3,"action_type":"managed_upgrade","params":{"revision":"0123456789abcdef0123456789abcdef01234567","version":"1.8.44;id"}}"#,
        )
        .unwrap();
        let r3 = execute_action(&bad_ver);
        assert!(!r3.ok);

        // Valid format but script does not exist in test environment -> safe ok: false
        let missing_script = ActionRequest::from_json(
            r#"{"id":4,"action_type":"managed_upgrade","params":{"revision":"0123456789abcdef0123456789abcdef01234567","version":"1.8.44"}}"#,
        )
        .unwrap();
        let r4 = execute_managed_upgrade(
            &missing_script,
            Path::new("/nonexistent/managed-client-update.sh"),
            &ActionContext::default(),
        );
        assert!(!r4.ok);
    }

    #[test]
    fn test_systemd_unit_validation_and_limit_props() {
        assert!(is_valid_systemd_unit("narwhal-agent.service"));
        assert!(is_valid_systemd_unit("runman-123e4567.scope"));
        assert!(is_valid_systemd_unit("user@1000.service"));

        assert!(!is_valid_systemd_unit(""));
        assert!(!is_valid_systemd_unit(".service"));
        assert!(!is_valid_systemd_unit("-flag.service"));
        assert!(!is_valid_systemd_unit("../evil.service"));
        assert!(!is_valid_systemd_unit("foo/bar.service"));
        assert!(!is_valid_systemd_unit("foo.timer"));
        assert!(!is_valid_systemd_unit("foo.service;id"));
        assert!(!is_valid_systemd_unit("foo bar.service"));

        let cpu_req = ActionRequest::from_json(
            r#"{"id":10,"action_type":"cpu_limit","params":{"unit":"runman-1.service","cpu_quota_percent":75}}"#,
        )
        .unwrap();
        let (unit, props) = build_systemd_limit_props(&cpu_req).unwrap();
        assert_eq!(unit, "runman-1.service");
        assert_eq!(props, vec!["CPUQuota=75%"]);

        let cpu_restore = ActionRequest::from_json(
            r#"{"id":11,"action_type":"cpu_limit","params":{"unit":"runman-1.service","restore":true}}"#,
        )
        .unwrap();
        let (_, props_restore) = build_systemd_limit_props(&cpu_restore).unwrap();
        assert_eq!(props_restore, vec!["CPUQuota="]);

        let mem_req = ActionRequest::from_json(
            r#"{"id":12,"action_type":"memory_limit","params":{"unit":"ct-1.scope","memory_max":"512M","memory_high":"384M"}}"#,
        )
        .unwrap();
        let (_, mem_props) = build_systemd_limit_props(&mem_req).unwrap();
        assert_eq!(mem_props, vec!["MemoryMax=512M", "MemoryHigh=384M"]);

        let io_req = ActionRequest::from_json(
            r#"{"id":13,"action_type":"io_limit","params":{"unit":"ct-1.scope","io_weight":200,"device":"/dev/sda","read_bps":"10M"}}"#,
        )
        .unwrap();
        let (_, io_props) = build_systemd_limit_props(&io_req).unwrap();
        assert_eq!(
            io_props,
            vec!["IOWeight=200", "IOReadBandwidthMax=/dev/sda 10M"]
        );

        let bad_unit_req = ActionRequest::from_json(
            r#"{"id":14,"action_type":"cpu_limit","params":{"unit":"../etc/passwd","cpu_quota_percent":50}}"#,
        )
        .unwrap();
        let r_bad = execute_action(&bad_unit_req);
        assert!(!r_bad.ok);

        let bad_dev_req = ActionRequest::from_json(
            r#"{"id":15,"action_type":"io_limit","params":{"unit":"ct-1.scope","device":"/dev/../sda","read_bps":"10M"}}"#,
        )
        .unwrap();
        let r_bad_dev = execute_action(&bad_dev_req);
        assert!(!r_bad_dev.ok);
    }

    #[test]
    fn test_tcp_ping_validation_and_unknown_action_rejection() {
        let bad_host = ActionRequest::from_json(
            r#"{"id":20,"action_type":"tcp_ping","params":{"targets":[{"id":"local","host":"127.0.0.1","port":80}]}}"#,
        )
        .unwrap();
        let r_host = execute_action(&bad_host);
        assert!(!r_host.ok);

        let bad_port = ActionRequest::from_json(
            r#"{"id":21,"action_type":"tcp_ping","params":{"targets":[{"id":"p0","host":"example.com","port":0}]}}"#,
        )
        .unwrap();
        let r_port = execute_action(&bad_port);
        assert!(!r_port.ok);

        let bad_samples = ActionRequest::from_json(
            r#"{"id":22,"action_type":"tcp_ping","params":{"samples":99,"targets":[{"id":"t1","host":"example.com","port":443}]}}"#,
        )
        .unwrap();
        let r_samples = execute_action(&bad_samples);
        assert!(!r_samples.ok);

        let unknown = ActionRequest::from_json(
            r#"{"id":23,"action_type":"rm_rf_root","params":{}}"#,
        )
        .unwrap();
        let r_unknown = execute_action(&unknown);
        assert!(!r_unknown.ok);
        assert_eq!(r_unknown.status, "failed");
    }

    #[test]
    fn test_kill_pid_validation_rejects_pid_le_one_and_invalid_values() {
        for (idx, payload) in [
            r#"{"id":30,"action_type":"kill_pid","params":{}}"#,
            r#"{"id":31,"action_type":"kill_pid","params":{"pid":0}}"#,
            r#"{"id":32,"action_type":"kill_pid","params":{"pid":1}}"#,
            r#"{"id":33,"action_type":"stop_socks_process","params":{"pid":1}}"#,
            r#"{"id":34,"action_type":"kill_pid","params":{"pid":-5}}"#,
            r#"{"id":35,"action_type":"kill_pid","params":{"pid":"1"}}"#,
            r#"{"id":36,"action_type":"kill_pid","params":{"pid":"123;id"}}"#,
            r#"{"id":37,"action_type":"kill_pid","params":{"pid":4294967296}}"#,
        ]
        .iter()
        .enumerate()
        {
            let req = ActionRequest::from_json(payload).unwrap();
            let receipt = execute_action(&req);
            assert!(!receipt.ok, "case {idx} should fail: {payload}");
            assert_eq!(receipt.status, "failed");
            assert!(
                receipt.message.contains("pid"),
                "case {idx} should mention pid validation error, got: {}",
                receipt.message
            );
        }

        // Valid pid > 1 passes validation (fails gracefully on non-Unix or missing /proc/<pid>/stat)
        let valid_req = ActionRequest::from_json(
            r#"{"id":38,"action_type":"stop_socks_process","params":{"pid":99999999}}"#,
        )
        .unwrap();
        let valid_receipt = execute_action(&valid_req);
        assert!(!valid_receipt.ok);
        assert!(
            valid_receipt.message.contains("does not exist")
                || valid_receipt.message.contains("only supported on Unix"),
            "unexpected message for valid pid: {}",
            valid_receipt.message
        );
    }

    #[test]
    fn test_runman_overload_validation_rejects_empty_and_unsafe_container_id() {
        let too_long_id = "a".repeat(129);
        let too_long_gen = "g".repeat(129);
        let long_id_json = format!(
            r#"{{"id":40,"action_type":"runman_restart_overload","params":{{"container":"{too_long_id}"}}}}"#
        );
        let long_gen_json = format!(
            r#"{{"id":41,"action_type":"runman_stop_overload","params":{{"container":"ct-1","generation":"{too_long_gen}"}}}}"#
        );

        let invalid_cases = [
            r#"{"id":42,"action_type":"runman_restart_overload","params":{}}"#,
            r#"{"id":43,"action_type":"runman_stop_overload","params":{"container":""}}"#,
            r#"{"id":44,"action_type":"runman_restart_overload","params":{"container":"../evil"}}"#,
            r#"{"id":45,"action_type":"runman_stop_overload","params":{"container":"ct;rm -rf /"}}"#,
            r#"{"id":46,"action_type":"runman_restart_overload","params":{"instance_id":"bad/id"}}"#,
            r#"{"id":47,"action_type":"runman_stop_overload","params":{"container":"ct-1","generation":"bad\nline"}}"#,
            long_id_json.as_str(),
            long_gen_json.as_str(),
        ];

        for (idx, payload) in invalid_cases.iter().enumerate() {
            let req = ActionRequest::from_json(payload).unwrap();
            let receipt = execute_action(&req);
            assert!(!receipt.ok, "case {idx} should fail: {payload}");
            assert_eq!(receipt.status, "failed");
        }

        // Valid container + generation passes validation and fails gracefully when socket is absent / non-Unix
        for action_type in ["runman_restart_overload", "runman_stop_overload"] {
            let valid_json = format!(
                r#"{{"id":50,"action_type":"{action_type}","params":{{"container":"ct_1.prod-01","instance_id":"inst-123","generation":"gen-42"}}}}"#
            );
            let req = ActionRequest::from_json(&valid_json).unwrap();
            let receipt = execute_action(&req);
            assert!(!receipt.ok);
            assert!(
                receipt.message.contains("socket")
                    || receipt.message.contains("Unix")
                    || receipt.message.contains("request failed"),
                "expected graceful socket/platform failure, got: {}",
                receipt.message
            );
        }
    }

    #[test]
    fn test_mainline_host_config_rescan_discover_and_firewall_validation() {
        let dir = std::env::temp_dir().join("narwhal-actions-mainline-test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let env_file = dir.join("client.env");
        fs::write(&env_file, "HOST_ID=old-host\nREPORT_INTERVAL=300\nSECURITY_MONITOR_ENABLED=true\n").unwrap();

        let log_file = dir.join("access.log");
        fs::write(&log_file, "203.0.113.1 - - [16/Nov/2026:12:00:00 +0800] \"GET /health HTTP/1.1\" 200 2\n").unwrap();

        let mut ctx = ActionContext {
            node_id: "node-xyz".to_string(),
            env_file: env_file.clone(),
            configured_access_logs: vec![log_file.to_string_lossy().into_owned()],
            rescan_requested: false,
            restart_required: false,
            ..ActionContext::default()
        };

        // Mismatched node_id must be rejected
        let bad_cfg = ActionRequest::from_json(
            r#"{"id":60,"action_type":"update_host_config","params":{"expected_node_id":"wrong","config":{"host_id":"new"}}}"#,
        )
        .unwrap();
        let r_bad_cfg = execute_action_with_context(&bad_cfg, &mut ctx);
        assert!(!r_bad_cfg.ok);
        assert!(!ctx.restart_required);

        // Unsafe access log path must be rejected
        let bad_paths = ActionRequest::from_json(
            r#"{"id":61,"action_type":"update_host_config","params":{"expected_node_id":"node-xyz","config":{"security_access_log_paths":["/etc/passwd"]}}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&bad_paths, &mut ctx).ok);

        // Valid host config update mutates client.env and requests restart
        let ok_cfg = ActionRequest::from_json(
            r#"{"id":62,"action_type":"update_host_config","params":{"expected_node_id":"node-xyz","config":{"host_id":"new-host","report_interval":120,"security_monitor_enabled":false,"security_access_log_paths":["/var/log/nginx/access.log"]}}}"#,
        )
        .unwrap();
        let r_ok_cfg = execute_action_with_context(&ok_cfg, &mut ctx);
        assert!(r_ok_cfg.ok);
        assert!(ctx.restart_required);
        let written = fs::read_to_string(&env_file).unwrap();
        assert!(written.contains("HOST_ID=new-host"));
        assert!(written.contains("REPORT_INTERVAL=120"));
        assert!(written.contains("SECURITY_MONITOR_ENABLED=false"));
        assert!(written.contains("SECURITY_ACCESS_LOG_PATHS=/var/log/nginx/access.log"));

        // host_security_rescan sets rescan flag
        let rescan_req = ActionRequest::from_json(
            r#"{"id":63,"action_type":"host_security_rescan","params":{"expected_node_id":"node-xyz"}}"#,
        )
        .unwrap();
        let r_rescan = execute_action_with_context(&rescan_req, &mut ctx);
        assert!(r_rescan.ok);
        assert!(ctx.rescan_requested);

        // discover_access_logs finds & parses configured log
        let disc_req = ActionRequest::from_json(
            r#"{"id":64,"action_type":"discover_access_logs","params":{"expected_node_id":"node-xyz"}}"#,
        )
        .unwrap();
        let r_disc = execute_action_with_context(&disc_req, &mut ctx);
        assert!(r_disc.ok);
        assert!(r_disc.message.contains("access.log"));
        assert!(r_disc.message.contains("\"status\":\"healthy\""));

        // Host firewall policy rejects wrong scope and non-manual delete
        let bad_fw = ActionRequest::from_json(
            r#"{"id":65,"action_type":"apply_host_firewall_policy","runtime":"podman","container_name":"c1","params":{"expected_node_id":"node-xyz","policy":{"revision":1,"rules":[],"abuse":{}}}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&bad_fw, &mut ctx).ok);

        let bad_del = ActionRequest::from_json(
            r#"{"id":66,"action_type":"delete_host_firewall_rule","runtime":"host","container_name":"__host__","params":{"expected_node_id":"node-xyz","rule":{"id":1,"origin":"auto","sync_state":"manual"}}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&bad_del, &mut ctx).ok);

        // apply_container_connlimit rejects non-default project and expired action
        let bad_cl = ActionRequest::from_json(
            r#"{"id":67,"action_type":"apply_container_connlimit","runtime":"runman","project":"other","container_name":"00000000-0000-4000-8000-000000000001","params":{"expected_node_id":"node-xyz"}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&bad_cl, &mut ctx).ok);

        // stop_container rejects missing reason/expired evidence
        let bad_stop = ActionRequest::from_json(
            r#"{"id":68,"action_type":"stop_container","runtime":"podman","container_name":"c1","params":{"reason":"other"}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&bad_stop, &mut ctx).ok);

        // request_deep_sample sets rescan_requested
        ctx.rescan_requested = false;
        let deep_req = ActionRequest::from_json(
            r#"{"id":69,"action_type":"request_deep_sample","params":{"expected_node_id":"node-xyz"}}"#,
        )
        .unwrap();
        let r_deep = execute_action_with_context(&deep_req, &mut ctx);
        assert!(r_deep.ok);
        assert!(ctx.rescan_requested);

        // remediate_malicious_process rejects Docker
        let bad_rem = ActionRequest::from_json(
            r#"{"id":70,"action_type":"remediate_malicious_process","runtime":"docker","container_name":"c1","params":{}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&bad_rem, &mut ctx).ok);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_net_guard_panel_domain_and_disk_cleanup_actions() {
        let dir = std::env::temp_dir().join("narwhal-actions-new-crates-test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let env_file = dir.join("client.env");
        fs::write(
            &env_file,
            "SHARED_SECRET=keep-me-secret\nNODE_ID=node-xyz\n",
        )
        .unwrap();
        let allowlist_file = dir.join("panel-allowlist.json");
        let auto_file = dir.join("panel-auto-remediate.json");
        let cleanup_journal = dir.join("disk-cleanup.json");
        let quarantine_journal = dir.join("quarantine-journal.json");

        let mut ctx = ActionContext {
            node_id: "node-xyz".to_string(),
            env_file: env_file.clone(),
            panel_allowlist_path: allowlist_file.clone(),
            panel_auto_remediate_path: auto_file.clone(),
            cleanup_journal_path: cleanup_journal.clone(),
            quarantine_journal_path: Some(quarantine_journal.clone()),
            cleanup_host_available: Some(true),
            cleanup_policy: app_guard::disk_cleanup::CleanupPolicy {
                enabled: true,
                include_containers: true,
                retention_days: 14,
                interval_hours: 24,
            },
            ..ActionContext::default()
        };

        // 1. UDP blackhole validation (rejects Docker & pid<=1)
        let bad_udp = ActionRequest::from_json(
            r#"{"id":71,"action_type":"apply_udp_blackhole","runtime":"podman","container_name":"c1","params":{"pid":0}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&bad_udp, &mut ctx).ok);

        let rel_udp_bad = ActionRequest::from_json(
            r#"{"id":72,"action_type":"release_udp_blackhole","runtime":"docker","container_name":"c1","params":{}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&rel_udp_bad, &mut ctx).ok);

        // 2. Anti-spoof validation (rejects invalid veth name)
        let bad_spoof = ActionRequest::from_json(
            r#"{"id":73,"action_type":"apply_anti_spoof","runtime":"podman","container_name":"c1","params":{"veth_name":"bad;veth","allocated_ips":["10.0.0.2"]}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&bad_spoof, &mut ctx).ok);

        let bad_spoof_rel = ActionRequest::from_json(
            r#"{"id":74,"action_type":"release_anti_spoof","runtime":"podman","container_name":"c1","params":{"veth_name":""}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&bad_spoof_rel, &mut ctx).ok);

        // 3. Quarantine release / confirm replaced node check
        let bad_q = ActionRequest::from_json(
            r#"{"id":75,"action_type":"release_network_quarantine","runtime":"incus","container_name":"c1","params":{"expected_node_id":"wrong","instance_id":"inst-1"}}"#,
        )
        .unwrap();
        let r_bad_q = execute_action_with_context(&bad_q, &mut ctx);
        assert!(!r_bad_q.ok);
        assert!(r_bad_q.message.contains("mismatch"));

        let bad_rep = ActionRequest::from_json(
            r#"{"id":76,"action_type":"confirm_replaced_network_quarantine","runtime":"docker","container_name":"c1","params":{"expected_node_id":"node-xyz","instance_id":"inst-1"}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&bad_rep, &mut ctx).ok);

        // 4. Panel domains allow & disallow update files cleanly while preserving env secrets
        let allow_req = ActionRequest::from_json(
            r#"{"id":77,"action_type":"allow_panel_domains","runtime":"host","container_name":"__host__","params":{"domains":["panel.example.com","API.EXAMPLE.COM."]}}"#,
        )
        .unwrap();
        let r_allow = execute_action_with_context(&allow_req, &mut ctx);
        assert!(r_allow.ok, "allow_panel_domains failed: {}", r_allow.message);
        let env_after_allow = fs::read_to_string(&env_file).unwrap();
        assert!(env_after_allow.contains("SHARED_SECRET=keep-me-secret"));
        assert!(env_after_allow.contains("SECURITY_ALLOWED_PANEL_DOMAINS=api.example.com,panel.example.com"));

        let disallow_req = ActionRequest::from_json(
            r#"{"id":78,"action_type":"disallow_panel_domains","runtime":"host","container_name":"__host__","params":{"domains":["api.example.com"]}}"#,
        )
        .unwrap();
        let r_disallow = execute_action_with_context(&disallow_req, &mut ctx);
        assert!(r_disallow.ok);
        let env_after_disallow = fs::read_to_string(&env_file).unwrap();
        assert!(env_after_disallow.contains("SECURITY_ALLOWED_PANEL_DOMAINS=panel.example.com"));

        // 5. Disk cleanup scan executes against mock host root, transitions to scanned, then execute deletes
        let mock_root = dir.join("mock_host");
        let apt_dir = mock_root.join("var/cache/apt/archives");
        fs::create_dir_all(&apt_dir).unwrap();
        let old_deb = apt_dir.join("stale.deb");
        fs::write(&old_deb, b"deb-bytes").unwrap();
        ctx.disk_cleanup_host_root = Some(mock_root.clone());
        ctx.cleanup_now_epoch = Some(crate::current_unix_ts() as i64 + 15 * 86_400);

        let scan_req = ActionRequest::from_json(
            r#"{"id":79,"action_type":"disk_cleanup_scan","runtime":"host","container_name":"__host__","params":{"expected_node_id":"node-xyz"}}"#,
        )
        .unwrap();
        let r_scan = execute_action_with_context(&scan_req, &mut ctx);
        assert!(r_scan.ok, "disk_cleanup_scan failed: {}", r_scan.message);
        assert_eq!(r_scan.status, "running");
        let receipt_json = r_scan.to_result_json("h1", "node-xyz");
        assert!(receipt_json.contains("\"cleanup_run\":{\"run_id\":\"action-79\""));

        // Wait briefly for worker thread to finalize action-79
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let j = app_guard::disk_cleanup::read_cleanup_journal_readonly(&cleanup_journal).unwrap();
            if j.runs.iter().any(|r| r.run_id == "action-79" && r.status == "scanned") {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "disk cleanup worker did not finish");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        // Duplicate scan must reflect already-scanned state without re-running as running
        let r_scan_dup = execute_action_with_context(&scan_req, &mut ctx);
        assert!(r_scan_dup.ok);
        assert_eq!(r_scan_dup.status, "succeeded");

        // Unconfirmed execute must fail; confirmed execute deletes stale.deb
        let exec_unconfirmed = ActionRequest::from_json(
            r#"{"id":80,"action_type":"disk_cleanup_execute","runtime":"host","container_name":"__host__","params":{"expected_node_id":"node-xyz","confirmed":false,"plan_id":"action-79"}}"#,
        )
        .unwrap();
        assert!(!execute_action_with_context(&exec_unconfirmed, &mut ctx).ok);

        let exec_confirmed = ActionRequest::from_json(
            r#"{"id":82,"action_type":"disk_cleanup_execute","runtime":"host","container_name":"__host__","params":{"expected_node_id":"node-xyz","confirmed":true,"plan_id":"action-79"}}"#,
        )
        .unwrap();
        let r_exec = execute_action_with_context(&exec_confirmed, &mut ctx);
        assert!(r_exec.ok, "disk_cleanup_execute failed: {}", r_exec.message);
        let deadline2 = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let j = app_guard::disk_cleanup::read_cleanup_journal_readonly(&cleanup_journal).unwrap();
            if j.runs.iter().any(|r| r.run_id == "action-82" && r.status == "succeeded") {
                break;
            }
            assert!(std::time::Instant::now() < deadline2, "disk cleanup execute did not finish");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(!old_deb.exists());

        // 5b. Empty node_id fails closed on node-bound quarantine & upgrade actions
        let mut empty_ctx = ActionContext::default();
        let q_empty = ActionRequest::from_json(
            r#"{"id":83,"action_type":"release_network_quarantine","runtime":"incus","container_name":"c1","params":{"expected_node_id":"","instance_id":"inst-1"}}"#,
        )
        .unwrap();
        let r_q_empty = execute_action_with_context(&q_empty, &mut empty_ctx);
        assert!(!r_q_empty.ok);
        assert!(r_q_empty.message.contains("node identity unavailable"));

        // 5c. Corrupt quarantine journal fails closed on disk_cleanup
        fs::write(&quarantine_journal, "{not-valid-json").unwrap();
        let corrupt_scan = ActionRequest::from_json(
            r#"{"id":84,"action_type":"disk_cleanup_scan","runtime":"host","container_name":"__host__","params":{"expected_node_id":"node-xyz"}}"#,
        )
        .unwrap();
        let r_corrupt = execute_action_with_context(&corrupt_scan, &mut ctx);
        assert!(!r_corrupt.ok);
        assert!(r_corrupt.message.contains("quarantine recovery journal"));
        let _ = fs::remove_file(&quarantine_journal);

        // 6. stop_container with incus + all/missing project fails closed via incus_health preflight
        let now_ts = crate::current_unix_ts() as i64;
        let stop_incus_json = format!(
            r#"{{"id":81,"action_type":"stop_container","runtime":"incus","project":"all","container_name":"c1","params":{{"reason":"sustained_connection_overload","metric_schema":1,"required_duration_seconds":10,"duration_seconds":20,"expires_at":{}}}}}"#,
            now_ts + 300
        );
        let stop_incus = ActionRequest::from_json(&stop_incus_json).unwrap();
        let r_stop = execute_action_with_context(&stop_incus, &mut ctx);
        assert!(!r_stop.ok);
        assert!(r_stop.message.contains("Incus stop skipped"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_apply_host_firewall_policy_requires_rfw_false_saves_speedtest_policy() {
        let dir = std::env::temp_dir().join(format!(
            "narwhal-actions-speedtest-pol-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let policy_file = dir.join("speedtest-policy.json");

        let mut ctx = ActionContext {
            node_id: "node-xyz".to_string(),
            speedtest_policy_path: Some(policy_file.clone()),
            ..ActionContext::default()
        };

        let req = ActionRequest::from_json(
            r#"{
                "id": 91,
                "action_type": "apply_host_firewall_policy",
                "runtime": "host",
                "container_name": "__host__",
                "params": {
                    "expected_node_id": "node-xyz",
                    "requires_rfw": false,
                    "policy": {
                        "revision": 7,
                        "rules": [],
                        "abuse": {
                            "speedtest": false,
                            "mining": false,
                            "bt": false,
                            "services": ["ookla", "fast"],
                            "service_runtimes": ["incus", "podman"]
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        let receipt = execute_action_with_context(&req, &mut ctx);
        assert!(receipt.ok, "expected ok receipt, got: {}", receipt.message);
        assert_eq!(
            receipt.message,
            "service policy saved for the selected Incus/Podman runtimes"
        );
        let saved = protocol_guard::speedtest::load_policy(Some(&policy_file))
            .expect("speedtest policy saved");
        assert!(!saved.invalid);
        assert_eq!(saved.revision, 7);
        assert_eq!(saved.services, vec!["fast", "ookla"]);
        assert_eq!(saved.runtimes, vec!["incus", "podman"]);

        // Invalid runtime in service_runtimes must fail
        let bad_req = ActionRequest::from_json(
            r#"{
                "id": 92,
                "action_type": "apply_host_firewall_policy",
                "runtime": "host",
                "container_name": "__host__",
                "params": {
                    "expected_node_id": "node-xyz",
                    "requires_rfw": false,
                    "policy": {
                        "revision": 8,
                        "rules": [],
                        "abuse": {
                            "services": ["ookla"],
                            "service_runtimes": ["docker"]
                        }
                    }
                }
            }"#,
        )
        .unwrap();
        let bad_receipt = execute_action_with_context(&bad_req, &mut ctx);
        assert!(!bad_receipt.ok);

        let _ = fs::remove_dir_all(&dir);
    }
