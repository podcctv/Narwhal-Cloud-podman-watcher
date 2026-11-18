#![allow(unused_imports)]
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use proc_probe::json_escape;
use runtime_drivers::JsonVal;
use crate::*;
use crate::disk_cleanup::*;
use crate::incus_health::*;
use crate::security_banner::*;
use crate::socks_detector::*;
use crate::util::*;


fn temp_dir(label: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = env::temp_dir().join(format!("narwhal-app-guard-{label}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp test dir");
    dir
}

// -----------------------------------------------------------------------
// 1. incus_health tests
// -----------------------------------------------------------------------

#[test]
fn test_incus_healthy_complete_snapshot_and_operations_health() {
    let inst_scan = r#"{
        "ok": true,
        "latency_ms": 42.5,
        "error": "",
        "items": [
            {"name": "c1", "project": "default", "status": "Running", "type": "container", "config": {"volatile.uuid": "uuid-1"}, "state": {"pid": 1001}}
        ]
    }"#;
    let ops_scan = r#"{
        "ok": true,
        "latency_ms": 18.0,
        "error": "",
        "items": [
            {"id": "op-fast", "status": "Running", "status_code": 103, "description": "Restarting instance", "created_at": "2026-11-16T00:00:00Z", "may_cancel": true, "resources": {"instances": ["/1.0/instances/c1?project=default"]}}
        ]
    }"#;
    // 120 seconds elapsed (< 300s stuck threshold)
    let now = parse_incus_created_epoch("2026-11-16T00:02:00Z").unwrap();
    let snap_json = build_incus_snapshot_json(inst_scan, ops_scan, "all", now);
    let snap = JsonVal::parse(&snap_json).expect("valid snapshot JSON");

    assert_eq!(snap.get_str("status"), Some("healthy"));
    assert_eq!(snap.get_str("scan_status"), Some("complete"));
    assert_eq!(snap.get_i64("instance_count"), Some(1));
    assert_eq!(snap.get_i64("error_instance_count"), Some(0));
    assert_eq!(snap.get_i64("active_lifecycle_operation_count"), Some(1));
    assert_eq!(snap.get_i64("stuck_lifecycle_operation_count"), Some(0));
    assert_eq!(snap.get("alerts").and_then(JsonVal::as_arr).map(|a| a.len()), Some(0));

    let ops_health_json = build_incus_operations_health_json(&snap_json);
    let ops_health = JsonVal::parse(&ops_health_json).expect("valid operations health JSON");
    assert_eq!(ops_health.get_str("source"), Some("incus_runtime"));
    assert_eq!(ops_health.get_str("status"), Some("healthy"));
    assert_eq!(
        ops_health.get("details").and_then(|d| d.get_i64("active_lifecycle_operations")),
        Some(1)
    );
}

#[test]
fn test_incus_detects_error_stuck_op_and_slow_api() {
    let inst_scan = r#"{
        "ok": true,
        "latency_ms": 3100.0,
        "error": "",
        "items": [
            {"name": "err-box", "project": "buyers", "status": "Error", "config": {"volatile.uuid": "uuid-err"}, "state": {"pid": 555}},
            {"name": "hang-box", "project": "default", "status": "Running", "config": {"volatile.uuid": "uuid-hang"}, "state": {"pid": 777}}
        ]
    }"#;
    let ops_scan = r#"{
        "ok": true,
        "latency_ms": 200.0,
        "error": "",
        "items": [
            {"id": "op-stuck", "status": "Running", "description": "Stopping instance", "created_at": "2026-11-16T00:00:00Z", "may_cancel": false, "resources": {"instances": ["/1.0/instances/hang-box"]}},
            {"id": "op-bad-time", "status_code": 103, "metadata": {"action": "delete"}, "created_at": "", "resources": {"containers": ["/1.0/containers/hang-box?project=default"]}}
        ]
    }"#;
    let now = parse_incus_created_epoch("2026-11-16T00:05:00Z").unwrap(); // exact 300s
    let (ops_health_json, alerts_json) =
        build_incus_health_and_alerts_json(inst_scan, ops_scan, "all", now);

    let oh = JsonVal::parse(&ops_health_json).unwrap();
    assert_eq!(oh.get_str("status"), Some("warning"));
    let details = oh.get("details").unwrap();
    assert_eq!(details.get_i64("error_instances"), Some(1));
    assert_eq!(details.get_i64("stuck_lifecycle_operations"), Some(1));
    assert_eq!(details.get_i64("active_lifecycle_operations"), Some(2));

    let alerts = JsonVal::parse(&alerts_json).unwrap();
    let arr = alerts.as_arr().unwrap();
    let types: BTreeSet<&str> = arr.iter().filter_map(|a| a.get_str("type")).collect();
    assert!(types.contains("incus_instance_error"));
    assert!(types.contains("incus_lifecycle_operation_stuck"));
    assert!(types.contains("incus_lifecycle_operation_unverified"));
    assert!(types.contains("incus_api_slow"));

    let err_alert = arr.iter().find(|a| a.get_str("type") == Some("incus_instance_error")).unwrap();
    assert_eq!(err_alert.get_str("severity"), Some("critical"));
    assert_eq!(err_alert.get_str("instance_id"), Some("uuid-err"));
    assert!(err_alert.get_str("message").unwrap().contains("/var/log/incus/uuid-err/lxc.log"));

    let stuck_alert = arr
        .iter()
        .find(|a| a.get_str("type") == Some("incus_lifecycle_operation_stuck"))
        .unwrap();
    assert_eq!(stuck_alert.get_str("severity"), Some("critical"));
    assert_eq!(stuck_alert.get_f64("threshold"), Some(300.0));
    assert!(stuck_alert.get_str("message").unwrap().contains("不可取消"));
}

#[test]
fn test_incus_unavailable_and_stop_preflight() {
    let bad_scan = r#"{"ok":false,"items":[],"latency_ms":8001.0,"error":"timeout"}"#;
    let snap_json = build_incus_snapshot_json(bad_scan, "", "default", 1_700_000_000.0);
    let snap = JsonVal::parse(&snap_json).unwrap();
    assert_eq!(snap.get_str("status"), Some("unavailable"));
    assert_eq!(snap.get_str("scan_status"), Some("unavailable"));
    let types: BTreeSet<&str> = snap
        .get("alerts")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .filter_map(|a| a.get_str("type"))
        .collect();
    assert!(types.contains("incus_api_unavailable"));
    assert!(types.contains("incus_operation_inventory_unavailable"));

    let ok_inst = IncusScan::from_cli_output(
        true,
        r#"[{"name":"c1","project":"default","status":"Running","type":"container"}]"#,
        50.0,
        "",
    );
    let ok_ops = IncusScan::from_cli_output(true, "[]", 50.0, "");
    let cfg = IncusHealthConfig::default();
    assert!(evaluate_incus_stop_preflight(&ok_inst, &ok_ops, "default", "c1", &cfg).is_ok());
    assert!(evaluate_incus_stop_preflight(&ok_inst, &ok_ops, "all", "c1", &cfg).is_err());

    let busy_ops = IncusScan::from_cli_output(
        true,
        r#"[{"id":"op1","status":"Running","description":"Stopping","resources":{"instances":["/1.0/instances/c1"]}}]"#,
        50.0,
        "",
    );
    assert!(evaluate_incus_stop_preflight(&ok_inst, &busy_ops, "default", "c1", &cfg).is_err());
}

// -----------------------------------------------------------------------
// 2. socks_detector & panel pairing tests
// -----------------------------------------------------------------------

#[test]
fn test_password_profile_and_gost_url_and_no_secret_leak() {
    let prof_json = password_profile_json(Some("Ab112!中文"));
    let prof = JsonVal::parse(&prof_json).unwrap();
    assert_eq!(prof.get_bool("available"), Some(true));
    assert_eq!(prof.get_i64("length"), Some(8));
    assert_eq!(prof.get_i64("lowercase"), Some(1));
    assert_eq!(prof.get_i64("uppercase"), Some(1));
    assert_eq!(prof.get_i64("digits"), Some(3));
    assert_eq!(prof.get_i64("symbols"), Some(1));
    assert_eq!(prof.get_i64("other"), Some(2));
    assert_eq!(prof.get_i64("repeated_digits"), Some(1));
    assert_eq!(prof.get_i64("max_digit_frequency"), Some(2));
    assert_eq!(prof.get_i64("longest_identical_run"), Some(2));
    assert!(!prof_json.contains("Ab112!"));

    let ref_prof = JsonVal::parse(&password_profile_json(Some("${ENV_PASS}"))).unwrap();
    assert_eq!(ref_prof.get_bool("available"), Some(false));

    let g1 = JsonVal::parse(&gost_url_json("socks5://alice:super-secret-pw@0.0.0.0:1080")).unwrap();
    assert_eq!(g1.get_i64("port"), Some(1080));
    assert_eq!(g1.get_str("listen"), Some("0.0.0.0"));
    assert_eq!(g1.get_str("auth_state"), Some("unknown"));
    assert!(!gost_url_json("socks5://alice:super-secret-pw@0.0.0.0:1080").contains("super-secret-pw"));

    let g2 = JsonVal::parse(&gost_url_json("socks+tls://:1080")).unwrap();
    assert_eq!(g2.get_str("listen"), Some("*"));
    assert_eq!(g2.get_i64("port"), Some(1080));
    assert_eq!(gost_url_json("http://127.0.0.1:8080"), "null");
}

#[test]
fn test_standalone_panels_and_socks_config_and_exposure() {
    let ps = "210 S sui /usr/local/s-ui/sui\n211 S x-ui /usr/local/x-ui/x-ui\n212 S sh sh -c /usr/local/s-ui/sui\n213 S vim vim /etc/x-ui/config\n214 Z sui /usr/local/s-ui/sui\n215 S sui /usr/bin/x-ui\n";
    let panels_json = standalone_panels_json(ps);
    let panels = JsonVal::parse(&panels_json).unwrap();
    let arr = panels.as_arr().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0].get_i64("pid"), Some(210));
    assert_eq!(arr[0].get_str("panel"), Some("S-ui"));
    assert_eq!(arr[0].get_bool("auto_stop_eligible"), Some(false));
    assert_eq!(arr[1].get_i64("pid"), Some(211));
    assert_eq!(arr[1].get_str("panel"), Some("X-ui"));
    assert!(!panels_json.contains("/usr/local"));

    let xray_cfg = r#"{/* comment */ "inbounds": [{"protocol": "vless", "port": 443}, {"protocol": "socks", "port": 1080, "settings": {"auth": "password", "users": [{"user": "u", "pass": "password"}]}}], "outbounds": [{"protocol": "socks", "tag": "https://example.test"}]}"#;
    let parsed = JsonVal::parse(&parse_socks_config_json(xray_cfg, "xray")).unwrap();
    assert_eq!(parsed.get_bool("parsed"), Some(true));
    assert_eq!(parsed.get_bool("single_purpose"), Some(false));
    let ep = &parsed.get("endpoints").unwrap().as_arr().unwrap()[0];
    assert_eq!(ep.get_i64("port"), Some(1080));
    assert_eq!(ep.get_str("auth_state"), Some("weak_password"));

    assert_eq!(is_listener_exposed("[::1]:1080", &[]), Some(false));
    assert_eq!(is_listener_exposed("[::ffff:127.0.0.1]:1080", &[]), Some(false));
    assert_eq!(is_listener_exposed("0.0.0.0:1080", &[]), Some(true));
    assert_eq!(
        is_listener_exposed(
            "127.0.0.1:1080",
            &[("tcp:127.0.0.1:1080".to_string(), "tcp:0.0.0.0:8080".to_string())]
        ),
        Some(true)
    );
}

#[test]
fn test_manage_panel_domains_updates_state_and_env_without_leaking_secrets() {
    let dir = temp_dir("panel-domains");
    let allow_file = dir.join("panel-allowlist.json");
    let auto_file = dir.join("panel-auto-remediate.json");
    let env_file = dir.join("client.env");
    fs::write(
        &auto_file,
        r#"{"domains":["panel.example.net","bad.example.net"],"updated_at":100}"#,
    )
    .unwrap();
    fs::write(
        &env_file,
        "SERVER_URL=https://watcher.local\nSHARED_SECRET=top-secret-hmac-key-never-leak\nSECURITY_ALLOWED_PANEL_DOMAINS=trusted.example.com\n",
    )
    .unwrap();

    let store = PanelDomainStore {
        allowlist_path: allow_file.clone(),
        auto_remediate_path: Some(auto_file.clone()),
        env_file_path: Some(env_file.clone()),
        env_allowed_domains: Vec::new(),
    };

    let allow_res = manage_panel_domains(
        &store,
        PanelDomainAction::Allow,
        &["Panel.Example.NET.".to_string()],
        1_700_000_000,
    )
    .expect("allow panel domains");
    assert!(allow_res.ok);
    assert_eq!(
        allow_res.allowlist,
        vec!["panel.example.net".to_string(), "trusted.example.com".to_string()]
    );
    assert_eq!(allow_res.auto_remediate, vec!["bad.example.net".to_string()]);
    assert!(!allow_res.to_json().contains("top-secret-hmac-key-never-leak"));

    let env_after_allow = fs::read_to_string(&env_file).unwrap();
    assert!(env_after_allow.contains("SHARED_SECRET=top-secret-hmac-key-never-leak"));
    assert!(env_after_allow.contains("SECURITY_ALLOWED_PANEL_DOMAINS=panel.example.net,trusted.example.com"));

    let disallow_res = manage_panel_domains(
        &store,
        PanelDomainAction::Disallow,
        &["panel.example.net".to_string()],
        1_700_000_010,
    )
    .expect("disallow panel domains");
    assert_eq!(disallow_res.allowlist, vec!["trusted.example.com".to_string()]);
    let env_after_disallow = fs::read_to_string(&env_file).unwrap();
    assert!(env_after_disallow.contains("SHARED_SECRET=top-secret-hmac-key-never-leak"));
    assert!(env_after_disallow.contains("SECURITY_ALLOWED_PANEL_DOMAINS=trusted.example.com"));

    // Invalid domain supply on allow fails closed
    let bad = manage_panel_domains(
        &store,
        PanelDomainAction::Allow,
        &["not a domain!".to_string()],
        1_700_000_020,
    );
    assert!(bad.is_err());

    let _ = fs::remove_dir_all(&dir);
}

// -----------------------------------------------------------------------
// 3. disk_cleanup tests
// -----------------------------------------------------------------------

#[test]
fn test_validate_cleanup_policy_and_node_binding() {
    let ok = validate_cleanup_policy(
        r#"{"enabled":true,"include_containers":false,"retention_days":30,"interval_hours":12,"node_id":"node-1"}"#,
        Some("node-1"),
    )
    .expect("valid policy");
    assert!(ok.enabled);
    assert!(!ok.include_containers);
    assert_eq!(ok.retention_days, 30);
    assert_eq!(ok.interval_hours, 12);

    // Node mismatch must fail closed to default (enabled=false)
    let foreign = validate_cleanup_policy(
        r#"{"enabled":true,"node_id":"old-node"}"#,
        Some("new-node"),
    )
    .expect("mismatch resets to default");
    assert!(!foreign.enabled);

    // Invalid types, bounds, and arbitrary keys rejected
    for bad in [
        r#"{"enabled":"true"}"#,
        r#"{"retention_days":true}"#,
        r#"{"retention_days":13}"#,
        r#"{"retention_days":91}"#,
        r#"{"interval_hours":5}"#,
        r#"{"interval_hours":169}"#,
        r#"{"paths":["/root"],"command":"rm"}"#,
    ] {
        assert!(validate_cleanup_policy(bad, None).is_err(), "expected err for {bad}");
    }
}

#[test]
fn test_cleanup_journal_load_recovery_and_action_safety_checks() {
    let dir = temp_dir("disk-cleanup");
    let journal = dir.join("disk-cleanup.json");

    // Pre-seed an interrupted 'running' run and confirm recovery marks it interrupted
    let mut initial = CleanupJournalState {
        runs: vec![CleanupRunRecord {
            run_id: "action-1".to_string(),
            action_id: 1,
            node_id: "node-a".to_string(),
            mode: "scan".to_string(),
            automatic: false,
            started_at: 1_700_000_000,
            finished_at: None,
            status: "running".to_string(),
            targets: vec![CleanupTarget::host()],
            items: vec![],
            plan_id: String::new(),
            delivered: false,
            error: String::new(),
        }],
        attempts: BTreeMap::new(),
    };
    save_cleanup_journal(&journal, &mut initial).unwrap();
    let recovered = load_cleanup_journal(&journal, 1_700_000_050).unwrap();
    assert_eq!(recovered.runs[0].status, "interrupted");
    assert_eq!(recovered.runs[0].finished_at, Some(1_700_000_050));

    // Corrupt journal fails closed
    let bad_journal = dir.join("bad-cleanup.json");
    fs::write(&bad_journal, r#"{"runs":"not-a-list","attempts":{}}"#).unwrap();
    assert!(load_cleanup_journal(&bad_journal, 1_700_000_050).is_err());

    // Action safety checks
    let ctx = CleanupActionContext {
        host_available: true,
        node_id: "node-a".to_string(),
        now_epoch: 1_700_000_100,
        journal_path: dir.join("actions.json"),
        policy: CleanupPolicy::default(),
        containers: vec![
            CleanupContainerCandidate {
                runtime: "docker".to_string(),
                runtime_bin: "docker".to_string(),
                project: "".to_string(),
                name: "docker-biz".to_string(),
                id: "d1".to_string(),
                stable_id: "d1".to_string(),
                instance_id: "".to_string(),
                pid: "100".to_string(),
                pid_start_ticks: "1".to_string(),
            },
            CleanupContainerCandidate {
                runtime: "podman".to_string(),
                runtime_bin: "podman".to_string(),
                project: "".to_string(),
                name: "narwhal-monitor-client".to_string(),
                id: "p0".to_string(),
                stable_id: "p0".to_string(),
                instance_id: "".to_string(),
                pid: "101".to_string(),
                pid_start_ticks: "1".to_string(),
            },
            CleanupContainerCandidate {
                runtime: "podman".to_string(),
                runtime_bin: "podman".to_string(),
                project: "".to_string(),
                name: "app1".to_string(),
                id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                stable_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                instance_id: "".to_string(),
                pid: "102".to_string(),
                pid_start_ticks: "2".to_string(),
            },
        ],
        quarantined_identities: BTreeSet::new(),
        active_run_in_progress: false,
    };

    // Node mismatch rejected
    let wrong_node = execute_disk_cleanup_action(
        r#"{"id":10,"action_type":"disk_cleanup_scan","params":{"expected_node_id":"other"}}"#,
        &ctx,
    );
    assert!(!wrong_node.ok);

    // Scan succeeds and excludes docker & protected containers
    let scan_res = execute_disk_cleanup_action(
        r#"{"id":10,"action_type":"disk_cleanup_scan","params":{"expected_node_id":"node-a"}}"#,
        &ctx,
    );
    assert!(scan_res.ok);
    assert_eq!(scan_res.targets.len(), 2);
    assert_eq!(scan_res.targets[0].name, "__host__");
    assert_eq!(scan_res.targets[1].name, "app1");

    // Duplicate action_id is idempotent
    let dup_res = execute_disk_cleanup_action(
        r#"{"id":10,"action_type":"disk_cleanup_scan","params":{"expected_node_id":"node-a"}}"#,
        &ctx,
    );
    assert!(dup_res.ok);
    assert_eq!(dup_res.status, "accepted");

    // Prepare completed scan plan for execute checks
    let mut plan_state = CleanupJournalState {
        runs: vec![CleanupRunRecord {
            run_id: "action-11".to_string(),
            action_id: 11,
            node_id: "node-a".to_string(),
            mode: "scan".to_string(),
            automatic: false,
            started_at: 1_700_000_000,
            finished_at: Some(1_700_000_010),
            status: "scanned".to_string(),
            targets: vec![CleanupTarget::host()],
            items: vec![CleanupRunItem {
                runtime: "host".to_string(),
                name: "__host__".to_string(),
                project: String::new(),
                status: "scanned".to_string(),
                reason: String::new(),
                instance_id: "host".to_string(),
                candidate_files: 1,
                candidate_bytes: 1024,
                deleted_files: 0,
                unlinked_bytes: 0,
                freed_bytes: 0,
                skipped: 0,
                errors: 0,
                bounded: false,
                extra_fields: BTreeMap::new(),
            }],
            plan_id: String::new(),
            delivered: false,
            error: String::new(),
        }],
        attempts: BTreeMap::new(),
    };
    save_cleanup_journal(&ctx.journal_path, &mut plan_state).unwrap();

    // Missing confirmation rejected
    let unconfirmed = execute_disk_cleanup_action(
        r#"{"id":12,"action_type":"disk_cleanup_execute","params":{"expected_node_id":"node-a","confirmed":false,"plan_id":"action-11"}}"#,
        &ctx,
    );
    assert!(!unconfirmed.ok);

    // Stale scan (> 900s) rejected
    let mut stale_ctx = ctx.clone();
    stale_ctx.now_epoch = 1_700_000_901;
    let stale_exec = execute_disk_cleanup_action(
        r#"{"id":12,"action_type":"disk_cleanup_execute","params":{"expected_node_id":"node-a","confirmed":true,"plan_id":"action-11"}}"#,
        &stale_ctx,
    );
    assert!(!stale_exec.ok);

    // Fresh confirmed execute succeeds and records attempt cooldown
    let exec_ok = execute_disk_cleanup_action(
        r#"{"id":12,"action_type":"disk_cleanup_execute","params":{"expected_node_id":"node-a","confirmed":true,"plan_id":"action-11"}}"#,
        &ctx,
    );
    assert!(exec_ok.ok);
    assert_eq!(exec_ok.status, "running");
    let after_exec = load_cleanup_journal(&ctx.journal_path, ctx.now_epoch + 1).unwrap();
    assert!(after_exec.attempts.contains_key("[\"host\",\"\",\"__host__\",\"host\"]"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_allowlist_rules_and_bounded_sweep() {
    assert_eq!(
        is_allowlisted_cleanup_file("var/log/syslog.1.gz"),
        Some((CleanupCategory::ArchivedLogs, 14))
    );
    assert_eq!(
        is_allowlisted_cleanup_file("var/cache/apt/archives/curl_8.0.deb"),
        Some((CleanupCategory::PackageCache, 1))
    );
    assert_eq!(
        is_allowlisted_cleanup_file(&format!("var/log/journal/{}/system@abc-123.journal", "a".repeat(32))),
        Some((CleanupCategory::ArchivedLogs, 14))
    );
    assert!(is_allowlisted_cleanup_file("var/log/syslog").is_none());
    assert!(is_allowlisted_cleanup_file("var/log/auth.log.1.gz").is_none());
    assert!(is_allowlisted_cleanup_file(&format!("var/log/journal/{}/system.journal", "a".repeat(32))).is_none());

    let dir = temp_dir("sweep");
    let log_dir = dir.join("var/log");
    fs::create_dir_all(&log_dir).unwrap();
    let old_archive = log_dir.join("syslog.1.gz");
    let active_log = log_dir.join("syslog");
    let auth_log = log_dir.join("auth.log.1.gz");
    fs::write(&old_archive, b"archive-bytes").unwrap();
    fs::write(&active_log, b"active-syslog").unwrap();
    fs::write(&auth_log, b"auth-log").unwrap();

    let future = util::now_unix_secs() + 30 * 86_400;
    let scan = sweep_cleanup_root(
        &dir,
        false,
        14,
        disk_cleanup::MAX_BYTES,
        disk_cleanup::MAX_FILES,
        future,
        &BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(scan.candidate_files, 1);
    assert_eq!(scan.deleted_files, 0);
    assert!(old_archive.exists());

    let clean = sweep_cleanup_root(
        &dir,
        true,
        14,
        disk_cleanup::MAX_BYTES,
        disk_cleanup::MAX_FILES,
        future,
        &BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(clean.deleted_files, 1);
    assert!(!old_archive.exists());
    assert!(active_log.exists());
    assert!(auth_log.exists());

    let _ = fs::remove_dir_all(&dir);
}

// -----------------------------------------------------------------------
// 4. security_banner tests
// -----------------------------------------------------------------------

#[test]
fn test_safe_banner_text_strips_ansi_control_and_redacts_secrets() {
    let raw = "\x1b]0;EvilTitle\x07\x1b[31mAlert\x1b[0m\u{200B}\n password=hunter2 Token: abc123 api-key = k999 secret:xyz";
    let sanitized = safe_banner_text(raw, 300);
    assert!(!sanitized.contains('\x1b'));
    assert!(!sanitized.contains('\n'));
    assert!(!sanitized.contains('\u{200B}'));
    assert!(!sanitized.contains("hunter2"));
    assert!(!sanitized.contains("abc123"));
    assert!(!sanitized.contains("k999"));
    assert!(!sanitized.contains("xyz"));
    assert!(sanitized.contains("password=[REDACTED]"));
    assert!(sanitized.contains("Token: [REDACTED]"));
    assert!(sanitized.contains("api-key = [REDACTED]"));
    assert!(sanitized.contains("secret:[REDACTED]"));
    assert!(sanitized.starts_with("Alert"));
}

#[test]
fn test_beijing_time_utc_plus_8_and_legacy() {
    assert_eq!(beijing_time(Some(0.0), ""), "1970-01-01 08:00:00");
    assert_eq!(
        beijing_time(None, "2026-10-08 23:00:00 UTC"),
        "2026-10-09 07:00:00"
    );
    assert_eq!(beijing_time(Some(1_791_509_400.0), ""), "2026-10-09 09:30:00");
    assert_eq!(beijing_time(Some(f64::NAN), ""), "");
    assert_eq!(beijing_time(None, "invalid"), "");
}

#[test]
fn test_render_motd_banner_closed_widths_metrics_history_and_merge() {
    // Width invariance across all supported widths and color modes
    let entries_json = r#"[{
        "type": "container_connection_count",
        "title": "连接数偏高",
        "detail": "连接数量偏高",
        "state": "active",
        "severity": "warning",
        "metrics": "value=738 / threshold=500 / duration_seconds=720",
        "time_epoch": 1791509400
    }]"#;
    for &width in &[12usize, 16, 24, 32, 40, 52, 68, 80, 100] {
        for &color in &[false, true] {
            let opts = MotdRenderOptions {
                language: "zh".to_string(),
                width,
                color,
                stale: false,
                sampled_at: Some(1_791_509_400.0),
                now_epoch: None,
                dynamic_history_age: false,
            };
            let card = render_motd_banner(entries_json, &opts);
            for line in card.lines() {
                let plain = strip_csi_sgr_for_test(line);
                assert_eq!(cell_width(&plain), width, "width={width} line={plain:?}");
            }
        }
    }

    // Check numeric evidence & Beijing timestamp formatting
    let opts100 = MotdRenderOptions {
        width: 100,
        sampled_at: Some(1_791_509_400.0),
        ..MotdRenderOptions::default()
    };
    let card100 = render_motd_banner(entries_json, &opts100);
    assert!(card100.contains("连接 738 条（预警 500 条）；持续 12 分钟"));
    assert!(card100.contains("2026-10-09 09:30:00"));
    assert!(!card100.contains("value="));

    // Historical recovered alert tense & duration
    let hist_json = r#"[{
        "type": "connections",
        "title": "连接数过高",
        "state": "verified",
        "historical": true,
        "first_seen_epoch": 1000,
        "time_epoch": 1600,
        "recovered_at_epoch": 2800,
        "detail": "容器当前连接 738 条"
    }]"#;
    let hist_card = render_motd_banner(
        hist_json,
        &MotdRenderOptions {
            width: 100,
            sampled_at: Some(6400.0),
            ..MotdRenderOptions::default()
        },
    );
    assert!(hist_card.contains("历史告警 · 已恢复"));
    assert!(hist_card.contains("当时情况：容器当时连接 738 条"));
    assert!(hist_card.contains("恢复于：1小时0分钟前"));
    assert!(hist_card.contains("告警持续约 30 分钟"));
    assert!(hist_card.contains("目前容器无异常"));

    // Stale & merge behavior
    let stale_card = render_motd_banner(
        "[]",
        &MotdRenderOptions {
            stale: true,
            ..MotdRenderOptions::default()
        },
    );
    assert!(stale_card.contains("当前状态未知"));
    assert!(!stale_card.contains("目前容器无异常"));

    let merged = merge_motd_banner("user motd\n", &card100).unwrap();
    assert!(merged.starts_with(security_banner::START_MARKER));
    assert!(merged.ends_with("user motd\n"));
    assert!(merge_motd_banner("# >>> NARWHAL SECURITY ALERT BEGIN >>>\nbroken", &card100).is_err());
}

#[test]
fn test_socks_inbound_protocols_process_configs_and_gost_cli() {
    // Xray xhttp ALPN h3 -> udp, h2 -> tcp, mixed -> ambiguous (omitted), masque -> omitted
    let xhttp_h3 = r#"{"inbounds":[{"protocol":"vmess","port":443,"streamSettings":{"method":"xhttp","security":"tls","tlsSettings":{"alpn":["h3"]}}}]}"#;
    let r_h3 = JsonVal::parse(&parse_inbound_protocols_json(xhttp_h3, "xray")).unwrap();
    assert_eq!(
        r_h3.get("endpoints").unwrap().as_arr().unwrap()[0]
            .get("transports")
            .unwrap()
            .as_arr()
            .unwrap()[0]
            .as_str(),
        Some("udp")
    );

    let xhttp_mix = r#"{"inbounds":[{"protocol":"vmess","port":443,"streamSettings":{"method":"xhttp","security":"tls","tlsSettings":{"alpn":["h2","h3"]}}}]}"#;
    let r_mix = JsonVal::parse(&parse_inbound_protocols_json(xhttp_mix, "xray")).unwrap();
    assert!(r_mix.get("endpoints").unwrap().as_arr().unwrap()[0].get("transports").is_none());

    let sing_box = r#"{"inbounds":[{"type":"trojan","listen":"0.0.0.0","listen_port":443},{"type":"socks","listen":"127.0.0.1","listen_port":1080}]}"#;
    let r_sb = JsonVal::parse(&parse_inbound_protocols_json(sing_box, "sing-box")).unwrap();
    let sb_eps = r_sb.get("endpoints").unwrap().as_arr().unwrap();
    assert_eq!(sb_eps[0].get("transports").unwrap().as_arr().unwrap()[0].as_str(), Some("tcp"));
    assert!(sb_eps[1].get("transports").is_none());

    // process_configs exact binary + safe path checks
    let ps = "1 S supervise-daemo supervise-daemon xray --start\n12 S xray /usr/bin/xray run -config /opt/proxy/test.json -confdir /etc/xray/conf.d\n15 S sing-box /usr/bin/sing-box run -C /etc/sing-box\n18 S xray /usr/bin/xray run -c /etc/xray/../secret.json\n";
    let procs = JsonVal::parse(&parse_process_configs_json(ps)).unwrap();
    let arr = procs.as_arr().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0].get_i64("pid"), Some(12));
    assert_eq!(arr[0].get_bool("additional_configs"), Some(false));
    assert_eq!(arr[1].get_i64("pid"), Some(15));
    assert_eq!(arr[1].get("config_dirs").unwrap().as_arr().unwrap()[0].as_str(), Some("/etc/sing-box"));
    assert_eq!(arr[2].get_bool("additional_configs"), Some(true));

    // 3proxy CL password profile & gost CLI -L without -F leak
    let leg = JsonVal::parse(&legacy_profiles_json("users alice:CL:StrongPass99!\n", "3proxy")).unwrap();
    assert_eq!(leg.as_arr().unwrap()[0].get_bool("available"), Some(true));
    assert!(!legacy_profiles_json("users alice:CL:StrongPass99!\n", "3proxy").contains("StrongPass99"));

    let gost_ps = "42 S gost /usr/bin/gost -L socks5://u:pw123@:1080 -F socks5://:2080\n";
    let gcli = JsonVal::parse(&gost_cli_json(gost_ps, 42)).unwrap();
    assert_eq!(gcli.get_bool("single_purpose"), Some(true));
    assert_eq!(gcli.get("endpoints").unwrap().as_arr().unwrap().len(), 1);
    assert!(!gost_cli_json(gost_ps, 42).contains("pw123"));
    assert_eq!(socks_greeting_mode(&[0x05, 0x00]), "no_auth");
    assert_eq!(socks_greeting_mode(&[0x05, 0x02]), "auth_required");
    assert_eq!(socks_greeting_mode(&[0x05, 0xff]), "unknown");
    assert!(panel_domain_allowed("sub.trusted.example.com", &["*.trusted.example.com".to_string()]));
}

#[test]
fn test_incus_timezone_offsets_partial_scan_and_project_filtering() {
    let inst_scan = r#"{"ok":true,"latency_ms":10.0,"items":[{"name":"vm1","project":"buyers","status":"Running","config":{"volatile.uuid":"u1"}}]}"#;
    let ops_scan = r#"{
        "ok": true,
        "latency_ms": 20.0,
        "items": [
            {"id":"op-other","status":"Running","description":"Stopping","created_at":"2026-11-16T00:00:00+08:00","resources":{"instances":["/1.0/instances/other?project=buyers"]}},
            {"id":"op-match","status":"Running","description":"Restarting","created_at":"2026-11-16T08:00:00+08:00","may_cancel":true,"resources":{"instances":["/1.0/instances/vm1?project=buyers"]}}
        ]
    }"#;
    // 2026-11-16T08:00:00+08:00 == 2026-11-16T00:00:00Z; check at 00:05:00Z (300s exact -> stuck)
    let now = parse_incus_created_epoch("2026-11-16T00:05:00Z").unwrap();
    let snap = JsonVal::parse(&build_incus_snapshot_json(inst_scan, ops_scan, "all", now)).unwrap();
    assert_eq!(snap.get_i64("active_lifecycle_operation_count"), Some(1));
    assert_eq!(snap.get_i64("stuck_lifecycle_operation_count"), Some(1));
    assert_eq!(snap.get_str("status"), Some("degraded"));

    // Partial scan (instances ok, operations failed)
    let partial = JsonVal::parse(&build_incus_snapshot_json(inst_scan, r#"{"ok":false,"error":"timeout"}"#, "buyers", now)).unwrap();
    assert_eq!(partial.get_str("scan_status"), Some("partial"));
    assert_eq!(partial.get_str("status"), Some("degraded"));
}

#[test]
fn test_disk_cleanup_quarantine_and_podman_cooldown_truncation_and_banner_copy() {
    let pod_target = CleanupTarget {
        runtime: "podman".to_string(),
        runtime_bin: "podman".to_string(),
        project: "".to_string(),
        name: "c".to_string(),
        id: "a".repeat(12),
        stable_id: "a".repeat(64),
        instance_id: String::new(),
        pid: String::new(),
        pid_start_ticks: String::new(),
    };
    assert_eq!(
        cleanup_cooldown_key(&pod_target),
        format!("[\"podman\",\"\",\"c\",\"{}\"]", "a".repeat(12))
    );

    let dir = temp_dir("quarantine-cleanup");
    let mut quarantined = BTreeSet::new();
    quarantined.insert("uuid-quarantined".to_string());
    let ctx = CleanupActionContext {
        host_available: true,
        node_id: "n1".to_string(),
        now_epoch: 1_700_000_000,
        journal_path: dir.join("j.json"),
        policy: CleanupPolicy::default(),
        containers: vec![CleanupContainerCandidate {
            runtime: "incus".to_string(),
            runtime_bin: "incus".to_string(),
            project: "default".to_string(),
            name: "q-box".to_string(),
            id: "uuid-quarantined".to_string(),
            stable_id: "uuid-quarantined".to_string(),
            instance_id: String::new(),
            pid: "50".to_string(),
            pid_start_ticks: "10".to_string(),
        }],
        quarantined_identities: quarantined,
        active_run_in_progress: false,
    };
    let res = execute_disk_cleanup_action(
        r#"{"id":7,"action_type":"disk_cleanup_scan","params":{"expected_node_id":"n1"}}"#,
        &ctx,
    );
    assert!(res.ok);
    assert_eq!(res.targets.len(), 1); // quarantined container excluded, only __host__ remains
    assert_eq!(res.targets[0].name, "__host__");

    // Panel pairing MOTD copy omits config paths and unrelated ports
    let panel_json = r#"[{
        "type": "unauthorized_panel_pairing",
        "state": "awaiting_report",
        "severity": "critical",
        "detail": "未授权面板域名 xb.netech.eu.org；节点程序特征 xboard-node；配置文件 /etc/xboard-node/config.yml；容器内部监听端口 22,5355,65530",
        "metrics": "value=1 / threshold=1"
    }]"#;
    let panel_card = render_motd_banner(
        panel_json,
        &MotdRenderOptions {
            width: 100,
            ..MotdRenderOptions::default()
        },
    );
    assert!(panel_card.contains("疑似第三方面板对接"));
    assert!(panel_card.contains("面板：xb.netech.eu.org"));
    assert!(panel_card.contains("已执行处理，等待复查确认"));
    assert!(!panel_card.contains("65530"));
    assert!(!panel_card.contains("config.yml"));

    // Shell hook merge preserves original
    let rc = merge_shell_hook("return\n# custom\n", shell_hook()).unwrap();
    assert!(rc.ends_with("return\n# custom\n"));
    assert_eq!(merge_shell_hook(&rc, shell_hook()).unwrap(), rc);

    // Font F-stem columns align identically across all 4 stem rows at width 68
    let font_card = render_motd_banner(
        "[]",
        &MotdRenderOptions {
            width: 68,
            color: false,
            ..MotdRenderOptions::default()
        },
    );
    let font_lines: Vec<&str> = font_card.lines().skip(2).take(5).collect();
    let pipe_positions: BTreeSet<usize> = font_lines[1..]
        .iter()
        .filter_map(|row| row.find('|'))
        .collect();
    assert_eq!(pipe_positions.len(), 1);

    // OSC-8 hyperlink with ST terminator (\x1b\\) stripped safely
    assert_eq!(
        safe_banner_text("\x1b]8;;https://evil.example\x1b\\SafeLink\x1b]8;;\x1b\\", 100),
        "SafeLink"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_json_wrappers_and_symlink_and_capacity_guards() {
    let pol_ok = JsonVal::parse(&validate_cleanup_policy_json(
        r#"{"enabled":true,"retention_days":90,"interval_hours":168}"#,
        None,
    ))
    .unwrap();
    assert_eq!(pol_ok.get_bool("ok"), Some(true));
    let pol_bad = JsonVal::parse(&validate_cleanup_policy_json(
        r#"{"retention_days":91}"#,
        None,
    ))
    .unwrap();
    assert_eq!(pol_bad.get_bool("ok"), Some(false));

    let dir = temp_dir("wrappers");
    let store = PanelDomainStore {
        allowlist_path: dir.join("allow.json"),
        auto_remediate_path: Some(dir.join("auto.json")),
        env_file_path: None,
        env_allowed_domains: Vec::new(),
    };
    let dom_res = JsonVal::parse(&manage_panel_domains_json(
        &store,
        "allow_panel_domains",
        &["192.0.2.10".to_string()],
        1_700_000_000,
    ))
    .unwrap();
    assert_eq!(dom_res.get_bool("ok"), Some(true));
    assert_eq!(
        dom_res.get("allowlist").unwrap().as_arr().unwrap()[0].as_str(),
        Some("192.0.2.10")
    );

    let ctx = CleanupActionContext {
        host_available: false,
        node_id: "n1".to_string(),
        journal_path: dir.join("j.json"),
        ..CleanupActionContext::default()
    };
    let act_res = JsonVal::parse(&execute_disk_cleanup_action_json(
        r#"{"id":1,"action_type":"disk_cleanup_scan","params":{"expected_node_id":"n1"}}"#,
        &ctx,
    ))
    .unwrap();
    assert_eq!(act_res.get_bool("ok"), Some(false));

    // select_motd_entries enforces 1 notice + up to 2 current + 1 historical (3+1 total)
    let mut entries = vec![MotdEntry {
        entry_type: "user_notice".to_string(),
        time_epoch: Some(50.0),
        detail: "notice".to_string(),
        ..MotdEntry::default()
    }];
    for i in 1..=4 {
        entries.push(MotdEntry {
            entry_type: "cpu".to_string(),
            time_epoch: Some(i as f64),
            state: "active".to_string(),
            ..MotdEntry::default()
        });
    }
    entries.push(MotdEntry {
        entry_type: "memory".to_string(),
        state: "verified".to_string(),
        historical: true,
        recovered_at_epoch: Some(100.0),
        ..MotdEntry::default()
    });
    let selected = select_motd_entries(&entries);
    assert_eq!(selected.len(), 4);
    assert_eq!(selected[0].entry_type, "user_notice");
    assert!(selected[3].historical);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_cleanup_readonly_journal_and_finalize_run() {
    use disk_cleanup::{
        execute_and_finalize_cleanup_run, execute_disk_cleanup_action,
        mark_cleanup_run_delivered, read_cleanup_journal_readonly, CleanupActionContext,
        CleanupPolicy, DAY_SECONDS,
    };
    let dir = temp_dir("cleanup_finalize");
    let root = dir.join("mock_host");
    let apt_dir = root.join("var/cache/apt/archives");
    fs::create_dir_all(&apt_dir).unwrap();
    let pkg = apt_dir.join("old.deb");
    fs::write(&pkg, b"deb-bytes").unwrap();

    let journal_path = dir.join("disk-cleanup.json");
    let now_epoch = super::util::now_unix_secs() + 10 * DAY_SECONDS;
    let ctx = CleanupActionContext {
        host_available: true,
        node_id: "node-1".to_string(),
        now_epoch,
        journal_path: journal_path.clone(),
        policy: CleanupPolicy {
            enabled: true,
            include_containers: false,
            retention_days: 14,
            interval_hours: 24,
        },
        ..CleanupActionContext::default()
    };

    let scan_action = r#"{"id":101,"action_type":"disk_cleanup_scan","params":{"expected_node_id":"node-1"}}"#;
    let scan_stage = execute_disk_cleanup_action(scan_action, &ctx);
    assert!(scan_stage.ok);
    assert_eq!(scan_stage.status, "running");

    // Readonly inspect must preserve "running" (never turn it into "interrupted")
    let ro = read_cleanup_journal_readonly(&journal_path).unwrap();
    assert_eq!(ro.runs.len(), 1);
    assert_eq!(ro.runs[0].status, "running");

    // Finalize scan against mock root
    let scanned = execute_and_finalize_cleanup_run(
        &journal_path,
        "action-101",
        &ctx.policy,
        Some(&root),
        now_epoch,
    )
    .unwrap();
    assert_eq!(scanned.status, "scanned");
    assert_eq!(scanned.items.len(), 1);
    assert_eq!(scanned.items[0].candidate_files, 1);
    assert!(pkg.exists());

    // Execute confirmed cleanup and mark delivered
    let exec_action = r#"{"id":102,"action_type":"disk_cleanup_execute","params":{"expected_node_id":"node-1","confirmed":true,"plan_id":"action-101"}}"#;
    let exec_stage = execute_disk_cleanup_action(exec_action, &ctx);
    assert!(exec_stage.ok);
    let cleaned = execute_and_finalize_cleanup_run(
        &journal_path,
        "action-102",
        &ctx.policy,
        Some(&root),
        now_epoch,
    )
    .unwrap();
    assert_eq!(cleaned.status, "succeeded");
    assert_eq!(cleaned.items[0].deleted_files, 1);
    assert!(!pkg.exists());

    mark_cleanup_run_delivered(&journal_path, "action-102").unwrap();
    let after = read_cleanup_journal_readonly(&journal_path).unwrap();
    assert!(after.runs.iter().find(|r| r.run_id == "action-102").unwrap().delivered);

    let _ = fs::remove_dir_all(&dir);
}

fn strip_csi_sgr_for_test(line: &str) -> String {
    let mut out = String::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'm' {
                i += 1;
            }
            i += 1;
            continue;
        }
        let ch = line[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}
