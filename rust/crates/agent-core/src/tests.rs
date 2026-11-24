use super::*;
use std::io::{BufRead, BufReader, Read, Write as IoWrite};
use std::net::TcpListener;
use transport::{sign_payload, HEADER_RESPONSE_SIGNATURE, HEADER_TIMESTAMP};

fn make_temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "narwhal_agent_core_{}_{}",
        name,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn test_config_from_env_file_env_and_cli_precedence() {
    let dir = make_temp_dir("cfg_precedence");
    let env_file = dir.join("client.env");
    fs::write(
        &env_file,
        r#"
# comment line
SERVER_URL="https://env-file.example.com:8443"
SHARED_SECRET='file-secret'
REPORT_INTERVAL=120
ACTION_POLL_INTERVAL=3
HOST_ID=file-host
NODE_ID=node-from-file
CONTAINER_RUNTIMES=podman
DOCKER_MONITOR_MODE=ignore
INCUS_PROJECT=default
SECURITY_MONITOR_ENABLED=false
"#,
    )
    .expect("write env file");

    let mut proc_env = HashMap::new();
    proc_env.insert(
        "SERVER_URL".to_string(),
        "https://proc-env.example.com".to_string(),
    );
    proc_env.insert("REPORT_INTERVAL".to_string(), "30".to_string()); // clamped to 60

    let args = vec![
        "--host-id".to_string(),
        "cli-host".to_string(),
        "--secret".to_string(),
        "cli-secret".to_string(),
        "--once".to_string(),
        "--dry-run".to_string(),
    ];

    let cfg = Config::from_sources(Some(&env_file), &proc_env, &args).expect("parse config");
    assert_eq!(cfg.server_url, "https://proc-env.example.com");
    assert_eq!(cfg.shared_secret, "cli-secret");
    assert_eq!(cfg.report_interval, 60);
    assert_eq!(cfg.action_poll_interval, 5); // clamped from 3 to 5
    assert_eq!(cfg.host_id, "cli-host");
    assert_eq!(cfg.node_id, "node-from-file");
    assert_eq!(cfg.container_runtimes, "podman");
    assert_eq!(cfg.docker_monitor_mode, "ignore");
    assert_eq!(cfg.incus_project, "default");
    assert!(!cfg.security_monitor_enabled);
    assert!(cfg.once);
    assert!(cfg.dry_run);
    assert!(!cfg.check_config);

    let summary = cfg.sanitized_summary();
    assert!(!summary.contains("cli-secret"));
    assert!(summary.contains("configured(redacted)"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_config_cli_errors() {
    let env = HashMap::new();
    let err = Config::from_sources(None, &env, &["--unknown".to_string()]).unwrap_err();
    assert_eq!(err, ConfigError::InvalidFlag("--unknown".to_string()));

    let err = Config::from_sources(None, &env, &["--server".to_string()]).unwrap_err();
    assert_eq!(err, ConfigError::MissingFlagValue("--server".to_string()));

    let err = Config::from_sources(
        None,
        &env,
        &["--interval".to_string(), "not-a-num".to_string()],
    )
    .unwrap_err();
    assert_eq!(
        err,
        ConfigError::InvalidInt {
            flag: "--interval".to_string(),
            value: "not-a-num".to_string()
        }
    );
}

#[test]
fn test_report_json_structure_with_mock_proc() {
    let dir = make_temp_dir("report_mock");
    let proc_root = dir.join("proc");
    fs::create_dir_all(proc_root.join("net")).unwrap();
    fs::create_dir_all(proc_root.join("pressure")).unwrap();
    fs::write(proc_root.join("uptime"), "1234.56 789.01\n").unwrap();
    fs::write(proc_root.join("loadavg"), "0.25 0.30 0.40 1/120 1234\n").unwrap();
    fs::write(
        proc_root.join("stat"),
        "cpu  1000 10 200 8000 50 0 0 0 0 0\n",
    )
    .unwrap();
    fs::write(
        proc_root.join("meminfo"),
        "MemTotal:        4096000 kB\nMemAvailable:    2048000 kB\n",
    )
    .unwrap();
    fs::write(
        proc_root.join("net").join("dev"),
        "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n",
    )
    .unwrap();
    fs::write(
        proc_root.join("pressure").join("cpu"),
        "some avg10=1.50 avg60=1.00 avg300=0.50 total=1000\n",
    )
    .unwrap();
    fs::write(
        proc_root.join("pressure").join("memory"),
        "some avg10=0.10 avg60=0.05 avg300=0.01 total=10\n",
    )
    .unwrap();
    fs::write(
        proc_root.join("pressure").join("io"),
        "some avg10=0.20 avg60=0.10 avg300=0.05 total=20\n",
    )
    .unwrap();
    let conntrack = dir.join("nf_conntrack");
    fs::write(&conntrack, "").unwrap();

    let cfg = Config {
        host_id: "test-host".to_string(),
        node_id: "node-123".to_string(),
        container_runtimes: "none".to_string(),
        ..Config::default()
    };
    let mut state = AgentState::with_paths(&cfg, proc_root, conntrack);
    let report = state.build_report_json(&cfg, 1_700_000_000);

    for required_key in [
        "\"host_id\":\"test-host\"",
        "\"node_id\":\"node-123\"",
        "\"client_config\":{",
        "\"agent_version\":",
        "\"timestamp\":1700000000",
        "\"container_network\":{\"ipv4_ok\":",
        "\"podman_network\":{\"ipv4_ok\":",
        "\"runtime_inventory\":{\"state\":",
        "\"containers\":[]",
        "\"security\":{",
        "\"operations\":{",
        "\"cpu_guard\":{",
        "\"memory_guard\":{",
        "\"io_guard\":{",
        "\"host_metrics\":{",
    ] {
        assert!(
            report.contains(required_key),
            "missing {required_key} in report: {report}"
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_check_config_and_dry_run_modes() {
    let cfg_check = Config {
        shared_secret: "super-secret".to_string(),
        check_config: true,
        ..Config::default()
    };
    let mut state = AgentState::new(&cfg_check);
    let mut out = Vec::new();
    let stop = AtomicBool::new(false);
    let code = run_with_config(&cfg_check, &mut state, &mut out, &stop).unwrap();
    assert_eq!(code, 0);
    let printed = String::from_utf8(out).unwrap();
    assert!(printed.contains("configured(redacted)"));
    assert!(!printed.contains("super-secret"));

    let cfg_dry = Config {
        host_id: "dry-host".to_string(),
        once: true,
        dry_run: true,
        ..Config::default()
    };
    let mut out2 = Vec::new();
    let code2 = run_with_config(&cfg_dry, &mut state, &mut out2, &stop).unwrap();
    assert_eq!(code2, 0);
    let printed2 = String::from_utf8(out2).unwrap();
    assert!(printed2.contains("\"host_id\":\"dry-host\""));
    assert!(printed2.contains("\"operations\":{"));
}

#[test]
fn test_action_poll_and_result_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().unwrap();
    let secret = "poll-test-secret".to_string();
    let secret_clone = secret.clone();

    let handle = thread::spawn(move || {
        for idx in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut req_line = String::new();
            reader.read_line(&mut req_line).unwrap();
            let mut ts_header = 0i64;
            let mut content_len = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    break;
                }
                if let Some((k, v)) = trimmed.split_once(':') {
                    if k.eq_ignore_ascii_case(HEADER_TIMESTAMP) {
                        ts_header = v.trim().parse().unwrap_or(0);
                    } else if k.eq_ignore_ascii_case("content-length") {
                        content_len = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut body_buf = vec![0u8; content_len];
            reader.read_exact(&mut body_buf).unwrap();

            let resp_body = if idx == 0 {
                b"{\"actions\":[{\"id\":42,\"action_type\":\"host_security_rescan\"}]}".to_vec()
            } else {
                b"{\"ok\":true}".to_vec()
            };
            let resp_sig = sign_payload(&resp_body, &secret_clone, ts_header);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}: {}\r\nConnection: close\r\n\r\n",
                resp_body.len(),
                HEADER_RESPONSE_SIGNATURE,
                resp_sig
            );
            stream.write_all(header.as_bytes()).unwrap();
            stream.write_all(&resp_body).unwrap();
        }
    });

    let cfg = Config {
        server_url: format!("http://{addr}"),
        shared_secret: secret,
        host_id: "h1".to_string(),
        node_id: "n1".to_string(),
        ..Config::default()
    };
    let client = TransportClient::new(cfg.to_transport_config()).unwrap();
    let handled = poll_actions_once(&client, &cfg).expect("poll actions");
    assert_eq!(handled, 1);
    handle.join().unwrap();
}

#[test]
fn test_extract_proc_infos_and_aggregate_socket_abuse() {
    let snapshot = r#"{
        "available": true,
        "items": [
            {
                "pid": 101,
                "ppid": 1,
                "lifetime_cpu_percent": 42.5,
                "rss_bytes": 1048576,
                "process": "xmrig",
                "command": "/tmp/xmrig --url stratum+tcp://pool.example:3333"
            },
            {
                "pid": 102,
                "ppid": 1,
                "cpu_percent": 3.25,
                "rss_bytes": 2048,
                "process": "nginx",
                "command": "nginx: master process"
            }
        ]
    }"#;

    let procs = extract_proc_infos_from_snapshot(snapshot);
    assert_eq!(procs.len(), 2);
    assert_eq!(procs[0].pid, 101);
    assert_eq!(procs[0].ppid, 1);
    assert!((procs[0].cpu_percent - 42.5).abs() < 1e-6);
    assert_eq!(procs[0].rss_bytes, 1_048_576);
    assert_eq!(procs[0].process, "xmrig");
    assert_eq!(
        procs[0].command,
        "/tmp/xmrig --url stratum+tcp://pool.example:3333"
    );
    assert_eq!(procs[1].pid, 102);
    assert!((procs[1].cpu_percent - 3.25).abs() < 1e-6);

    let findings = detect_suspicious_processes(&procs);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].pid, 101);

    let c1 = ContainerSample {
        id: "c1".to_string(),
        stable_id: "docker:c1".to_string(),
        name: "app1".to_string(),
        image: "alpine".to_string(),
        runtime: "docker".to_string(),
        runtime_bin: "docker".to_string(),
        project: String::new(),
        pid: Some(1000),
        status: "running".to_string(),
        instance_id: String::new(),
        network_addresses: Vec::new(),
        pid_metrics_json: Some(r#"{"available":true,"mem_bytes":52428800}"#.to_string()),
        socket_tables_json: Some(
            r#"{"available":true,"tcp_established":10,"tcp_time_wait":4,"syn_sent_count":2,"syn_recv_count":3,"udp_sockets":5}"#
                .to_string(),
        ),
        cgroup_metrics_json: Some(
            r#"{"available":true,"cpu_max":{"quota_usec":150000,"period_usec":100000},"memory":{"current_bytes":67108864,"max_bytes":134217728}}"#
                .to_string(),
        ),
    };
    let c2 = ContainerSample {
        id: "c2".to_string(),
        stable_id: "docker:c2".to_string(),
        name: "app2".to_string(),
        image: "alpine".to_string(),
        runtime: "docker".to_string(),
        runtime_bin: "docker".to_string(),
        project: String::new(),
        pid: Some(2000),
        status: "running".to_string(),
        instance_id: String::new(),
        network_addresses: Vec::new(),
        pid_metrics_json: Some(r#"{"available":true,"mem_bytes":16777216}"#.to_string()),
        socket_tables_json: Some(
            r#"{"available":true,"tcp_established":5,"tcp_time_wait":1,"tcp_syn_sent":1,"tcp_syn_recv":2,"udp_sockets":3,"conn_count":20}"#
                .to_string(),
        ),
        cgroup_metrics_json: None,
    };

    let containers = vec![c1, c2];
    let agg = aggregate_socket_abuse_from_containers(&containers, 1_700_000_123);
    assert_eq!(agg.evaluated_at, 1_700_000_123);
    assert_eq!(agg.tcp_established, 15);
    assert_eq!(agg.tcp_time_wait, 5);
    assert_eq!(agg.tcp_syn_sent, 3);
    assert_eq!(agg.tcp_syn_recv, 5);
    assert_eq!(agg.udp_sockets, 8);
    assert_eq!(agg.conn_count, 44);
    assert!(agg.has_tcp_states);

    let (mem_samples, cpu_samples) = extract_container_guard_samples(&containers, 4);
    assert_eq!(mem_samples.len(), 2);
    assert_eq!(mem_samples[0].key, "docker:c1");
    assert_eq!(mem_samples[0].current_bytes, 67_108_864);
    assert_eq!(mem_samples[0].max_bytes, Some(134_217_728));
    assert_eq!(mem_samples[1].key, "docker:c2");
    assert_eq!(mem_samples[1].current_bytes, 16_777_216);
    assert_eq!(mem_samples[1].max_bytes, None);

    assert_eq!(cpu_samples.len(), 2);
    assert_eq!(cpu_samples[0].key, "docker:c1");
    assert!((cpu_samples[0].effective_cpus - 1.5).abs() < 1e-6);
    assert_eq!(cpu_samples[1].key, "docker:c2");
    assert!((cpu_samples[1].effective_cpus - 4.0).abs() < 1e-6);
}

#[test]
fn test_two_tick_cross_delta_diskstats_and_network_rates() {
    let dir = std::env::temp_dir().join(format!("agent-core-delta-test-{}", std::process::id()));
    let proc_root = dir.join("proc");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(proc_root.join("net")).unwrap();
    fs::create_dir_all(proc_root.join("pressure")).unwrap();
    fs::write(proc_root.join("loadavg"), "0.20 0.15 0.10 1/100 42\n").unwrap();
    fs::write(proc_root.join("uptime"), "100.00 200.00\n").unwrap();
    fs::write(
        proc_root.join("meminfo"),
        "MemTotal:        4096000 kB\nMemAvailable:    2048000 kB\n",
    )
    .unwrap();
    fs::write(
        proc_root.join("net").join("dev"),
        "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n",
    )
    .unwrap();
    fs::write(
        proc_root.join("pressure").join("cpu"),
        "some avg10=1.00 avg60=0.50 avg300=0.25 total=100\n",
    )
    .unwrap();
    fs::write(
        proc_root.join("pressure").join("memory"),
        "some avg10=0.10 avg60=0.05 avg300=0.01 total=10\n",
    )
    .unwrap();
    fs::write(
        proc_root.join("pressure").join("io"),
        "some avg10=0.20 avg60=0.10 avg300=0.05 total=20\n",
    )
    .unwrap();
    fs::write(
        proc_root.join("stat"),
        "cpu  1000 0 500 8500 0 0 0 0 0 0\n",
    )
    .unwrap();
    fs::write(
        proc_root.join("diskstats"),
        "   8       0 sda 100 0 2000 10 50 0 1000 5 0 500 15\n",
    )
    .unwrap();
    let conntrack = dir.join("nf_conntrack");
    fs::write(&conntrack, "").unwrap();

    let cfg = Config {
        host_id: "delta-host".to_string(),
        node_id: "node-delta".to_string(),
        container_runtimes: "none".to_string(),
        ..Config::default()
    };
    let mut state = AgentState::with_paths(&cfg, proc_root.clone(), conntrack);

    // Tick 1 via public build_report_json(): records baseline diskstats & CPU without panics.
    let report1 = state.build_report_json(&cfg, 1_700_000_000);
    assert!(report1.contains("\"total_rx_bps\":0.000"));
    assert!(state.prev_host_disks.contains_key("8:0"));

    // Advance /proc/stat & /proc/diskstats for tick 2 (10s later).
    fs::write(
        proc_root.join("stat"),
        "cpu  1200 0 600 9200 0 0 0 0 0 0\n",
    )
    .unwrap();
    fs::write(
        proc_root.join("diskstats"),
        "   8       0 sda 200 0 6000 20 150 0 3000 15 0 2500 35\n",
    )
    .unwrap();
    let report2 = state.build_report_json(&cfg, 1_700_000_010);
    assert!(report2.contains("\"interval_seconds\":10.000"));
    assert_eq!(state.prev_host_disks.get("8:0"), Some(&(200, 6000, 150, 3000, 2500)));

    // Verify diskstats delta calculation directly on tick 3 (10s later).
    fs::write(
        proc_root.join("diskstats"),
        "   8       0 sda 300 0 10000 30 250 0 5000 25 0 7500 55\n",
    )
    .unwrap();
    let disk_samples = state.sample_host_disks(Some(10.0));
    assert_eq!(disk_samples.len(), 1);
    assert_eq!(disk_samples[0].device, "8:0");
    assert!((disk_samples[0].busy_percent - 50.0).abs() < 1e-6);
    assert!((disk_samples[0].total_bps - 307_200.0).abs() < 1e-6);
    assert!((disk_samples[0].total_iops - 20.0).abs() < 1e-6);

    // Verify two-tick container CPU, IO, and network rate deltas via build_report_json_with_containers().
    let make_container = |usage_usec: u64, rbytes: u64, wbytes: u64, rios: u64, wios: u64, rx_b: u64, tx_b: u64, rx_p: u64, tx_p: u64| {
        ContainerSample {
            id: "c1".to_string(),
            stable_id: "docker:c1".to_string(),
            name: "app1".to_string(),
            image: "alpine".to_string(),
            runtime: "docker".to_string(),
            runtime_bin: "docker".to_string(),
            project: String::new(),
            pid: Some(1000),
            status: "running".to_string(),
            instance_id: String::new(),
            network_addresses: Vec::new(),
            pid_metrics_json: Some(format!(
                r#"{{"available":true,"mem_bytes":52428800,"net":{{"rx_bytes":{rx_b},"tx_bytes":{tx_b},"rx_packets":{rx_p},"tx_packets":{tx_p}}}}}"#
            )),
            socket_tables_json: None,
            cgroup_metrics_json: Some(format!(
                r#"{{"available":true,"cpu_stat":{{"usage_usec":{usage_usec}}},"memory":{{"current_bytes":52428800,"max_bytes":134217728}},"io":{{"available":true,"devices":[{{"dev":"8:0","rbytes":{rbytes},"wbytes":{wbytes},"rios":{rios},"wios":{wios}}}]}}}}"#
            )),
        }
    };

    let c_tick1 = vec![make_container(1_000_000, 10_000, 20_000, 100, 200, 1_000, 2_000, 10, 20)];
    let c_tick2 = vec![make_container(6_000_000, 30_000, 60_000, 150, 300, 11_000, 22_000, 110, 220)];

    let _ = state.build_report_json_with_containers(&cfg, 1_700_000_020, &c_tick1);
    let net_report = state.build_report_json_with_containers(&cfg, 1_700_000_030, &c_tick2);

    assert!(net_report.contains("\"total_rx_bps\":1000.000"));
    assert!(net_report.contains("\"total_tx_bps\":2000.000"));
    assert!(net_report.contains("\"total_rx_pps\":10.000"));
    assert!(net_report.contains("\"total_tx_pps\":20.000"));

    // Verify CPU & IO container deltas on a follow-up tick (10s later).
    let c_tick3 = vec![make_container(11_000_000, 50_000, 100_000, 200, 400, 21_000, 42_000, 210, 420)];
    let (_, cpu_samples) = extract_container_guard_samples_with_cpu_delta(
        &mut state.prev_container_cpu,
        &c_tick3,
        1_700_000_040,
        4,
    );
    assert_eq!(cpu_samples.len(), 1);
    assert!((cpu_samples[0].cpu_percent.unwrap() - 50.0).abs() < 1e-6);

    let io_samples = state.extract_container_io_samples(&c_tick3, Some(10.0));
    assert_eq!(io_samples.len(), 1);
    assert_eq!(io_samples[0].device_rates[0].0, "8:0");
    assert!((io_samples[0].device_rates[0].1.rbps - 2000.0).abs() < 1e-6);
    assert!((io_samples[0].device_rates[0].1.wbps - 4000.0).abs() < 1e-6);
    assert!((io_samples[0].device_rates[0].1.riops - 5.0).abs() < 1e-6);
    assert!((io_samples[0].device_rates[0].1.wiops - 10.0).abs() < 1e-6);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_deterministic_jitter_and_guard_tick_scheduler() {
    let j1 = deterministic_jitter_secs("node-abc", "host-1", 30);
    let j2 = deterministic_jitter_secs("node-abc", "host-1", 30);
    assert_eq!(j1, j2);
    assert!(j1 <= 30);
    assert_eq!(deterministic_jitter_secs("node-abc", "host-1", 0), 0);

    let mut env = HashMap::new();
    env.insert("GUARD_SAMPLE_INTERVAL".to_string(), "5".to_string());
    let cfg = Config::from_sources(None, &env, &[]).unwrap();
    assert_eq!(cfg.guard_interval, MIN_GUARD_INTERVAL);

    let dir = make_temp_dir("guard_tick");
    let proc_root = dir.join("proc");
    fs::create_dir_all(proc_root.join("pressure")).unwrap();
    fs::write(proc_root.join("stat"), "cpu  1000 0 100 9000 0 0 0 0 0 0\n").unwrap();
    fs::write(proc_root.join("loadavg"), "0.10 0.10 0.10 1/100 1\n").unwrap();
    fs::write(proc_root.join("diskstats"), "   8       0 sda 1 0 8 1 2 0 16 2 0 3 3\n").unwrap();
    fs::write(proc_root.join("pressure/cpu"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();
    fs::write(proc_root.join("pressure/memory"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();
    fs::write(proc_root.join("pressure/io"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();

    let cfg_none = Config {
        container_runtimes: "none".to_string(),
        ..cfg
    };
    let mut state = AgentState::with_paths(&cfg_none, proc_root, dir.join("conntrack"));
    let (c_act, m_act, i_act) = state.sample_guards_tick(&cfg_none, 1_700_000_000);
    assert_eq!((c_act, m_act, i_act), (0, 0, 0));
    assert_eq!(state.last_sample_ts, Some(1_700_000_000));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_runtime_inventory_and_security_alerts_generation() {
    let inv_empty = detect_runtime_inventory_json(&[]);
    assert!(inv_empty.contains("\"container_count\":0"));

    let containers = vec![ContainerSample {
        id: "id1".to_string(),
        stable_id: "runman:id1".to_string(),
        name: "c1".to_string(),
        image: "alpine".to_string(),
        runtime: "runman".to_string(),
        runtime_bin: "runman".to_string(),
        project: String::new(),
        pid: Some(42),
        status: "running".to_string(),
        instance_id: String::new(),
        network_addresses: Vec::new(),
        pid_metrics_json: None,
        socket_tables_json: None,
        cgroup_metrics_json: None,
    }];
    let inv = detect_runtime_inventory_json(&containers);
    assert!(inv.contains("\"state\":\"available\""));
    assert!(inv.contains("\"runman\""));
    assert!(inv.contains("\"container_count\":1"));

    let mut abuse_input = SocketAbuseInput::default();
    abuse_input.evaluated_at = 1_700_000_000;
    abuse_input.conn_count = 300;
    abuse_input.cm_total = 300;
    abuse_input.cm_valid = true;
    abuse_input.has_tcp_states = true;
    abuse_input.socks_detected = true;
    abuse_input.socks_auth_mode = "none".to_string();
    let verdict = evaluate_socket_abuse(&abuse_input);
    let findings = vec![SuspiciousProcFinding {
        pid: 999,
        cpu_percent: 98.0,
        process: "xmrig".to_string(),
        category: "crypto_miner".to_string(),
        pattern: "xmrig".to_string(),
        severity: "critical".to_string(),
        redacted_command: "xmrig -o stratum+tcp://pool".to_string(),
    }];
    let alerts = build_security_alerts_json(&verdict, &findings);
    assert!(alerts.contains("\"type\":\"suspicious_process\""));
    assert!(alerts.contains("\"pid\":999"));
    if verdict.suspected {
        assert!(alerts.contains("\"type\":\"socket_abuse_suspected\""));
    }
}

#[test]
fn test_access_log_parsing_incremental_tailing_and_operations_health() {
    let combined = parse_access_log_line(
        r#"203.0.113.5 - - [16/Nov/2026:16:00:00 +0800] "GET /wp-login.php?a=1 HTTP/1.1" 403 123 "-" "curl""#,
    )
    .expect("combined line");
    assert_eq!(combined.ip, "203.0.113.5");
    assert_eq!(combined.status, 403);
    assert_eq!(combined.method, "GET");
    assert_eq!(combined.uri, "/wp-login.php?a=1");

    let caddy = parse_access_log_line(
        r#"{"request":{"client_ip":"198.51.100.8","method":"POST","uri":"/.env"},"status":404}"#,
    )
    .expect("caddy json line");
    assert_eq!(caddy.ip, "198.51.100.8");
    assert_eq!(caddy.status, 404);
    assert_eq!(caddy.method, "POST");
    assert_eq!(caddy.uri, "/.env");

    assert!(parse_access_log_line(r#"{"level":"info","msg":"started"}"#).is_none());

    let dir = make_temp_dir("access_log");
    let log_path = dir.join("site-access.log");
    fs::write(
        &log_path,
        "192.0.2.1 - - [16/Nov/2026:15:59:00 +0800] \"GET /old HTTP/1.1\" 200 10\n",
    )
    .unwrap();

    let paths = vec![
        dir.join("*.log").to_string_lossy().into_owned(),
        dir.join("missing.log").to_string_lossy().into_owned(),
    ];
    let scan_patterns = parse_csv_lowercase(DEFAULT_WEB_SCAN_PATTERNS);
    let mut states = HashMap::new();

    // First tick initializes byte offset to current EOF without replaying history.
    let s1 = collect_access_log_stats(&paths, DEFAULT_ACCESS_LOG_MAX_BYTES, &scan_patterns, 60.0, &mut states);
    assert!(s1.enabled);
    assert_eq!(s1.readable_files, 1);
    assert_eq!(s1.missing_files, 1);
    assert_eq!(s1.requests, 0);

    // Append new events before tick 2.
    {
        let mut f = fs::OpenOptions::new().append(true).open(&log_path).unwrap();
        writeln!(
            f,
            "203.0.113.9 - - [16/Nov/2026:16:00:01 +0800] \"GET /index.html HTTP/1.1\" 200 100"
        )
        .unwrap();
        writeln!(
            f,
            "203.0.113.10 - - [16/Nov/2026:16:00:02 +0800] \"GET /.env HTTP/1.1\" 403 10"
        )
        .unwrap();
        writeln!(
            f,
            "{{\"request\":{{\"client_ip\":\"203.0.113.10\",\"method\":\"GET\",\"uri\":\"/wp-admin\"}},\"status\":502}}"
        )
        .unwrap();
        writeln!(f, "not a valid access log line").unwrap();
    }

    let s2 = collect_access_log_stats(&paths, DEFAULT_ACCESS_LOG_MAX_BYTES, &scan_patterns, 60.0, &mut states);
    assert_eq!(s2.requests, 3);
    assert_eq!(s2.unique_ips, 2);
    assert_eq!(s2.top_ip, "203.0.113.10");
    assert_eq!(s2.top_ip_requests, 2);
    assert_eq!(s2.status_4xx, 1);
    assert_eq!(s2.status_5xx, 1);
    assert_eq!(s2.top_ip_4xx, "203.0.113.10");
    assert_eq!(s2.suspicious_requests, 2);
    assert_eq!(s2.suspicious_unique_paths, 2);
    assert_eq!(s2.top_scanner_ip, "203.0.113.10");
    assert_eq!(s2.parse_errors, 1);

    let health = build_operations_health_json(true, false, 2, &s2);
    assert!(health.contains("\"source\":\"http_logs\""));
    assert!(health.contains("\"status\":\"healthy\""));
    assert_eq!(normalize_arch("x86_64"), "x86_64");
    assert_eq!(normalize_arch("arm64"), "aarch64");

    // Service probes configure & check local TCP + invalid scheme
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut svc_state = AgentState::new(&Config::default());
    let poll_payload = format!(
        "{{\"actions\":[],\"operations\":{{\"services\":[{{\"id\":\"svc-tcp\",\"kind\":\"tcp\",\"target\":\"tcp://127.0.0.1:{port}\",\"latency_warning_ms\":5000}},{{\"id\":\"svc-bad\",\"kind\":\"http\",\"target\":\"ftp://example.com\",\"latency_warning_ms\":1000}}]}}}}"
    );
    svc_state.configure_operations_services(&poll_payload);
    assert_eq!(svc_state.operations_services.len(), 2);
    let svc_out = probe_operations_services_json(&svc_state.operations_services, 1_700_000_000);
    assert!(svc_out.contains("\"id\":\"svc-tcp\""));
    assert!(svc_out.contains("\"status\":\"healthy\""));
    assert!(svc_out.contains("\"id\":\"svc-bad\""));
    assert!(svc_out.contains("\"status\":\"failed\""));

    // Verify disk_cleanup & bandwidth_limits operations integration in report + poll
    svc_state.bandwidth_state_path = dir.join("bw-state.json");
    let bw_poll = r#"{"actions":[],"operations":{"disk_cleanup":{"enabled":true,"include_containers":false,"retention_days":21,"interval_hours":12,"node_id":"node-bw"},"bandwidth_limits":{"schema":1,"host_id":"host-bw","expected_node_id":"node-bw","revision":3,"limits":[]}}}"#;
    let bw_cfg = Config {
        host_id: "host-bw".to_string(),
        node_id: "node-bw".to_string(),
        container_runtimes: "none".to_string(),
        ..Config::default()
    };
    svc_state.configure_operations_bandwidth_and_cleanup(bw_poll, &bw_cfg);
    assert!(svc_state.cleanup_policy.enabled);
    assert_eq!(svc_state.cleanup_policy.retention_days, 21);
    assert_eq!(svc_state.cleanup_policy.interval_hours, 12);

    // Empty node_id must fail closed back to disabled CleanupPolicy::default()
    let empty_node_cfg = Config {
        host_id: "host-bw".to_string(),
        node_id: String::new(),
        container_runtimes: "none".to_string(),
        ..Config::default()
    };
    let sneaky_poll = r#"{"actions":[],"operations":{"disk_cleanup":{"enabled":true,"include_containers":true,"retention_days":30,"interval_hours":6,"node_id":""}}}"#;
    svc_state.configure_operations_bandwidth_and_cleanup(sneaky_poll, &empty_node_cfg);
    assert!(!svc_state.cleanup_policy.enabled);

    // Re-apply valid policy and verify summary preserves "running" entry in custom journal without mutating
    svc_state.cleanup_journal_path = dir.join("disk-cleanup.json");
    fs::write(
        &svc_state.cleanup_journal_path,
        r#"{"runs":[{"run_id":"action-90","action_id":90,"node_id":"node-bw","mode":"scan","automatic":false,"started_at":1700000005,"status":"running","targets":[],"items":[],"plan_id":""}],"attempts":{}}"#,
    )
    .unwrap();
    svc_state.configure_operations_bandwidth_and_cleanup(bw_poll, &bw_cfg);
    let bw_report = svc_state.build_report_json_with_containers(&bw_cfg, 1_700_000_010, &[]);
    assert!(bw_report.contains("\"manual_bandwidth_limits\":{"));
    assert!(bw_report.contains("\"disk_cleanup\":{"));
    assert!(bw_report.contains("\"retention_days\":21"));
    assert!(bw_report.contains("\"disk\":{"));
    assert!(bw_report.contains("\"running\":false"));
    assert!(bw_report.contains("\"status\":\"running\""));
    let ro_after = app_guard::disk_cleanup::read_cleanup_journal_readonly(&svc_state.cleanup_journal_path).unwrap();
    assert_eq!(ro_after.runs[0].status, "running");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_release_admission_flag_and_container_security_telemetry_and_alerts() {
    // 1. --release-admission CLI flag parsing
    let env = HashMap::new();
    let cfg = Config::from_sources(None, &env, &["--release-admission".to_string()]).unwrap();
    assert!(cfg.release_admission);
    assert!(!Config::default().release_admission);

    // 2. Per-container security telemetry + microburst + sensitive_file_events + udp_flood_blackhole alert
    let dir = make_temp_dir("container_sec");
    let proc_root = dir.join("proc");
    fs::create_dir_all(proc_root.join("net")).unwrap();
    fs::create_dir_all(proc_root.join("pressure")).unwrap();
    fs::write(proc_root.join("uptime"), "100.00 200.00\n").unwrap();
    fs::write(proc_root.join("loadavg"), "0.10 0.10 0.10 1/100 1\n").unwrap();
    fs::write(proc_root.join("stat"), "cpu  100 0 10 900 0 0 0 0 0 0\n").unwrap();
    fs::write(
        proc_root.join("meminfo"),
        "MemTotal:        4096000 kB\nMemAvailable:    2048000 kB\n",
    )
    .unwrap();
    fs::write(
        proc_root.join("net").join("dev"),
        "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
    )
    .unwrap();
    fs::write(proc_root.join("pressure/cpu"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();
    fs::write(proc_root.join("pressure/memory"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();
    fs::write(proc_root.join("pressure/io"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();

    let drop_tmp = proc_root.join("4242").join("root").join("tmp");
    fs::create_dir_all(&drop_tmp).unwrap();
    fs::write(drop_tmp.join("payload.sh"), b"#!/bin/sh\necho hi\n").unwrap();

    let conntrack = dir.join("nf_conntrack");
    fs::write(&conntrack, "").unwrap();

    let report_cfg = Config {
        host_id: "sec-host".to_string(),
        node_id: "sec-node".to_string(),
        container_runtimes: "none".to_string(),
        ..Config::default()
    };
    let mut state = AgentState::with_paths(&report_cfg, proc_root, conntrack);

    let c_tick1 = ContainerSample {
        id: "c1".to_string(),
        stable_id: "incus:default:c1".to_string(),
        name: "c1".to_string(),
        image: "alpine".to_string(),
        runtime: "incus".to_string(),
        runtime_bin: "incus".to_string(),
        project: "default".to_string(),
        pid: Some(4242),
        status: "running".to_string(),
        instance_id: "inst-c1".to_string(),
        network_addresses: vec!["10.0.0.2".to_string()],
        pid_metrics_json: Some(
            r#"{"available":true,"net":{"rx_bytes":1000,"tx_bytes":1000,"rx_packets":10,"tx_packets":10}}"#
                .to_string(),
        ),
        socket_tables_json: None,
        cgroup_metrics_json: None,
    };
    let report1 = state.build_report_json_with_containers(&report_cfg, 1_700_000_000, &[c_tick1]);
    assert!(report1.contains("\"abuse_guard\":{"));
    assert!(
        report1.contains("\"state\":\"pending\"") || report1.contains("\"state\":\"stale\""),
        "unexpected abuse_guard state in report1: {report1}"
    );
    assert!(report1.contains("\"vmess_guard\":{"));
    assert!(report1.contains("\"trojan_guard\":{"));
    assert!(report1.contains("\"sensitive_file_events\":["));
    assert!(report1.contains("/tmp/payload.sh"));
    assert!(report1.contains("\"microburst\":{"));
    assert!(report1.contains("\"udp_blackhole\":{"));
    assert!(report1.contains("\"anti_spoof\":{"));

    // Tick 2 with high small-packet outbound flood triggers microburst + evaluate_udp_flood_candidate
    let c_tick2 = ContainerSample {
        pid_metrics_json: Some(
            r#"{"available":true,"net":{"rx_bytes":2000,"tx_bytes":161000,"rx_packets":20,"tx_packets":4010}}"#
                .to_string(),
        ),
        ..ContainerSample {
            id: "c1".to_string(),
            stable_id: "incus:default:c1".to_string(),
            name: "c1".to_string(),
            image: "alpine".to_string(),
            runtime: "incus".to_string(),
            runtime_bin: "incus".to_string(),
            project: "default".to_string(),
            pid: Some(4242),
            status: "running".to_string(),
            instance_id: "inst-c1".to_string(),
            network_addresses: vec!["10.0.0.2".to_string()],
            pid_metrics_json: None,
            socket_tables_json: None,
            cgroup_metrics_json: None,
        }
    };
    let report2 = state.build_report_json_with_containers(&report_cfg, 1_700_000_001, &[c_tick2.clone()]);
    assert!(report2.contains("\"flood_type\":\"outbound_small_packet_flood\""));

    let mut mb_det = protocol_guard::microburst::MicroburstDetector::new();
    mb_det.detect_microburst("incus", "c1", 10, 10, 1000, 1000, 100.0);
    let mb_res = mb_det.detect_microburst("incus", "c1", 20, 4010, 2000, 161000, 101.0);
    let reason = evaluate_udp_flood_candidate(&mb_res, 0.0, 0).expect("flood candidate");
    let alert_json = build_udp_flood_blackhole_alert_json(&c_tick2, &reason, mb_res.tx_pps, 1800);
    assert!(alert_json.contains("\"type\":\"udp_flood_blackhole\""));
    assert!(alert_json.contains("\"severity\":\"critical\""));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_extract_live_listeners_and_sockets_from_socket_tables() {
    let sample = ContainerSample {
        id: "c-sock".to_string(),
        stable_id: "incus:default:c-sock".to_string(),
        name: "c-sock".to_string(),
        image: "alpine".to_string(),
        runtime: "incus".to_string(),
        runtime_bin: "incus".to_string(),
        project: "default".to_string(),
        pid: None,
        status: "running".to_string(),
        instance_id: "inst-sock".to_string(),
        network_addresses: vec!["10.0.0.2".to_string()],
        pid_metrics_json: None,
        socket_tables_json: Some(
            r#"{"available":true,"malformed":false,"tcp_entries":[{"local_ip":"0.0.0.0","local_port":443,"remote_ip":"0.0.0.0","remote_port":0,"state_hex":"0A","inode":101},{"local_ip":"10.0.0.2","local_port":51234,"remote_ip":"1.1.1.1","remote_port":22,"state_hex":"02","inode":102}],"udp_entries":[{"local_ip":"0.0.0.0","local_port":5201,"remote_ip":"0.0.0.0","remote_port":0,"state_hex":"07","inode":103}]}"#
                .to_string(),
        ),
        cgroup_metrics_json: None,
    };
    let (listeners, complete, sockets) =
        extract_live_listeners_and_sockets(&sample, Path::new("/proc"));
    assert!(complete);
    assert_eq!(listeners.len(), 2);
    assert_eq!(listeners[0].proto, "tcp");
    assert_eq!(listeners[0].port, 443);
    assert_eq!(listeners[1].proto, "udp");
    assert_eq!(listeners[1].port, 5201);
    assert_eq!(sockets.len(), 1);
    assert_eq!(sockets[0].remote_ip, "1.1.1.1");
    assert_eq!(sockets[0].remote, "1.1.1.1:22");
    assert_eq!(sockets[0].state, "syn_sent");
    assert_eq!(sockets[0].direction, "outbound");
}

#[test]
fn test_build_ssh_banner_install_script_and_motd_render() {
    assert!(build_ssh_banner_install_script("").is_none());
    assert!(build_ssh_banner_install_script("bad\0banner").is_none());
    let oversized = "x".repeat(32 * 1024 + 1);
    assert!(build_ssh_banner_install_script(&oversized).is_none());

    let mut opts = app_guard::security_banner::MotdRenderOptions::from_env();
    opts.color = false;
    opts.sampled_at = Some(1_700_000_000.0);
    let entry = app_guard::security_banner::MotdEntry {
        entry_type: "user_notice".to_string(),
        title: "SNI Notice".to_string(),
        detail: "Use allowed SNI 'crates.io'".to_string(),
        severity: "warning".to_string(),
        ..Default::default()
    };
    let selected = app_guard::security_banner::select_motd_entries(&[entry]);
    let rendered = app_guard::security_banner::render_motd_banner_entries(
        &selected,
        &opts,
    );
    let script = build_ssh_banner_install_script(&rendered).expect("valid banner script");
    assert!(script.contains("/etc/ssh/narwhal-banner"));
    assert!(script.contains("/etc/ssh/sshd_config.d/90-narwhal-banner.conf"));
    assert!(script.contains("# NARWHAL MANAGED PREAUTH BANNER v1"));
    assert!(script.contains("crates.io"));
    assert!(script.contains("\"$sshd\" -t -f \"$cfg\""));

    let shell_script = build_shell_banner_install_script(&rendered).expect("valid shell script");
    assert!(shell_script.contains("/etc/narwhal-banner.txt"));
    assert!(shell_script.contains("/etc/profile.d/90-narwhal-banner.sh"));
    assert!(shell_script.contains("NARWHAL_SHELL_OK:"));

    let h1 = fnv1a_hex(&rendered, &["NOTICE-1".to_string()]);
    let h2 = fnv1a_hex(&rendered, &["NOTICE-2".to_string()]);
    assert_ne!(h1, h2);
    let delivery = MotdDeliveryState {
        banner_hash: h1,
        status: "written".to_string(),
        shell_delivery: "installed".to_string(),
        ssh_banner_state: "active".to_string(),
        notice_ids: vec!["NOTICE-1".to_string()],
        error: String::new(),
        updated_at: 1_700_000_000,
    };
    let dj = delivery.to_json();
    assert!(dj.contains("\"status\":\"written\""));
    assert!(dj.contains("\"shell_delivery\":\"installed\""));
    assert!(dj.contains("NOTICE-1"));

    let upd_dir = std::env::temp_dir().join(format!("narwhal_auto_upd_{}", std::process::id()));
    fs::create_dir_all(&upd_dir).unwrap();
    fs::write(upd_dir.join("client-auto-update.env"), "AUTO_UPDATE_ENABLED=true\nAUTO_UPDATE_MODE=git\n").unwrap();
    fs::write(upd_dir.join("client-auto-update.version"), "abc123\n").unwrap();
    fs::write(upd_dir.join("client-auto-update.log"), "2026-11-18T01:02:14Z [client] ERROR tracked local changes\n").unwrap();
    let upd_json = collect_auto_update_status_json(&upd_dir);
    assert!(upd_json.contains("\"has_error\":true"));
    assert!(upd_json.contains("\"deployed_commit\":\"abc123\""));
    let _ = fs::remove_dir_all(&upd_dir);
}

#[test]
fn test_dynamic_security_policy_hot_reload_and_service_audit() {
    let mut state = AgentState::new(&Config::default());
    let policy_val = runtime_drivers::JsonVal::parse(
        r#"{"sni_enforcement":true,"block_cn_missing_sni":false,"sni_whitelist":["custom.example.org"],"service_audit_enabled":true,"disallowed_protocols":["vmess","shadowsocks"]}"#,
    )
    .unwrap();
    state.apply_dynamic_security_policy(&policy_val);
    assert_eq!(
        state.sni_whitelist.as_deref(),
        Some(&["custom.example.org".to_string()][..])
    );
    assert!(state.service_audit_enabled);
    assert_eq!(
        state.disallowed_protocols.as_deref(),
        Some(&["vmess".to_string(), "shadowsocks".to_string()][..])
    );
    assert!(admission_guard::sni::is_allowed_sni_with_override(
        "custom.example.org",
        state.sni_whitelist.as_deref()
    ));
    assert!(!admission_guard::sni::is_allowed_sni_with_override(
        "crates.io",
        state.sni_whitelist.as_deref()
    ));
}

#[test]
fn test_managed_upgrade_available_archive_and_git_modes() {
    let base = std::env::temp_dir().join(format!("narwhal_managed_upd_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();

    assert!(!managed_upgrade_available_with_cmd_check(&base, |_| true));

    fs::write(base.join("managed-client-update.sh"), "#!/bin/bash\n").unwrap();
    fs::write(base.join("update_archive.py"), "print('ok')\n").unwrap();
    fs::write(
        base.join("client-auto-update.env"),
        "AUTO_UPDATE_ENABLED=true\nAUTO_UPDATE_MODE=archive\n",
    )
    .unwrap();

    assert!(managed_upgrade_available_with_cmd_check(&base, |_| true));
    assert!(!managed_upgrade_available_with_cmd_check(&base, |c| c != "systemd-run"));
    assert!(!managed_upgrade_available_with_cmd_check(&base, |c| c != "python3"));

    let repo = base.join("repo");
    fs::create_dir_all(&repo).unwrap();
    assert!(Command::new("git").arg("-C").arg(&repo).arg("init").output().unwrap().status.success());
    Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["remote", "add", "origin", "https://github.com/podcctv/Narwhal-Cloud-podman-watcher.git"])
        .output()
        .unwrap();
    fs::write(
        base.join("client-auto-update.env"),
        format!(
            "AUTO_UPDATE_ENABLED=true\nAUTO_UPDATE_MODE=git\nAUTO_UPDATE_REPO_DIR={}\n",
            repo.display()
        ),
    )
    .unwrap();
    assert!(managed_upgrade_available_with_cmd_check(&base, |_| true));

    fs::write(repo.join("untracked.txt"), "dirty").unwrap();
    assert!(!managed_upgrade_available_with_cmd_check(&base, |_| true));
    let _ = fs::remove_file(repo.join("untracked.txt"));

    Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["remote", "set-url", "origin", "https://github.com/example/other.git"])
        .output()
        .unwrap();
    assert!(!managed_upgrade_available_with_cmd_check(&base, |_| true));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_build_report_payload_includes_managed_upgrade_field() {
    let mut state = AgentState::new(&Config::default());
    let payload = state.build_report_json(&Config::default(), 1_700_000_000);
    assert!(payload.contains("\"managed_upgrade\":false") || payload.contains("\"managed_upgrade\":true"));
}

#[test]
fn test_cpu_guard_enforcer_runman_apply_escalate_manual_override_and_restore() {
    let base = std::env::temp_dir().join(format!("narwhal_cpu_enf_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let proc_root = base.join("proc");
    let cgroup_root = base.join("cgroup");
    let vm_id = "4a4c84c1-2c2a-4793-93c6-12160fcca350";
    let cg_rel = format!("/system.slice/runman-{vm_id}.service/ct");
    let cg_dir = cgroup_root.join("system.slice").join(format!("runman-{vm_id}.service")).join("ct");
    let pid_dir = proc_root.join("4242");
    fs::create_dir_all(&cg_dir).unwrap();
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(pid_dir.join("cgroup"), format!("0::{cg_rel}\n")).unwrap();
    fs::write(cg_dir.join("cpu.max"), "max 100000\n").unwrap();
    fs::write(cg_dir.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();

    let vm_id2 = "1ad00944-2c2a-4793-93c6-12160fcca350";
    let cg_rel2 = format!("/system.slice/runman-{vm_id2}.service/ct");
    let cg_dir2 = cgroup_root.join("system.slice").join(format!("runman-{vm_id2}.service")).join("ct");
    let pid_dir2 = proc_root.join("4343");
    fs::create_dir_all(&cg_dir2).unwrap();
    fs::create_dir_all(&pid_dir2).unwrap();
    fs::write(pid_dir2.join("cgroup"), format!("0::{cg_rel2}\n")).unwrap();
    fs::write(cg_dir2.join("cpu.max"), "100000 100000\n").unwrap();
    fs::write(cg_dir2.join("cgroup.events"), "populated 1\n").unwrap();

    let c1 = ContainerSample {
        id: vm_id.to_string(),
        stable_id: vm_id.to_string(),
        name: vm_id.to_string(),
        image: "alpine".to_string(),
        runtime: "runman".to_string(),
        runtime_bin: "runman".to_string(),
        project: "default".to_string(),
        pid: Some(4242),
        status: "running".to_string(),
        instance_id: vm_id.to_string(),
        network_addresses: vec![],
        pid_metrics_json: None,
        socket_tables_json: None,
        cgroup_metrics_json: None,
    };
    let c2 = ContainerSample {
        id: vm_id2.to_string(),
        stable_id: vm_id2.to_string(),
        name: vm_id2.to_string(),
        image: "alpine".to_string(),
        runtime: "runman".to_string(),
        runtime_bin: "runman".to_string(),
        project: "default".to_string(),
        pid: Some(4343),
        status: "running".to_string(),
        instance_id: vm_id2.to_string(),
        network_addresses: vec![],
        pid_metrics_json: None,
        socket_tables_json: None,
        cgroup_metrics_json: None,
    };
    let containers = vec![c1, c2];
    let state_file = base.join("cpu-guard-limits.json");
    let mut enforcer = CpuGuardEnforcer::new(state_file.clone());

    enforcer.execute_actions(
        &containers,
        &[
            guard_core::CpuGuardAction::ApplyLimit {
                key: vm_id.to_string(),
                tier: 1,
                target_cpus: 0.5,
                fair_share_cpus: None,
                pressure_basis: "single_core_host_cpu_saturation",
            },
            guard_core::CpuGuardAction::ApplyLimit {
                key: vm_id2.to_string(),
                tier: 1,
                target_cpus: 0.5,
                fair_share_cpus: None,
                pressure_basis: "host_busy_and_psi_confirmed",
            },
        ],
        &proc_root,
        &cgroup_root,
        1_700_000_000,
    );
    assert_eq!(fs::read_to_string(cg_dir.join("cpu.max")).unwrap().trim(), "50000 100000");
    assert_eq!(fs::read_to_string(cg_dir2.join("cpu.max")).unwrap().trim(), "50000 100000");
    assert!(enforcer.records.get(vm_id).unwrap().readback_confirmed);

    // Escalate c1 to Tier 2 (0.25 CPUs)
    enforcer.execute_actions(
        &containers,
        &[guard_core::CpuGuardAction::EscalateLimit {
            key: vm_id.to_string(),
            tier: 2,
            target_cpus: 0.25,
        }],
        &proc_root,
        &cgroup_root,
        1_700_000_600,
    );
    assert_eq!(fs::read_to_string(cg_dir.join("cpu.max")).unwrap().trim(), "25000 100000");

    // Simulate operator manual override on c1, then RestoreLimit must NOT overwrite it
    fs::write(cg_dir.join("cpu.max"), "80000 100000\n").unwrap();
    enforcer.execute_actions(
        &containers,
        &[
            guard_core::CpuGuardAction::RestoreLimit {
                key: vm_id.to_string(),
                original_cpus: 1.0,
                cooldown_until: 1_700_002_000,
            },
            guard_core::CpuGuardAction::RestoreLimit {
                key: vm_id2.to_string(),
                original_cpus: 1.0,
                cooldown_until: 1_700_002_000,
            },
        ],
        &proc_root,
        &cgroup_root,
        1_700_001_100,
    );
    assert_eq!(fs::read_to_string(cg_dir.join("cpu.max")).unwrap().trim(), "80000 100000");
    assert!(enforcer.records.get(vm_id).unwrap().manual_override);
    assert_eq!(fs::read_to_string(cg_dir2.join("cpu.max")).unwrap().trim(), "100000 100000");
    assert!(!enforcer.records.contains_key(vm_id2));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_build_report_json_emits_top_level_metrics_cpu_guard_and_alerts() {
    let base = std::env::temp_dir().join(format!("narwhal_cpu_rep_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let proc_root = base.join("proc");
    let cgroup_root = base.join("cgroup");
    let vm_id = "4a4c84c1-2c2a-4793-93c6-12160fcca350";
    let cg_dir = cgroup_root.join("system.slice").join(format!("runman-{vm_id}.service")).join("ct");
    let pid_dir = proc_root.join("5151");
    fs::create_dir_all(proc_root.join("pressure")).unwrap();
    fs::create_dir_all(&cg_dir).unwrap();
    fs::create_dir_all(&pid_dir).unwrap();

    fs::write(proc_root.join("loadavg"), "2.44 2.51 2.44 3/120 5151\n").unwrap();
    fs::write(proc_root.join("pressure").join("cpu"), "some avg10=12.00 avg60=8.00 avg300=4.00 total=1000\n").unwrap();
    fs::write(proc_root.join("pressure").join("memory"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();
    fs::write(proc_root.join("pressure").join("io"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();
    fs::write(pid_dir.join("cgroup"), format!("0::/system.slice/runman-{vm_id}.service/ct\n")).unwrap();
    fs::write(cg_dir.join("cpu.max"), "100000 100000\n").unwrap();
    fs::write(cg_dir.join("cgroup.events"), "populated 1\n").unwrap();
    fs::write(cg_dir.join("cpu.pressure"), "some avg10=15.00 avg60=10.00 avg300=5.00 total=200\n").unwrap();

    let cfg = Config {
        host_id: "los-angeles-test".to_string(),
        node_id: "node-la-1".to_string(),
        report_interval: 60,
        security_monitor_enabled: true,
        ..Config::default()
    };
    let mut state = AgentState::with_paths(&cfg, proc_root.clone(), proc_root.join("nf_conntrack"))
        .with_cgroup_root(cgroup_root.clone())
        .with_cpu_guard_state_path(base.join("cpu-guard-limits.json"));

    let make_sample = |usage_usec: u64, rx: u64, tx: u64| vec![ContainerSample {
        id: vm_id.to_string(),
        stable_id: vm_id.to_string(),
        name: vm_id.to_string(),
        image: "alpine".to_string(),
        runtime: "runman".to_string(),
        runtime_bin: "runman".to_string(),
        project: "default".to_string(),
        pid: Some(5151),
        status: "running".to_string(),
        instance_id: vm_id.to_string(),
        network_addresses: vec!["10.91.16.9".to_string()],
        pid_metrics_json: Some(format!(
            r#"{{"available":true,"mem_bytes":134217728,"net":{{"rx_bytes":{rx},"tx_bytes":{tx},"rx_packets":10,"tx_packets":10}}}}"#
        )),
        socket_tables_json: Some(r#"{"available":true,"tcp_established":12,"tcp_time_wait":0,"syn_sent_count":0,"syn_recv_count":0,"udp_sockets":2}"#.to_string()),
        cgroup_metrics_json: Some(format!(
            r#"{{"available":true,"cpu_stat":{{"usage_usec":{usage_usec}}},"cpu_max":{{"raw":"100000 100000","quota_usec":100000,"period_usec":100000}},"memory":{{"current_bytes":134217728,"max_bytes":268435456}}}}"#
        )),
    }];

    // Feed 5 ticks over 240s with host busy = 100% and container usage = 88% of its 1-CPU quota
    let mut final_report = String::new();
    for (idx, ts) in [1_700_000_000u64, 1_700_000_060, 1_700_000_120, 1_700_000_180, 1_700_000_240].iter().enumerate() {
        let busy_ticks = (idx as u64 + 1) * 6000;
        fs::write(proc_root.join("stat"), format!("cpu  {busy_ticks} 0 0 0 0 0 0 0 0 0\n")).unwrap();
        let usage_usec = (idx as u64 + 1) * 60 * 880_000;
        let rx = (idx as u64 + 1) * 6000;
        let tx = (idx as u64 + 1) * 12000;
        final_report = state.build_report_json_with_containers(&cfg, *ts, &make_sample(usage_usec, rx, tx));
    }

    assert!(final_report.contains("\"cpu_percent\":88.00"), "missing top-level cpu_percent: {final_report}");
    assert!(final_report.contains("\"cpu_effective_cpus\":1.000"));
    assert!(final_report.contains("\"mem_bytes\":134217728"));
    assert!(final_report.contains("\"mem_limit_bytes\":268435456"));
    assert!(final_report.contains("\"mem_percent\":50.00"));
    assert!(final_report.contains("\"net_rx_bps\":100.00"));
    assert!(final_report.contains("\"net_tx_bps\":200.00"));
    assert!(final_report.contains("\"conn_count\":12"));
    assert!(final_report.contains("\"cpu_guard\":{\"state\":\"limited\""), "missing container cpu_guard limited status: {final_report}");
    assert!(final_report.contains("\"readback_confirmed\":true"));
    assert!(final_report.contains("\"type\":\"cpu_pressure_protection\""), "missing cpu_pressure_protection alert: {final_report}");
    assert_eq!(fs::read_to_string(cg_dir.join("cpu.max")).unwrap().trim(), "50000 100000");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_host_proc_snapshot_detects_suspicious_xmrig_process() {
    let base = std::env::temp_dir().join(format!("narwhal_host_xmrig_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let proc_root = base.join("proc");
    let p_xmrig = proc_root.join("9001");
    fs::create_dir_all(proc_root.join("pressure")).unwrap();
    fs::create_dir_all(&p_xmrig).unwrap();

    fs::write(proc_root.join("uptime"), "500.00 100.00\n").unwrap();
    fs::write(proc_root.join("stat"), "cpu  1000 0 100 8000 0 0 0 0 0 0\n").unwrap();
    fs::write(proc_root.join("loadavg"), "1.50 1.20 1.00 2/100 9001\n").unwrap();
    for res in ["cpu", "memory", "io"] {
        fs::write(
            proc_root.join("pressure").join(res),
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        )
        .unwrap();
    }
    fs::write(
        p_xmrig.join("status"),
        "Name:\txmrig\nState:\tR (running)\nPid:\t9001\nPPid:\t1\nUid:\t0\t0\nVmRSS:\t65536 kB\n",
    )
    .unwrap();
    fs::write(p_xmrig.join("comm"), "xmrig\n").unwrap();
    fs::write(p_xmrig.join("cmdline"), "xmrig\0-o\0pool.example:3333\0").unwrap();
    fs::write(
        p_xmrig.join("stat"),
        "9001 (xmrig) R 1 9001 9001 0 -1 0 0 0 0 0 25000 0 0 0 20 0 1 0 100 0 0",
    )
    .unwrap();

    let cfg = Config {
        host_id: "h-xmrig".to_string(),
        node_id: "n-xmrig".to_string(),
        security_monitor_enabled: true,
        ..Config::default()
    };
    let mut state = AgentState::with_paths(&cfg, proc_root.clone(), proc_root.join("nf_conntrack"));
    let report = state.build_report_json_with_containers(&cfg, 1_700_000_000, &[]);
    assert!(report.contains("\"process\":\"xmrig\""), "missing xmrig in suspicious_processes: {report}");
    assert!(report.contains("\"suspicious_process\""), "missing suspicious_process alert: {report}");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_memory_and_io_guard_enforcers_apply_escalate_manual_override_and_restore() {
    let base = std::env::temp_dir().join(format!("narwhal_mem_io_enf_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let proc_root = base.join("proc");
    let cgroup_root = base.join("cgroup");
    let vm1 = "4a4c84c1-2c2a-4793-93c6-12160fcca350";
    let vm2 = "1ad00944-2c2a-4793-93c6-12160fcca350";
    let cg1 = cgroup_root.join("system.slice").join(format!("runman-{vm1}.service")).join("ct");
    let cg2 = cgroup_root.join("system.slice").join(format!("runman-{vm2}.service")).join("ct");
    let p1 = proc_root.join("6161");
    let p2 = proc_root.join("6262");
    fs::create_dir_all(&cg1).unwrap();
    fs::create_dir_all(&cg2).unwrap();
    fs::create_dir_all(&p1).unwrap();
    fs::create_dir_all(&p2).unwrap();

    fs::write(p1.join("cgroup"), format!("0::/system.slice/runman-{vm1}.service/ct\n")).unwrap();
    fs::write(p2.join("cgroup"), format!("0::/system.slice/runman-{vm2}.service/ct\n")).unwrap();
    for cg in [&cg1, &cg2] {
        fs::write(cg.join("cgroup.events"), "populated 1\n").unwrap();
        fs::write(cg.join("memory.high"), "max\n").unwrap();
        fs::write(cg.join("io.max"), "").unwrap();
    }

    let make_c = |id: &str, pid: u32| ContainerSample {
        id: id.to_string(),
        stable_id: id.to_string(),
        name: id.to_string(),
        image: "alpine".to_string(),
        runtime: "runman".to_string(),
        runtime_bin: "runman".to_string(),
        project: "default".to_string(),
        pid: Some(pid),
        status: "running".to_string(),
        instance_id: id.to_string(),
        network_addresses: vec![],
        pid_metrics_json: None,
        socket_tables_json: None,
        cgroup_metrics_json: None,
    };
    let containers = vec![make_c(vm1, 6161), make_c(vm2, 6262)];

    let mut mem_enf = MemoryGuardEnforcer::new(base.join("mem.json"));
    mem_enf.execute_actions(
        &containers,
        &[
            guard_core::MemoryGuardAction::ApplyMemoryHigh {
                key: vm1.to_string(),
                tier: 1,
                target_bytes: 200_000_000,
            },
            guard_core::MemoryGuardAction::ApplyMemoryHigh {
                key: vm2.to_string(),
                tier: 1,
                target_bytes: 200_000_000,
            },
        ],
        &proc_root,
        &cgroup_root,
        1_700_000_000,
    );
    assert_eq!(fs::read_to_string(cg1.join("memory.high")).unwrap().trim(), "200000000");
    assert!(mem_enf.records.get(vm1).unwrap().readback_confirmed);

    mem_enf.execute_actions(
        &containers,
        &[guard_core::MemoryGuardAction::EscalateMemoryHigh {
            key: vm1.to_string(),
            tier: 2,
            target_bytes: 160_000_000,
        }],
        &proc_root,
        &cgroup_root,
        1_700_000_600,
    );
    assert_eq!(fs::read_to_string(cg1.join("memory.high")).unwrap().trim(), "160000000");

    // Manual override on vm1, clean restore on vm2
    fs::write(cg1.join("memory.high"), "300000000\n").unwrap();
    mem_enf.execute_actions(
        &containers,
        &[
            guard_core::MemoryGuardAction::RestoreMemoryHigh {
                key: vm1.to_string(),
                original_high_bytes: None,
                cooldown_until: 1_700_002_000,
            },
            guard_core::MemoryGuardAction::RestoreMemoryHigh {
                key: vm2.to_string(),
                original_high_bytes: None,
                cooldown_until: 1_700_002_000,
            },
        ],
        &proc_root,
        &cgroup_root,
        1_700_001_500,
    );
    assert_eq!(fs::read_to_string(cg1.join("memory.high")).unwrap().trim(), "300000000");
    assert!(mem_enf.records.get(vm1).unwrap().manual_override);
    assert_eq!(fs::read_to_string(cg2.join("memory.high")).unwrap().trim(), "max");
    assert!(!mem_enf.records.contains_key(vm2));

    // IoGuardEnforcer
    let mut io_enf = IoGuardEnforcer::new(base.join("io.json"));
    let tier1_io = guard_core::IoMaxLimits {
        rbps: Some(52_428_800),
        wbps: None,
        riops: Some(400),
        wiops: None,
    };
    io_enf.execute_actions(
        &containers,
        &[
            guard_core::IoGuardAction::ApplyIoMax {
                key: vm1.to_string(),
                device: "8:0".to_string(),
                tier: 1,
                target: tier1_io.clone(),
            },
            guard_core::IoGuardAction::ApplyIoMax {
                key: vm2.to_string(),
                device: "8:0".to_string(),
                tier: 1,
                target: tier1_io,
            },
        ],
        &proc_root,
        &cgroup_root,
        1_700_000_000,
    );
    assert_eq!(
        fs::read_to_string(cg1.join("io.max")).unwrap().trim(),
        "8:0 rbps=52428800 wbps=max riops=400 wiops=max"
    );
    assert!(io_enf.records.get(vm1).unwrap().readback_confirmed);

    io_enf.execute_actions(
        &containers,
        &[guard_core::IoGuardAction::EscalateIoMax {
            key: vm1.to_string(),
            device: "8:0".to_string(),
            tier: 2,
            target: guard_core::IoMaxLimits {
                rbps: Some(26_214_400),
                wbps: None,
                riops: Some(200),
                wiops: None,
            },
        }],
        &proc_root,
        &cgroup_root,
        1_700_000_300,
    );
    assert_eq!(
        fs::read_to_string(cg1.join("io.max")).unwrap().trim(),
        "8:0 rbps=26214400 wbps=max riops=200 wiops=max"
    );

    fs::write(cg1.join("io.max"), "8:0 rbps=99999999 wbps=max riops=max wiops=max\n").unwrap();
    io_enf.execute_actions(
        &containers,
        &[
            guard_core::IoGuardAction::RestoreIoMax {
                key: vm1.to_string(),
                device: "8:0".to_string(),
                original: guard_core::IoMaxLimits::default(),
                cooldown_until: 1_700_002_000,
            },
            guard_core::IoGuardAction::RestoreIoMax {
                key: vm2.to_string(),
                device: "8:0".to_string(),
                original: guard_core::IoMaxLimits::default(),
                cooldown_until: 1_700_002_000,
            },
        ],
        &proc_root,
        &cgroup_root,
        1_700_001_000,
    );
    assert_eq!(
        fs::read_to_string(cg1.join("io.max")).unwrap().trim(),
        "8:0 rbps=99999999 wbps=max riops=max wiops=max"
    );
    assert!(io_enf.records.get(vm1).unwrap().manual_override);
    assert_eq!(
        fs::read_to_string(cg2.join("io.max")).unwrap().trim(),
        "8:0 rbps=max wbps=max riops=max wiops=max"
    );
    assert!(!io_enf.records.contains_key(vm2));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_build_report_json_emits_memory_and_io_guard_status_and_alerts() {
    let base = std::env::temp_dir().join(format!("narwhal_mem_io_rep_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let proc_root = base.join("proc");
    let cgroup_root = base.join("cgroup");
    let vm_id = "4a4c84c1-2c2a-4793-93c6-12160fcca350";
    let cg_dir = cgroup_root.join("system.slice").join(format!("runman-{vm_id}.service")).join("ct");
    let pid_dir = proc_root.join("7171");
    fs::create_dir_all(proc_root.join("pressure")).unwrap();
    fs::create_dir_all(&cg_dir).unwrap();
    fs::create_dir_all(&pid_dir).unwrap();

    fs::write(proc_root.join("loadavg"), "1.00 1.00 1.00 1/100 7171\n").unwrap();
    fs::write(proc_root.join("pressure").join("cpu"), "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();
    fs::write(proc_root.join("pressure").join("memory"), "some avg10=12.00 avg60=8.00 avg300=4.00 total=100\n").unwrap();
    fs::write(proc_root.join("pressure").join("io"), "some avg10=12.00 avg60=8.00 avg300=4.00 total=100\n").unwrap();
    fs::write(pid_dir.join("cgroup"), format!("0::/system.slice/runman-{vm_id}.service/ct\n")).unwrap();
    fs::write(cg_dir.join("cgroup.events"), "populated 1\n").unwrap();
    fs::write(cg_dir.join("memory.high"), "max\n").unwrap();
    fs::write(cg_dir.join("memory.pressure"), "some avg10=12.00 avg60=8.00 avg300=4.00 total=200\n").unwrap();
    fs::write(cg_dir.join("io.max"), "").unwrap();

    let cfg = Config {
        host_id: "mem-io-test".to_string(),
        node_id: "node-mem-io".to_string(),
        report_interval: 300,
        security_monitor_enabled: true,
        ..Config::default()
    };
    let mut state = AgentState::with_paths(&cfg, proc_root.clone(), proc_root.join("nf_conntrack"))
        .with_cgroup_root(cgroup_root.clone())
        .with_cpu_guard_state_path(base.join("cpu-guard.json"))
        .with_memory_guard_state_path(base.join("mem-guard.json"))
        .with_io_guard_state_path(base.join("io-guard.json"));

    let make_sample = |rbytes: u64, rios: u64| vec![ContainerSample {
        id: vm_id.to_string(),
        stable_id: vm_id.to_string(),
        name: vm_id.to_string(),
        image: "alpine".to_string(),
        runtime: "runman".to_string(),
        runtime_bin: "runman".to_string(),
        project: "default".to_string(),
        pid: Some(7171),
        status: "running".to_string(),
        instance_id: vm_id.to_string(),
        network_addresses: vec![],
        pid_metrics_json: None,
        socket_tables_json: None,
        cgroup_metrics_json: Some(format!(
            r#"{{"available":true,"memory":{{"current_bytes":241591910,"max_bytes":268435456}},"io":{{"available":true,"devices":[{{"dev":"8:0","rbytes":{rbytes},"wbytes":0,"rios":{rios},"wios":0}}]}}}}"#
        )),
    }];

    let mut final_report = String::new();
    for (idx, ts) in [1_700_000_000u64, 1_700_000_300, 1_700_000_600].iter().enumerate() {
        let step = idx as u64 + 1;
        fs::write(proc_root.join("stat"), format!("cpu  {} 0 0 {} 0 0 0 0 0 0\n", step * 1000, step * 9000)).unwrap();
        let rbytes = step * 300 * 50_000_000;
        let rios = step * 300 * 500;
        let rsectors = rbytes / 512;
        let busy_ms = step * 270_000; // 90% of 300s
        fs::write(
            proc_root.join("diskstats"),
            format!("   8       0 sda {rios} 0 {rsectors} 0 0 0 0 0 0 {busy_ms} 0\n"),
        )
        .unwrap();
        final_report = state.build_report_json_with_containers(&cfg, *ts, &make_sample(rbytes, rios));
    }

    assert!(final_report.contains("\"memory_guard\":{\"state\":\"limited\""), "missing memory_guard limited status: {final_report}");
    assert!(final_report.contains("\"io_guard\":{\"state\":\"limited\""), "missing io_guard limited status: {final_report}");
    assert!(final_report.contains("\"type\":\"memory_pressure_protection\""), "missing memory_pressure_protection alert: {final_report}");
    assert!(final_report.contains("\"type\":\"io_pressure_protection\""), "missing io_pressure_protection alert: {final_report}");
    assert_ne!(fs::read_to_string(cg_dir.join("memory.high")).unwrap().trim(), "max");
    assert!(fs::read_to_string(cg_dir.join("io.max")).unwrap().contains("8:0 rbps="));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_report_emits_compact_conntrack_unique_ips_traffic_counters_and_top_cpu_process() {
    let base = std::env::temp_dir().join(format!("narwhal_batch2_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let proc_root = base.join("proc");
    let p_sb = proc_root.join("5151");
    fs::create_dir_all(proc_root.join("pressure")).unwrap();
    fs::create_dir_all(&p_sb).unwrap();

    fs::write(proc_root.join("uptime"), "600.00 100.00\n").unwrap();
    fs::write(proc_root.join("stat"), "cpu  1000 0 100 8000 0 0 0 0 0 0\n").unwrap();
    fs::write(proc_root.join("loadavg"), "1.00 1.00 1.00 1/50 5151\n").unwrap();
    for res in ["cpu", "memory", "io"] {
        fs::write(
            proc_root.join("pressure").join(res),
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        )
        .unwrap();
    }
    fs::write(
        p_sb.join("status"),
        "Name:\tsing-box\nState:\tR (running)\nPid:\t5151\nPPid:\t1\nUid:\t0\t0\nVmRSS:\t32768 kB\n",
    )
    .unwrap();
    fs::write(p_sb.join("comm"), "sing-box\n").unwrap();
    fs::write(p_sb.join("cmdline"), "sing-box\0run\0-c\0/etc/sb.json\0").unwrap();
    fs::write(
        p_sb.join("stat"),
        "5151 (sing-box) R 1 5151 5151 0 -1 0 0 0 0 0 40000 0 0 0 20 0 1 0 100 0 0",
    )
    .unwrap();

    let conntrack_path = base.join("nf_conntrack");
    fs::write(
        &conntrack_path,
        concat!(
            "ipv4     2 tcp      6 431999 ESTABLISHED src=1.2.3.4 dst=10.91.16.9 sport=51234 dport=443 packets=12 bytes=1024 src=10.91.16.9 dst=1.2.3.4 sport=443 dport=51234 packets=10 bytes=2048 [ASSURED] mark=0\n",
            "ipv4     2 tcp      6 431999 ESTABLISHED src=5.6.7.8 dst=10.91.16.9 sport=51235 dport=443 packets=12 bytes=1024 src=10.91.16.9 dst=5.6.7.8 sport=443 dport=51235 packets=10 bytes=2048 [ASSURED] mark=0\n",
            "ipv4     2 tcp      6 431999 ESTABLISHED src=10.91.16.9 dst=9.9.9.9 sport=40000 dport=53 packets=5 bytes=256 src=9.9.9.9 dst=10.91.16.9 sport=53 dport=40000 packets=5 bytes=256 [ASSURED] mark=0\n",
        ),
    )
    .unwrap();

    let cfg = Config {
        host_id: "h-batch2".to_string(),
        node_id: "n-batch2".to_string(),
        security_monitor_enabled: true,
        ..Config::default()
    };
    let mut state = AgentState::with_paths(&cfg, proc_root.clone(), conntrack_path);
    let vm_id = "4a4c84c1-2c2a-4793-93c6-12160fcca350";
    let containers = vec![ContainerSample {
        id: vm_id.to_string(),
        stable_id: vm_id.to_string(),
        name: vm_id.to_string(),
        image: "alpine".to_string(),
        runtime: "runman".to_string(),
        runtime_bin: "runman".to_string(),
        project: "default".to_string(),
        pid: Some(5151),
        status: "running".to_string(),
        instance_id: vm_id.to_string(),
        network_addresses: vec!["10.91.16.9/24".to_string()],
        pid_metrics_json: Some(
            r#"{"available":true,"mem_bytes":33554432,"net":{"rx_bytes":12345,"tx_bytes":67890,"rx_packets":10,"tx_packets":20}}"#
                .to_string(),
        ),
        socket_tables_json: Some(
            r#"{"available":true,"tcp_established":3,"tcp_time_wait":0,"syn_sent_count":0,"syn_recv_count":0,"udp_sockets":0,"listening_ports":[443],"udp_listening_ports":[]}"#
                .to_string(),
        ),
        cgroup_metrics_json: None,
    }];

    let report = state.build_report_json_with_containers(&cfg, 1_700_000_000, &containers);
    assert!(
        report.contains("\"conntrack\":{\"available\":true,\"count\":3,\"truncated\":false}"),
        "expected compact conntrack summary: {report}"
    );
    assert!(!report.contains("\"entries\":[{\"proto\""), "raw conntrack entries should not be embedded");
    assert!(report.contains("\"inbound_unique_ips\":2"), "expected inbound_unique_ips=2: {report}");
    assert!(report.contains("\"outbound_unique_ips\":1"), "expected outbound_unique_ips=1: {report}");
    assert!(report.contains("\"process_count\":1"), "expected process_count=1: {report}");
    assert!(
        report.contains(&format!("\"traffic_counters\":{{\"available\":true,\"rx\":12345,\"tx\":67890,\"epoch\":\"{vm_id}\"}}")),
        "expected traffic_counters: {report}"
    );
    assert!(
        report.contains("\"top_cpu_process\":{\"pid\":5151,"),
        "expected top_cpu_process pid=5151: {report}"
    );
    assert!(
        report.contains("\"process\":\"sing-box\""),
        "expected top_cpu_process sing-box: {report}"
    );
    assert!(
        !report.contains("\"type\":\"suspicious_process\""),
        "sing-box should not trigger suspicious_process alert: {report}"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_suspicious_process_alerts_exclude_proxy_binaries_but_keep_malicious_ones() {
    let benign_procs = vec![
        ProcInfo {
            pid: 201,
            ppid: 1,
            cpu_percent: 15.0,
            rss_bytes: 32 * 1024 * 1024,
            process: "sing-box".to_string(),
            command: "/usr/bin/sing-box run -c /etc/sing-box/config.json".to_string(),
        },
        ProcInfo {
            pid: 202,
            ppid: 1,
            cpu_percent: 10.0,
            rss_bytes: 24 * 1024 * 1024,
            process: "xray".to_string(),
            command: "/usr/bin/xray run -c /etc/xray/config.json".to_string(),
        },
    ];
    let benign_findings = detect_suspicious_processes(&benign_procs);
    assert!(
        benign_findings.is_empty(),
        "expected no suspicious findings for sing-box/xray: {:?}",
        benign_findings
    );
    let empty_verdict = evaluate_socket_abuse(&SocketAbuseInput::default());
    let benign_alerts = build_security_alerts_json(&empty_verdict, &benign_findings);
    assert!(
        !benign_alerts.contains("\"type\":\"suspicious_process\""),
        "unexpected suspicious_process alert for proxy binaries: {benign_alerts}"
    );

    let malicious_procs = vec![
        ProcInfo {
            pid: 301,
            ppid: 1,
            cpu_percent: 99.0,
            rss_bytes: 128 * 1024 * 1024,
            process: "xmrig".to_string(),
            command: "/tmp/xmrig -o stratum+tcp://pool.example:3333".to_string(),
        },
        ProcInfo {
            pid: 302,
            ppid: 1,
            cpu_percent: 2.0,
            rss_bytes: 20 * 1024 * 1024,
            process: "traffmonetizer-cli".to_string(),
            command: "./traffmonetizer-cli start accept --token secret123".to_string(),
        },
    ];
    let malicious_findings = detect_suspicious_processes(&malicious_procs);
    assert_eq!(malicious_findings.len(), 2);
    let malicious_alerts = build_security_alerts_json(&empty_verdict, &malicious_findings);
    assert!(malicious_alerts.contains("\"type\":\"suspicious_process\""));
    assert!(malicious_alerts.contains("发现疑似恶意/违规进程：xmrig (PID 301)"));
}
