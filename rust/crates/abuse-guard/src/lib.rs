#![forbid(unsafe_code)]

//! Pure-`std`, `#![forbid(unsafe_code)]` prohibited-activity detection,
//! bounded host/container process collection, and corroboration/quarantine
//! engine migrated from:
//! - `client/abuse_detection.py`
//! - `client/abuse_collection.py`
//! - `client/abuse_guard.py`

pub mod collection;
pub mod detection;
pub mod engine;
mod py_ast;

pub use collection::{
    collect, collect_host, collect_host_with, host_metadata, host_metadata_from, parse_processes,
    posix_normpath, process_script, python_entrypoint, read_host_entrypoint,
    read_host_entrypoint_under, resolve_targets, scoped_host_processes, shlex_quote,
    verify_host_processes, verify_host_processes_with, verify_live_processes, ScopedHostProcess,
    PROCESS_SCRIPT,
};
pub use detection::{
    evaluate_process, network_evidence, public_ip, source_evidence, target_ip, tool_evidence,
    url_host, Finding, ProcessRecord, SocketRecord, SourceEvidence, SourceFeatures, AUTH_TOOLS,
    IDENTITY_KEYS, NODE_LIMIT, PASSWORD_KEYS, SCANNERS, SENSITIVE_PORTS, SOURCE_LIMIT,
    USERNAME_KEYS,
};
pub use engine::{
    build_abuse_event_payload, build_abuse_event_payload_json, kind_title, now_unix_secs_f64,
    AbuseAlert, AbuseCheckResult, AbuseEngine, AbuseIsolationDriver, ContainerTarget,
    NetworkQuarantineOutcome, PlainIsolationDriver, SharedAbuseEngine,
};

#[cfg(test)]
mod tests {
    use super::*;
    use net_guard::{DriverReleaseOutcome, IsolationDriver, QuarantineJournal, json_val_to_string};
    use runtime_drivers::JsonVal;
    use std::collections::BTreeMap;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

    fn temp_dir(label: &str) -> PathBuf {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!(
            "narwhal_abuse_guard_{label}_{}_{seq}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn base64_encode(data: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            out.push(TABLE[(b0 >> 2) as usize] as char);
            out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            if chunk.len() > 1 {
                out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(TABLE[(b2 & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    const IDENTITY_SRC: &str = r#"
import requests
from concurrent.futures import ThreadPoolExecutor
def generate_id_card(i):
    return str(i).zfill(18)
with ThreadPoolExecutor(max_workers=100) as pool:
    for i in range(100000):
        requests.post('https://example.org/patient/bind/add', json={'idcard': generate_id_card(i)})
"#;

    const CREDENTIALS_SRC: &str = r#"
import requests as r
import itertools
users = ['example']
with open('passwords.txt') as f:
    passwords = f.read().splitlines()
for user, pwd in itertools.product(users, passwords):
    r.post('https://example.org/login', json={'username': user, 'password': pwd})
"#;

    fn make_flow(
        pid: u32,
        ip: &str,
        port: u16,
        state: &str,
        direction: &str,
    ) -> SocketRecord {
        SocketRecord {
            pid,
            remote_ip: ip.to_string(),
            remote: format!("{ip}:{port}"),
            state: state.to_string(),
            proto: "tcp".to_string(),
            direction: direction.to_string(),
        }
    }

    fn sample_collector_out(
        pid: u32,
        ticks: &str,
        executable: &str,
        cwd: &str,
        argv: &[&str],
    ) -> String {
        let mut raw_argv = Vec::new();
        for a in argv {
            raw_argv.extend_from_slice(a.as_bytes());
            raw_argv.push(0);
        }
        format!(
            "@@NW_ABUSE_V1@@\n{pid}\t{ticks}\t{}\t{}\t{}\n@@NW_END@@:20:1\n",
            base64_encode(executable.as_bytes()),
            base64_encode(cwd.as_bytes()),
            base64_encode(&raw_argv),
        )
    }

    // -----------------------------------------------------------------------
    // 1. Detection Tests (`tests/test_abuse_detection.py`)
    // -----------------------------------------------------------------------

    #[test]
    fn test_ip_and_url_host_classification() {
        assert_eq!(public_ip("8.8.8.8"), "8.8.8.8");
        assert_eq!(public_ip("::ffff:8.8.8.8"), "8.8.8.8");
        assert_eq!(public_ip("2001:4860:4860::8888"), "2001:4860:4860::8888");
        assert_eq!(public_ip("10.0.0.1"), "");
        assert_eq!(public_ip("100.64.0.1"), "");
        assert_eq!(public_ip("127.0.0.1"), "");
        assert_eq!(public_ip("169.254.1.1"), "");
        assert_eq!(public_ip("224.0.0.1"), "");
        assert_eq!(public_ip("0.0.0.0"), "");
        assert_eq!(public_ip("::1"), "");
        assert_eq!(public_ip("fe80::1%eth0"), "");

        assert_eq!(target_ip("8.8.8.8"), "8.8.8.8");
        assert_eq!(target_ip("10.0.0.2"), "10.0.0.2");
        assert_eq!(target_ip("192.168.1.5"), "192.168.1.5");
        assert_eq!(target_ip("::ffff:10.0.0.2"), "10.0.0.2");
        assert_eq!(target_ip("127.0.0.1"), "");
        assert_eq!(target_ip("0.0.0.0"), "");
        assert_eq!(target_ip("169.254.1.1"), "");
        assert_eq!(target_ip("224.0.0.1"), "");
        assert_eq!(target_ip("240.0.0.1"), "");

        assert_eq!(url_host("https://Example.ORG./login?a=1"), "example.org");
        assert_eq!(url_host("http://8.8.8.8:8080/api"), "8.8.8.8");
        assert_eq!(url_host("http://localhost/api"), "");
        assert_eq!(url_host("http://127.0.0.1/api"), "");
        assert_eq!(url_host("http://10.0.0.1/api"), "");
        assert_eq!(url_host("http://service.internal/api"), "");
        assert_eq!(url_host("http://printer.local/api"), "");
        assert_eq!(url_host("ftp://example.org/file"), "");
    }

    #[test]
    fn test_identity_enumeration_requires_live_owned_connections() {
        let mut target_ips = BTreeMap::new();
        target_ips.insert("example.org".to_string(), vec!["8.8.8.8".to_string()]);
        let p = ProcessRecord {
            pid: 22,
            start_ticks: "12345".to_string(),
            executable: "/usr/bin/python3".to_string(),
            cwd: "/root".to_string(),
            argv: vec!["python3".to_string(), "1.py".to_string()],
            source: Some(IDENTITY_SRC.to_string()),
            target_ips,
            host_pid: None,
            source_coverage: None,
        };
        assert_eq!(
            source_evidence(Some(IDENTITY_SRC)).kinds,
            vec!["identity_enumeration".to_string()]
        );
        assert!(evaluate_process(&p, &[]).is_empty());
        assert!(evaluate_process(&p, &[make_flow(23, "8.8.8.8", 443, "established", "outbound")]).is_empty());
        assert!(evaluate_process(&p, &[make_flow(22, "8.8.8.8", 443, "established", "inbound")]).is_empty());
        assert!(evaluate_process(&p, &[make_flow(22, "10.0.0.2", 443, "established", "outbound")]).is_empty());

        let findings = evaluate_process(&p, &[make_flow(22, "8.8.8.8", 443, "established", "outbound")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "identity_enumeration");
        assert_eq!(findings[0].confidence, "high");
        let serialized = json_val_to_string(&findings[0].to_json_val(), false);
        assert!(!serialized.contains("\"source\":"));
        assert!(!serialized.contains("idcard"));

        let mut p_mismatch = p.clone();
        p_mismatch
            .target_ips
            .insert("example.org".to_string(), vec!["1.1.1.1".to_string()]);
        assert!(evaluate_process(&p_mismatch, &[make_flow(22, "8.8.8.8", 443, "established", "outbound")]).is_empty());

        let mut p_empty = p.clone();
        p_empty.target_ips.clear();
        assert!(evaluate_process(&p_empty, &[make_flow(22, "8.8.8.8", 443, "established", "outbound")]).is_empty());
    }

    #[test]
    fn test_credential_dictionary_and_aliases() {
        assert_eq!(
            source_evidence(Some(CREDENTIALS_SRC)).kinds,
            vec!["credential_stuffing".to_string()]
        );
        let session_src = CREDENTIALS_SRC
            .replace("import requests as r", "import requests as r\ns=r.Session()")
            .replace("r.post(", "s.post(");
        assert_eq!(
            source_evidence(Some(&session_src)).kinds,
            vec!["credential_stuffing".to_string()]
        );
    }

    #[test]
    fn test_named_worker_count_and_named_url_match_screenshot_shape() {
        let base = IDENTITY_SRC
            .replace("max_workers=100", "max_workers=MAX_WORKERS")
            .replace("'https://example.org/patient/bind/add'", "TARGET_URL");
        let source = format!(
            "MAX_WORKERS = 100\nBASE_URL='https://example.org'\nTARGET_URL=BASE_URL+'/patient/bind/add'\n{base}"
        );
        let result = source_evidence(Some(&source));
        assert_eq!(result.kinds, vec!["identity_enumeration".to_string()]);
        assert_eq!(result.features.as_ref().unwrap().concurrency, 100);
        assert_eq!(result.target_hosts, vec!["example.org".to_string()]);

        let reassigned = format!("{source}\nMAX_WORKERS=int(input())\n");
        assert!(source_evidence(Some(&reassigned)).kinds.is_empty());
    }

    #[test]
    fn test_dictionary_login_bruteforce_not_customer_import() {
        let single = r#"
import requests
with open('passwords.txt') as f:
    passwords=f.read().splitlines()
for pwd in passwords:
    requests.post('https://example.org/login',json={'username':'example','password':pwd})
"#;
        assert_eq!(
            source_evidence(Some(single)).kinds,
            vec!["authentication_bruteforce".to_string()]
        );
        assert!(source_evidence(Some(&single.replace("/login", "/customers/import")))
            .kinds
            .is_empty());
    }

    #[test]
    fn test_concurrency_python_telegram_and_customer_login_are_not_proof() {
        let innocent = r#"
import requests
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=100) as pool:
    for i in range(1000):
        requests.post('https://example.org/api', json={'username': 'customer', 'password': 'not-retained'})
"#;
        assert!(source_evidence(Some(innocent)).kinds.is_empty());
        assert!(tool_evidence(&[
            "python3".to_string(),
            "telegram-bot.py".to_string(),
            "100".to_string()
        ])
        .is_empty());
        assert!(source_evidence(Some(
            &IDENTITY_SRC.replace("generate_id_card", "read_customer_id")
        ))
        .kinds
        .is_empty());
    }

    #[test]
    fn test_dead_branches_comments_and_local_test_not_promoted() {
        let indented: String = IDENTITY_SRC
            .lines()
            .map(|l| format!("    {l}\n"))
            .collect();
        let dead = format!("if False:\n{indented}");
        assert!(source_evidence(Some(&dead)).kinds.is_empty());

        let comment = format!("# {:?}", IDENTITY_SRC);
        assert!(source_evidence(Some(&comment)).kinds.is_empty());

        let dormant = format!(
            "def unused_attack():\n{indented}\nimport requests\nrequests.get(\"https://example.org/health\")\n"
        );
        assert!(source_evidence(Some(&dormant)).kinds.is_empty());

        let nested_indented: String = IDENTITY_SRC
            .lines()
            .map(|l| format!("        {l}\n"))
            .collect();
        let nested = format!("def main():\n    def unused_attack():\n{nested_indented}    return 1\nmain()\n");
        assert!(source_evidence(Some(&nested)).kinds.is_empty());

        for endpoint in [
            "http://localhost/api",
            "http://127.0.0.1/api",
            "http://10.0.0.1/api",
            "http://service.internal/api",
        ] {
            let src = IDENTITY_SRC.replace("https://example.org/patient/bind/add", endpoint);
            assert!(source_evidence(Some(&src)).kinds.is_empty());
        }
    }

    #[test]
    fn test_no_source_or_credentials_or_personal_records_in_evidence() {
        let src = format!(
            "{IDENTITY_SRC}\npassword='example-secret'\nrecord='example-private-record'\n"
        );
        let result = json_val_to_string(&source_evidence(Some(&src)).to_json_val(), false);
        assert!(!result.contains("example-secret"));
        assert!(!result.contains("example-private-record"));
        assert!(!result.contains("/patient/bind/add"));
        assert!(!source_evidence(Some(&"x".repeat(70000))).available);
        assert!(!source_evidence(Some("for !!")).available);
    }

    #[test]
    fn test_active_tools_include_lateral_but_not_loopback_or_passive_targets() {
        for name in ["nmap", "masscan", "zmap", "rustscan"] {
            let f = tool_evidence(&[name.to_string(), "8.8.8.8".to_string()]);
            assert_eq!(f[0].kind, "outbound_scan");
        }
        for name in ["hydra", "medusa", "ncrack", "patator"] {
            let f = tool_evidence(&[name.to_string(), "8.8.8.8".to_string()]);
            assert_eq!(f[0].kind, "authentication_bruteforce");
        }
        let lat = tool_evidence(&["nmap".to_string(), "10.0.0.0/8".to_string()]);
        assert_eq!(lat[0].private_target_count, Some(1));

        for argv in [
            vec!["nmap", "--help"],
            vec!["nmap", "-sL", "8.8.8.8"],
            vec!["nmap", "127.0.0.1"],
            vec!["nmap", "0.0.0.0/0"],
            vec!["echo", "nmap 8.8.8.8"],
            vec!["nmap", "--exclude", "8.8.8.8", "127.0.0.1"],
            vec!["hydra", "-p", "8.8.8.8", "127.0.0.1", "ssh"],
            vec!["patator", "ssh_login", "host=127.0.0.1", "password=8.8.8.8"],
        ] {
            let owned: Vec<String> = argv.into_iter().map(ToString::to_string).collect();
            assert!(tool_evidence(&owned).is_empty());
        }

        assert!(!tool_evidence(&[
            "medusa".to_string(),
            "-h".to_string(),
            "8.8.8.8".to_string(),
            "-u".to_string(),
            "example".to_string()
        ])
        .is_empty());
        assert!(!tool_evidence(&[
            "patator".to_string(),
            "ssh_login".to_string(),
            "host=8.8.8.8".to_string(),
            "user=example".to_string(),
            "password=FILE0".to_string()
        ])
        .is_empty());

        let mut fake = ProcessRecord {
            pid: 22,
            start_ticks: "123".to_string(),
            executable: "/bin/sleep".to_string(),
            cwd: "/".to_string(),
            argv: vec!["nmap".to_string(), "8.8.8.8".to_string()],
            ..Default::default()
        };
        assert!(evaluate_process(&fake, &[]).is_empty());
        fake.executable = "/usr/bin/nmap".to_string();
        assert_eq!(evaluate_process(&fake, &[])[0].kind, "outbound_scan");
    }

    #[test]
    fn test_network_scan_directional_and_pid_one_supported() {
        let vertical: Vec<SocketRecord> = (1..40)
            .map(|n| make_flow(22, "8.8.8.8", n, "syn_sent", "outbound"))
            .collect();
        let res = network_evidence(&vertical);
        assert_eq!(res[0].vertical_ports, Some(39));
        assert_eq!(res[0].confidence, "corroboration_required");

        let inbound: Vec<SocketRecord> = (1..40)
            .map(|n| make_flow(22, "8.8.8.8", n, "syn_sent", "inbound"))
            .collect();
        assert!(network_evidence(&inbound).is_empty());

        let split_pids: Vec<SocketRecord> = (1..40)
            .map(|n| make_flow((n as u32) + 2, "8.8.8.8", n, "syn_sent", "outbound"))
            .collect();
        assert!(network_evidence(&split_pids).is_empty());

        let cdn_443: Vec<SocketRecord> = (1..70)
            .map(|i| make_flow(22, &format!("8.8.4.{i}"), 443, "syn_sent", "outbound"))
            .collect();
        assert!(network_evidence(&cdn_443).is_empty());

        let ssh_22: Vec<SocketRecord> = (1..70)
            .map(|i| make_flow(22, &format!("8.8.4.{i}"), 22, "syn_sent", "outbound"))
            .collect();
        assert_eq!(network_evidence(&ssh_22)[0].horizontal_targets, Some(69));

        let ssh_est: Vec<SocketRecord> = (1..70)
            .map(|i| make_flow(22, &format!("8.8.4.{i}"), 22, "established", "outbound"))
            .collect();
        assert!(network_evidence(&ssh_est).is_empty());

        let lateral: Vec<SocketRecord> = (1..40)
            .map(|n| make_flow(1, "10.0.0.2", n, "syn_sent", "outbound"))
            .collect();
        let lat_res = network_evidence(&lateral);
        assert_eq!(lat_res[0].private_target_count, Some(1));
        assert_eq!(lat_res[0].pid, 1);

        // Missing start_ticks never qualifies
        let no_ticks = ProcessRecord {
            pid: 22,
            start_ticks: String::new(),
            executable: "/usr/bin/nmap".to_string(),
            argv: vec!["nmap".to_string(), "8.8.8.8".to_string()],
            ..Default::default()
        };
        assert!(evaluate_process(&no_ticks, &[]).is_empty());
    }

    // -----------------------------------------------------------------------
    // 2. Collection Tests (`tests/test_abuse_collection.py`)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bounded_process_parser_and_entrypoint() {
        let out = sample_collector_out(
            22,
            "123",
            "/usr/bin/python3.12",
            "/root",
            &["python3", "1.py"],
        );
        let proc_item = &parse_processes(&out).expect("parse")[0];
        assert_eq!(proc_item.pid, 22);
        assert_eq!(proc_item.start_ticks, "123");
        assert_eq!(
            python_entrypoint(proc_item),
            (None, Some("/root/1.py".to_string()))
        );

        let inline_proc = ProcessRecord {
            argv: vec![
                "python3".to_string(),
                "-c".to_string(),
                "print(1)".to_string(),
            ],
            ..proc_item.clone()
        };
        assert_eq!(
            python_entrypoint(&inline_proc),
            (Some("print(1)".to_string()), None)
        );

        let mod_proc = ProcessRecord {
            argv: vec![
                "python3".to_string(),
                "-m".to_string(),
                "customer_module".to_string(),
            ],
            ..proc_item.clone()
        };
        assert_eq!(python_entrypoint(&mod_proc), (None, None));
    }

    #[test]
    fn test_only_running_entrypoint_read_never_customer_history() {
        let mut calls: Vec<String> = Vec::new();
        let mut exec = |_: &(), cmd: &str| -> (bool, String) {
            calls.push(cmd.to_string());
            if cmd.contains("@@NW_ABUSE_V1@@") {
                (
                    true,
                    sample_collector_out(
                        22,
                        "123",
                        "/usr/bin/python3.12",
                        "/root",
                        &["python3", "1.py", "verify_history.json"],
                    ),
                )
            } else {
                (true, base64_encode(b"print(\"example\")"))
            }
        };
        let sockets = vec![make_flow(22, "8.8.8.8", 443, "established", "outbound")];
        let result = collect(&(), &mut exec, &sockets).expect("collect");
        assert_eq!(result[0].source.as_deref(), Some("print(\"example\")"));
        assert_eq!(calls.len(), 2);
        assert!(!calls[1].contains("verify_history.json"));
        assert!(!calls[1].contains("eval"));
    }

    #[test]
    fn test_no_source_read_without_owned_outbound_and_source_limit() {
        let mut calls: Vec<String> = Vec::new();
        {
            let mut exec = |_: &(), cmd: &str| -> (bool, String) {
                calls.push(cmd.to_string());
                if cmd.contains("@@NW_ABUSE_V1@@") {
                    (
                        true,
                        sample_collector_out(
                            22,
                            "123",
                            "/usr/bin/python3.12",
                            "/root",
                            &["python3", "1.py"],
                        ),
                    )
                } else {
                    (true, base64_encode(&vec![b'x'; 65537]))
                }
            };
            let res_no_sock = collect(&(), &mut exec, &[]).expect("collect empty");
            assert!(res_no_sock[0].source.is_none());
        }
        assert_eq!(calls.len(), 1);

        let sockets = vec![make_flow(22, "8.8.8.8", 443, "established", "outbound")];
        {
            let mut exec = |_: &(), cmd: &str| -> (bool, String) {
                calls.push(cmd.to_string());
                if cmd.contains("@@NW_ABUSE_V1@@") {
                    (
                        true,
                        sample_collector_out(
                            22,
                            "123",
                            "/usr/bin/python3.12",
                            "/root",
                            &["python3", "1.py"],
                        ),
                    )
                } else {
                    (true, base64_encode(&vec![b'x'; 65537]))
                }
            };
            let res_oversize = collect(&(), &mut exec, &sockets).expect("collect oversize");
            assert!(res_oversize[0].source.is_none());
        }
    }

    #[test]
    fn test_incarnation_reverified_and_custom_socket_owners() {
        assert!(parse_processes("bad data").is_err());

        let finding = Finding {
            kind: "outbound_scan".to_string(),
            confidence: "high".to_string(),
            basis: "active_prohibited_tool".to_string(),
            pid: 22,
            start_ticks: "123".to_string(),
            tool: Some("nmap".to_string()),
            source_sha256: None,
            features: None,
            target_hosts: Vec::new(),
            target_count: Some(1),
            public_target_count: Some(1),
            private_target_count: Some(0),
            owned_http_connections: None,
            pending_attempts: None,
            vertical_ports: None,
            horizontal_targets: None,
            pending_ratio: None,
            failed_ratio: None,
        };
        assert!(verify_live_processes(
            &(),
            &mut |_, _| (
                true,
                sample_collector_out(22, "different", "/usr/bin/python3", "/root", &["python3"])
            ),
            std::slice::from_ref(&finding)
        )
        .is_err());
        assert!(verify_live_processes(
            &(),
            &mut |_, _| (
                true,
                sample_collector_out(22, "123", "/usr/bin/python3", "/root", &["python3"])
            ),
            std::slice::from_ref(&finding)
        )
        .is_ok());

        let script = process_script(&[make_flow(567, "8.8.8.8", 80, "syn_sent", "outbound")]);
        assert!(script.contains("for d in /proc/567 /proc/[0-9]*;"));
        assert!(script.contains("case \"$p\" in 567)"));
        let sample = sample_collector_out(22, "123", "/usr/bin/python3", "/root", &["python3"]);
        assert_eq!(
            parse_processes(&format!("{sample}{sample}"))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn test_native_pid_one_metadata_and_entrypoint_walk() {
        let dir = temp_dir("entrypoint");
        let app_py = dir.join("app.py");
        fs::write(&app_py, "print(1)").unwrap();
        fs::write(
            dir.join("verify_history.json"),
            "synthetic-private-record-do-not-read",
        )
        .unwrap();

        let proc_item = ProcessRecord {
            pid: 1,
            host_pid: Some(123),
            start_ticks: "456".to_string(),
            executable: "/usr/bin/python3".to_string(),
            cwd: "/".to_string(),
            argv: vec![
                "python3".to_string(),
                "app.py".to_string(),
                "verify_history.json".to_string(),
            ],
            ..Default::default()
        };
        assert_eq!(
            read_host_entrypoint_under(&dir, &proc_item)
                .unwrap()
                .as_deref(),
            Some("print(1)")
        );

        // Traversal `..` must be rejected
        let traversal = ProcessRecord {
            argv: vec!["python3".to_string(), "../app.py".to_string()],
            ..proc_item.clone()
        };
        assert_eq!(read_host_entrypoint_under(&dir, &traversal).unwrap(), None);

        // > 65536 bytes must return None
        fs::write(&app_py, vec![b'x'; 65537]).unwrap();
        assert_eq!(read_host_entrypoint_under(&dir, &proc_item).unwrap(), None);

        // Test collect_host_with & verify_host_processes_with
        let inline_proc = ProcessRecord {
            argv: vec![
                "python3".to_string(),
                "-c".to_string(),
                "print(1)".to_string(),
            ],
            ..proc_item.clone()
        };
        let scoped = vec![ScopedHostProcess {
            host_pid: 123,
            pid: 1,
            process: "python3".to_string(),
        }];
        let sockets = vec![make_flow(1, "8.8.8.8", 443, "established", "outbound")];
        let collected = collect_host_with(
            &scoped,
            &sockets,
            &(),
            &mut |_, _| (false, String::new()),
            &mut |_| Ok(inline_proc.clone()),
            &mut |p| read_host_entrypoint_under(&dir, p),
        )
        .expect("collect_host_with");
        assert_eq!(collected[0].source.as_deref(), Some("print(1)"));

        let finding = Finding {
            kind: "identity_enumeration".to_string(),
            confidence: "high".to_string(),
            basis: "running_entrypoint_and_owned_public_http".to_string(),
            pid: 1,
            start_ticks: "456".to_string(),
            tool: None,
            source_sha256: None,
            features: None,
            target_hosts: Vec::new(),
            target_count: None,
            public_target_count: None,
            private_target_count: None,
            owned_http_connections: None,
            pending_attempts: None,
            vertical_ports: None,
            horizontal_targets: None,
            pending_ratio: None,
            failed_ratio: None,
        };
        assert!(verify_host_processes_with(
            &collected,
            std::slice::from_ref(&finding),
            &mut |_| Ok(inline_proc.clone())
        )
        .is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // 3. Engine Tests (`tests/test_abuse_guard.py` & `tests/test_abuse_api.py`)
    // -----------------------------------------------------------------------

    struct MockDriver {
        changed: usize,
        fail_isolate: bool,
        fail_evidence: bool,
    }

    impl MockDriver {
        fn new() -> Self {
            Self {
                changed: 0,
                fail_isolate: false,
                fail_evidence: false,
            }
        }
    }

    impl IsolationDriver for MockDriver {
        fn snapshot(&mut self) -> Result<JsonVal, String> {
            Ok(JsonVal::Obj(BTreeMap::from([(
                "original_network".to_string(),
                JsonVal::Str("kept".to_string()),
            )])))
        }
        fn isolate(&mut self, _backup: &JsonVal) -> Result<(), String> {
            if self.fail_isolate {
                return Err("verification failed".to_string());
            }
            self.changed += 1;
            Ok(())
        }
        fn verify(&mut self, _backup: &JsonVal) -> Result<(), String> {
            Ok(())
        }
        fn release(&mut self, _backup: &JsonVal) -> Result<DriverReleaseOutcome, String> {
            Ok(DriverReleaseOutcome {
                container_deleted: false,
            })
        }
        fn prove_replaced(&mut self) -> Result<String, String> {
            Ok("none".to_string())
        }
    }

    impl AbuseIsolationDriver for MockDriver {
        fn check_evidence(&mut self, _findings: &[Finding]) -> Result<(), String> {
            if self.fail_evidence {
                Err("container restarted during collection; no new quarantine".to_string())
            } else {
                Ok(())
            }
        }
    }

    fn podman_container(name: &str, id: &str) -> ContainerTarget {
        ContainerTarget {
            runtime: "podman".to_string(),
            runtime_bin: "podman".to_string(),
            project: String::new(),
            name: name.to_string(),
            id: id.to_string(),
            pid: Some(101),
            stable_id: id.to_string(),
            instance_id: String::new(),
        }
    }

    fn nmap_process(ticks: &str) -> ProcessRecord {
        ProcessRecord {
            pid: 22,
            start_ticks: ticks.to_string(),
            executable: "/usr/bin/nmap".to_string(),
            cwd: "/".to_string(),
            argv: vec!["nmap".to_string(), "8.8.8.8".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn test_two_fresh_corroborating_samples_and_persistence() {
        let dir = temp_dir("engine_corroborate");
        let journal = QuarantineJournal::new(Some(&dir.join("state.json"))).unwrap();
        let mut engine = AbuseEngine::new(journal.clone(), 20.0, 180.0);
        let id = "a".repeat(64);
        let container = podman_container("customer", &id);
        let procs = vec![nmap_process("12345")];
        let mut driver = MockDriver::new();

        let r1 = engine
            .check(&container, &id, &mut driver, &procs, &[], Some(100.0))
            .unwrap();
        assert_eq!(r1.state, "suspected");
        assert_eq!(driver.changed, 0);

        let r2 = engine
            .check(&container, &id, &mut driver, &procs, &[], Some(110.0))
            .unwrap();
        assert_eq!(r2.state, "suspected");

        let r3 = engine
            .check(&container, &id, &mut driver, &procs, &[], Some(121.0))
            .unwrap();
        assert_eq!(r3.state, "isolated");
        let alert = r3.alert.as_ref().unwrap();
        assert_eq!(alert.severity, "critical");
        assert!(alert.network_quarantine.egress_blocked);
        assert!(alert.network_quarantine.ingress_blocked);
        assert_eq!(driver.changed, 1);

        // Restarted engine persists quarantine even after network activity disappears
        let mut restarted = AbuseEngine::new(journal, 20.0, 180.0);
        let r4 = restarted
            .check(&container, &id, &mut driver, &[], &[], Some(180.0))
            .unwrap();
        assert_eq!(r4.state, "isolated");
        assert!(r4.alert.as_ref().unwrap().message.contains("等待管理员复核"));
        assert_eq!(driver.changed, 2);

        // Renamed instance retains quarantine, replacement gets fresh state
        let renamed = podman_container("renamed-customer", &id);
        let r5 = restarted
            .check(&renamed, &id, &mut driver, &[], &[], Some(185.0))
            .unwrap();
        assert_eq!(r5.state, "isolated");

        let new_id = "c".repeat(64);
        let replacement = podman_container("renamed-customer", &new_id);
        let r6 = restarted
            .check(&replacement, &new_id, &mut driver, &[], &[], Some(190.0))
            .unwrap();
        assert_eq!(r6.state, "not_observed");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_incarnation_change_stale_gap_and_isolation_failure() {
        let dir = temp_dir("engine_edge");
        let journal = QuarantineJournal::new(Some(&dir.join("state.json"))).unwrap();
        let mut engine = AbuseEngine::new(journal, 20.0, 180.0);
        let id = "a".repeat(64);
        let container = podman_container("customer", &id);
        let mut driver = MockDriver::new();

        // Incarnation change does not confirm old evidence
        engine
            .check(
                &container,
                &id,
                &mut driver,
                &[nmap_process("12345")],
                &[],
                Some(100.0),
            )
            .unwrap();
        let res_inc = engine
            .check(
                &container,
                &id,
                &mut driver,
                &[nmap_process("other-process")],
                &[],
                Some(130.0),
            )
            .unwrap();
        assert_eq!(res_inc.state, "suspected");
        assert_eq!(driver.changed, 0);

        // Discontinuous gap (>180s) and missing sample reset confirmation
        assert_eq!(
            engine
                .check(
                    &container,
                    &id,
                    &mut driver,
                    &[nmap_process("other-process")],
                    &[],
                    Some(500.0)
                )
                .unwrap()
                .state,
            "suspected"
        );
        assert_eq!(
            engine
                .check(&container, &id, &mut driver, &[], &[], Some(510.0))
                .unwrap()
                .state,
            "not_observed"
        );
        assert_eq!(
            engine
                .check(
                    &container,
                    &id,
                    &mut driver,
                    &[nmap_process("other-process")],
                    &[],
                    Some(530.0)
                )
                .unwrap()
                .state,
            "suspected"
        );

        // Isolation failure remains critical, not success
        driver.fail_isolate = true;
        let res_fail = engine
            .check(
                &container,
                &id,
                &mut driver,
                &[nmap_process("other-process")],
                &[],
                Some(560.0),
            )
            .unwrap();
        assert_eq!(res_fail.state, "failed");
        let alert = res_fail.alert.as_ref().unwrap();
        assert!(!alert.network_quarantine.ingress_blocked);
        assert_eq!(alert.severity, "critical");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_notification_delivery_backoff_stale_and_collection_failure() {
        let dir = temp_dir("engine_notify");
        let journal = QuarantineJournal::new(Some(&dir.join("state.json"))).unwrap();
        let mut engine = AbuseEngine::new(journal, 20.0, 180.0);
        let id = "a".repeat(64);
        let container = podman_container("customer", &id);
        let procs = vec![nmap_process("12345")];
        let mut driver = MockDriver::new();

        engine
            .check(&container, &id, &mut driver, &procs, &[], Some(100.0))
            .unwrap();
        let mut result = engine
            .check(&container, &id, &mut driver, &procs, &[], Some(130.0))
            .unwrap();

        // Error retries immediately
        engine.notify(&mut result, |_| Err("offline".to_string()), 130.0);
        assert_eq!(result.notification_pending, Some(true));

        // Server ACK without telegram delivery retries after 30s (not before)
        let mut ack_calls = 0usize;
        let mut emit_unconfigured = |_: &AbuseAlert| -> Result<JsonVal, String> {
            ack_calls += 1;
            JsonVal::parse(r#"{"ok":true,"telegram_delivery":{"state":"unconfigured"}}"#)
        };
        engine.notify(&mut result, &mut emit_unconfigured, 130.0);
        assert_eq!(result.event_relayed, Some(true));
        assert_eq!(result.notification_pending, Some(true));
        engine.notify(&mut result, &mut emit_unconfigured, 140.0);
        engine.notify(&mut result, &mut emit_unconfigured, 161.0);
        assert_eq!(ack_calls, 2);

        // Delivered suppresses for 300s
        let mut delivered_calls = 0usize;
        let mut emit_delivered = |_: &AbuseAlert| -> Result<JsonVal, String> {
            delivered_calls += 1;
            JsonVal::parse(r#"{"ok":true,"telegram_delivery":{"state":"delivered"}}"#)
        };
        engine.notify(&mut result, &mut emit_delivered, 200.0);
        assert_eq!(result.notification_pending, Some(false));
        engine.notify(&mut result, &mut emit_delivered, 300.0);
        assert_eq!(delivered_calls, 1);

        // Stale quarantine (>900s) downgrades to stale/unverified
        engine.results.insert(container.identity_key(), result);
        let st = engine.status(&container, Some(1100.0));
        assert_eq!(st.state, "stale");
        assert_eq!(
            st.alert.as_ref().unwrap().network_quarantine.status,
            "unverified"
        );
        assert!(st.alert.as_ref().unwrap().message.contains("不表示风险已恢复"));

        // Collection failure retains pending review as unverified
        engine.record_collection_failure(&container, 150.0);
        let after_fail = engine.results.get(&container.identity_key()).unwrap();
        assert_eq!(after_fail.state, "unverified");
        assert_eq!(after_fail.alert.as_ref().unwrap().severity, "critical");
        assert!(!after_fail.alert.as_ref().unwrap().network_quarantine.ingress_blocked);

        // Runman generation tracking in status
        let runman_ctr = ContainerTarget {
            runtime: "runman".to_string(),
            runtime_bin: "runman".to_string(),
            project: "default".to_string(),
            name: "11111111-1111-4111-8111-111111111111".to_string(),
            id: "11111111-1111-4111-8111-111111111111".to_string(),
            pid: Some(200),
            stable_id: "11111111-1111-4111-8111-111111111111".to_string(),
            instance_id: "22222222-2222-4222-8222-222222222222".to_string(),
        };
        engine.results.insert(
            runman_ctr.identity_key(),
            AbuseCheckResult {
                state: "isolated".to_string(),
                observed_at: Some(100.0),
                instance_id: Some(runman_ctr.instance_id.clone()),
                findings: None,
                alert: None,
                coverage: None,
                collection_failed_at: None,
                event_relayed: None,
                notification_pending: None,
            },
        );
        assert_eq!(engine.status(&runman_ctr, Some(120.0)).state, "isolated");

        let mut replacement_rm = runman_ctr.clone();
        replacement_rm.instance_id = "33333333-3333-4333-8333-333333333333".to_string();
        assert_eq!(engine.status(&replacement_rm, Some(120.0)).state, "pending");

        let mut missing_gen = runman_ctr.clone();
        missing_gen.instance_id.clear();
        assert_eq!(engine.status(&missing_gen, Some(120.0)).state, "pending");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_schedule_worker_forget_and_event_payload_contract() {
        let dir = temp_dir("engine_schedule");
        let journal = QuarantineJournal::new(Some(&dir.join("state.json"))).unwrap();
        let shared = SharedAbuseEngine::new(AbuseEngine::new(journal, 20.0, 180.0));
        let id = "a".repeat(64);
        let container = podman_container("customer", &id);

        let scheduled = shared.schedule(
            std::slice::from_ref(&container),
            |c| Ok((c.id.clone(), MockDriver::new(), Vec::new(), Vec::new())),
            |_| Ok(JsonVal::Obj(BTreeMap::new())),
            8,
        );
        assert!(scheduled);
        shared.join_worker();

        assert_eq!(shared.status(&container, None).state, "not_observed");

        // Protected container is excluded
        let mut protected = container.clone();
        protected.name = "narwhal-monitor-server".to_string();
        assert_eq!(shared.status(&protected, None).state, "protected");

        // forget_replaced preserves replacement result, removes old
        shared.forget_replaced(&container, &"b".repeat(64));
        assert_eq!(shared.status(&container, None).state, "not_observed");
        shared.forget_replaced(&container, &id);
        assert!(shared.lock().results.get(&container.identity_key()).is_none());

        // Chinese identity key, async with ClientSession, Path wordlist, while False, rustscan --addresses=
        let cn_src = r#"
import aiohttp
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
def 生成_身份证(n):
    return str(n)
while False:
    pass
async def run():
    p = Path('cn_wordlist.txt')
    async with aiohttp.ClientSession() as client:
        with ProcessPoolExecutor(32) as ex:
            for i in range(500):
                await client.post('https://example.org/api/query', data={'身份证号': 生成_身份证(i)})
run()
"#;
        let ev = source_evidence(Some(cn_src));
        assert_eq!(ev.kinds, vec!["identity_enumeration".to_string()]);
        assert_eq!(ev.features.as_ref().unwrap().dictionary_inputs, true);
        assert_eq!(ev.features.as_ref().unwrap().concurrency, 32);

        let rs_tool = tool_evidence(&[
            "rustscan".to_string(),
            "--addresses=8.8.8.8".to_string(),
        ]);
        assert_eq!(rs_tool.len(), 1);
        assert_eq!(rs_tool[0].kind, "outbound_scan");

        // Verify /api/v1/abuse/events JSON payload structure
        let alert = AbuseAlert {
            alert_type: "prohibited_activity".to_string(),
            severity: "critical".to_string(),
            title: "违规活动：对外扫描".to_string(),
            runtime: "podman".to_string(),
            project: String::new(),
            container_name: "customer".to_string(),
            instance_id: id.clone(),
            message: "test".to_string(),
            value: 1,
            threshold: 1,
            abuse_evidence: vec![rs_tool[0].to_json_val()],
            network_quarantine: NetworkQuarantineOutcome {
                status: "isolated".to_string(),
                ingress_blocked: true,
                egress_blocked: true,
                verified_at: Some(100),
                error: None,
                data_preserved: true,
            },
        };
        let payload_json =
            build_abuse_event_payload_json("host-1", "node-1", "1.9.11", 1700000000, &alert);
        let parsed = JsonVal::parse(&payload_json).expect("valid event json");
        assert_eq!(parsed.get_str("host_id"), Some("host-1"));
        assert_eq!(parsed.get_str("node_id"), Some("node-1"));
        assert_eq!(
            parsed.get("alert").and_then(|a| a.get_str("type")),
            Some("prohibited_activity")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_scoped_host_processes_and_symlink_rejection() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("unix_proc");
        let target_ns = dir.join("target-ns");
        let other_ns = dir.join("other-ns");
        fs::write(&target_ns, "").unwrap();
        fs::write(&other_ns, "").unwrap();

        for (host, pid, ns) in [(100u32, 1u32, &target_ns), (101, 2, &target_ns), (200, 1, &other_ns)] {
            let base = dir.join(host.to_string());
            fs::create_dir_all(base.join("ns")).unwrap();
            fs::hard_link(ns, base.join("ns/pid")).unwrap();
            fs::write(
                base.join("status"),
                format!("PPid:\t0\nNSpid:\t{host} {pid}\n"),
            )
            .unwrap();
            fs::write(base.join("comm"), "synthetic-python\n").unwrap();
        }

        let procs = scoped_host_processes(100, &dir, 20000).expect("scoped");
        let pairs: Vec<(u32, u32)> = procs.iter().map(|p| (p.host_pid, p.pid)).collect();
        assert_eq!(pairs, vec![(100, 1), (101, 2)]);
        assert!(scoped_host_processes(100, &dir, 2).is_err());

        // Symlink entrypoint must be rejected with Err
        let real_py = dir.join("real.py");
        let link_py = dir.join("linked.py");
        fs::write(&real_py, "print(1)").unwrap();
        symlink(&real_py, &link_py).unwrap();
        let proc_rec = ProcessRecord {
            pid: 1,
            host_pid: Some(100),
            start_ticks: "123".to_string(),
            executable: "/usr/bin/python3".to_string(),
            cwd: "/".to_string(),
            argv: vec!["python3".to_string(), "linked.py".to_string()],
            ..Default::default()
        };
        assert!(read_host_entrypoint_under(&dir, &proc_rec).is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
