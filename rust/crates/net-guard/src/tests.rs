use super::*;
use std::collections::VecDeque;

fn make_temp_dir(label: &str) -> PathBuf {
    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = env::temp_dir().join(format!(
        "narwhal_net_guard_{label}_{}_{seq}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp test dir");
    dir
}

#[derive(Default)]
struct MockRunner {
    calls: Vec<(Vec<String>, Option<String>)>,
    responses: VecDeque<(bool, String)>,
    default_ok: bool,
    default_out: String,
}

impl MockRunner {
    fn always(ok: bool, out: &str) -> Self {
        Self {
            calls: Vec::new(),
            responses: VecDeque::new(),
            default_ok: ok,
            default_out: out.to_string(),
        }
    }
}

impl CommandRunner for MockRunner {
    fn run(&mut self, args: &[String], stdin: Option<&str>) -> (bool, String) {
        self.calls
            .push((args.to_vec(), stdin.map(ToString::to_string)));
        if let Some(resp) = self.responses.pop_front() {
            resp
        } else {
            (self.default_ok, self.default_out.clone())
        }
    }
}

fn tools_with_all() -> NetToolPaths {
    NetToolPaths {
        nsenter_bin: Some("/usr/bin/nsenter".to_string()),
        nft_bin: Some("/usr/sbin/nft".to_string()),
        iptables_bin: Some("/usr/sbin/iptables".to_string()),
        podman_bin: Some("/usr/bin/podman".to_string()),
        sysctl_bin: Some("sysctl".to_string()),
    }
}

#[test]
fn test_identifier_regex_validators() {
    assert!(is_safe_key("test-vm_1.prod:80@host+a"));
    assert!(!is_safe_key(""));
    assert!(!is_safe_key("bad/name"));
    assert!(!is_safe_key(&"a".repeat(257)));

    assert!(is_safe_veth("veth1a2b"));
    assert!(is_safe_veth("eth0.10-a_b"));
    assert!(!is_safe_veth(""));
    assert!(!is_safe_veth("."));
    assert!(!is_safe_veth(".."));
    assert!(!is_safe_veth("bad;veth"));
    assert!(!is_safe_veth("vethname_too_long_17"));

    assert!(is_safe_quarantine_name("customer-1"));
    assert!(!is_safe_quarantine_name("narwhal-monitor-client"));
    assert!(!is_safe_quarantine_name("narwhal-monitor-server"));
    assert!(!is_safe_quarantine_name("narwhal-monitor-caddy"));
    assert!(!is_safe_quarantine_name("x;evil"));

    assert!(is_uuid_lower("11111111-2222-3333-4444-555555555555"));
    assert!(!is_uuid_v4_lower("11111111-2222-3333-4444-555555555555"));
    assert!(is_uuid_v4_lower("22222222-2222-4222-8222-222222222222"));
    assert!(!is_uuid_v4_lower("22222222-2222-4222-0222-222222222222"));

    assert!(is_valid_incus_operation(
        "/1.0/operations/11111111-2222-3333-4444-555555555555"
    ));
    assert!(!is_valid_incus_operation("/1.0/operations/../bad"));
}

#[test]
fn test_udp_blackhole_validation_rules_and_lifecycle() {
    let dir = make_temp_dir("udp");
    let journal = dir.join("udp-blackhole.json");
    let tools = tools_with_all();
    let mut runner = MockRunner::always(true, "table inet narwhal_udp_guard");

    // Invalid parameters
    let bad_rt = UdpBlackholeApply::new("docker", "my-container", 100);
    let r_rt = apply_udp_blackhole_with(&bad_rt, &journal, &tools, &mut runner, 1000);
    assert!(!r_rt.ok);
    assert!(r_rt.message.contains("不支持的运行时"));

    let bad_name = UdpBlackholeApply::new("runman", "bad/name", 100);
    let r_name = apply_udp_blackhole_with(&bad_name, &journal, &tools, &mut runner, 1000);
    assert!(!r_name.ok);
    assert!(r_name.message.contains("容器名称格式无效"));

    let bad_pid = UdpBlackholeApply::new("runman", "c1", 1);
    let r_pid = apply_udp_blackhole_with(&bad_pid, &journal, &tools, &mut runner, 1000);
    assert!(!r_pid.ok);
    assert!(r_pid.message.contains("容器 PID 无效"));

    let no_nsenter = NetToolPaths {
        nsenter_bin: None,
        ..tools.clone()
    };
    let valid_req = UdpBlackholeApply {
        auto_triggered: true,
        duration: 1200,
        reason: "高危小包泛洪".to_string(),
        ..UdpBlackholeApply::new("runman", "test-vm-1", 1234)
    };
    let r_ns = apply_udp_blackhole_with(&valid_req, &journal, &no_nsenter, &mut runner, 1000);
    assert!(!r_ns.ok);
    assert!(r_ns.message.contains("nsenter"));

    // Apply with allow_dns=true
    let r_ok = apply_udp_blackhole_with(&valid_req, &journal, &tools, &mut runner, 1000);
    assert!(r_ok.ok);
    assert!(r_ok.message.contains("专项阻断"));
    assert!(r_ok.message.contains("放行 53 端口 DNS"));
    assert_eq!(runner.calls.len(), 1);
    assert_eq!(
        runner.calls[0].0,
        vec![
            "/usr/bin/nsenter",
            "-t",
            "1234",
            "-n",
            "--",
            "/usr/sbin/nft",
            "-f",
            "-"
        ]
    );
    let nft_stdin = runner.calls[0].1.as_deref().unwrap();
    assert!(nft_stdin.contains("table inet narwhal_udp_guard"));
    assert!(nft_stdin.contains("udp dport 53 accept"));
    assert!(nft_stdin.contains("ip protocol udp drop"));
    assert!(nft_stdin.contains("ip6 nexthdr udp drop"));

    // Status check
    let st = get_udp_blackhole_status_with(
        "runman",
        "test-vm-1",
        1234,
        &journal,
        &tools,
        Some(&mut runner),
        1040,
    )
    .expect("status");
    assert!(st.active);
    assert!(st.allow_dns);
    assert!(st.auto_triggered);
    assert_eq!(st.expires_at, Some(2200));
    assert_eq!(st.remaining_seconds, Some(1160));
    assert_eq!(st.reason, "高危小包泛洪");

    // Release
    runner.calls.clear();
    let rel = release_udp_blackhole_with(
        "runman",
        "test-vm-1",
        1234,
        "",
        "default",
        &journal,
        &tools,
        &mut runner,
    );
    assert!(rel.ok);
    assert!(rel.message.contains("已解除"));
    assert!(runner
        .calls
        .iter()
        .any(|(args, _)| args.ends_with(&[
            "delete".to_string(),
            "table".to_string(),
            "inet".to_string(),
            "narwhal_udp_guard".to_string()
        ])));

    let st_after = get_udp_blackhole_status_with(
        "runman",
        "test-vm-1",
        1234,
        &journal,
        &tools,
        None,
        1050,
    )
    .expect("status after");
    assert!(!st_after.active);

    // Fallback to iptables when nft fails and allow_dns=false
    let mut fb_runner = MockRunner::always(false, "");
    fb_runner.responses.push_back((false, "nft missing".to_string()));
    fb_runner.responses.push_back((true, String::new()));
    let no_dns = UdpBlackholeApply {
        allow_dns: false,
        ..UdpBlackholeApply::new("incus", "c-no-dns", 2222)
    };
    let r_fb = apply_udp_blackhole_with(&no_dns, &journal, &tools, &mut fb_runner, 2000);
    assert!(r_fb.ok);
    assert!(r_fb.message.contains("完全阻断全部 UDP"));
    assert_eq!(fb_runner.calls.len(), 2);
    assert_eq!(fb_runner.calls[1].0[4], "sh");
    assert!(!fb_runner.calls[1].0[6].contains("--dport 53"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_anti_spoof_validation_rules_and_lifecycle() {
    let dir = make_temp_dir("spoof");
    let journal = dir.join("anti-spoof.json");
    let tools = tools_with_all();
    let mut runner = MockRunner::always(true, "");

    let (v4, v6) = parse_valid_ips(&[
        "192.168.1.100",
        "127.0.0.1",
        "2001:0db8::1",
        "::1",
        "invalid-ip",
        "10.0.0.2",
    ]);
    assert_eq!(v4, vec!["10.0.0.2", "192.168.1.100"]);
    assert_eq!(v6, vec!["2001:db8::1"]);

    let bad_veth = apply_anti_spoof_with(
        "bad;veth",
        &["192.168.1.10"],
        "runman",
        "vm1",
        &journal,
        &tools,
        &mut runner,
        1000,
    );
    assert!(!bad_veth.ok);
    assert!(bad_veth.message.contains("无效的网卡接口名"));

    let bad_ips = apply_anti_spoof_with(
        "veth123",
        &["not-an-ip", "127.0.0.1"],
        "runman",
        "vm1",
        &journal,
        &tools,
        &mut runner,
        1000,
    );
    assert!(!bad_ips.ok);
    assert!(bad_ips.message.contains("未提供已分配的有效 IPv4 / IPv6 列表"));

    // Apply with both v4 and v6
    let ok_res = apply_anti_spoof_with(
        "veth1a2b",
        &["198.51.100.10", "2001:db8::5"],
        "runman",
        "test-vm",
        &journal,
        &tools,
        &mut runner,
        5000,
    );
    assert!(ok_res.ok);
    assert!(ok_res.message.contains("已在接口 veth1a2b 启用源地址防伪造保护"));
    assert!(runner
        .calls
        .iter()
        .any(|(args, _)| args == &["sysctl", "-w", "net.ipv4.conf.veth1a2b.rp_filter=1"]));
    assert!(runner.calls.iter().any(|(args, _)| {
        args.first().map(String::as_str) == Some("/usr/sbin/nft")
            && args.contains(&"ip".to_string())
            && args.contains(&"198.51.100.10".to_string())
    }));

    // v4-only rule blocks ip6
    let v4_only_rules =
        build_anti_spoof_nft_rules("veth1a2b", &["198.51.100.10".to_string()], &[]);
    assert_eq!(v4_only_rules.len(), 2);
    assert_eq!(
        v4_only_rules[1],
        "add rule inet narwhal_antispoof forward iifname \"veth1a2b\" ip6 drop"
    );

    let st = get_anti_spoof_status_with("veth1a2b", &journal).expect("status");
    assert!(st.active);
    assert_eq!(st.v4_ips, vec!["198.51.100.10"]);
    assert_eq!(st.v6_ips, vec!["2001:db8::5"]);

    let st_c =
        get_anti_spoof_status_for_container_with("RUNMAN", "test-vm", "", &journal).expect("lookup");
    assert!(st_c.active);
    assert_eq!(st_c.veth, "veth1a2b");

    runner.calls.clear();
    let rel = release_anti_spoof_with("veth1a2b", "runman", "test-vm", &journal, &tools, &mut runner);
    assert!(rel.ok);
    assert!(rel.message.contains("已在接口 veth1a2b 解除"));
    assert!(runner
        .calls
        .iter()
        .any(|(args, _)| args == &["sysctl", "-w", "net.ipv4.conf.veth1a2b.rp_filter=2"]));
    assert!(runner
        .calls
        .iter()
        .any(|(args, _)| args == &["/usr/sbin/nft", "delete", "table", "inet", "narwhal_antispoof"]));

    let st_after = get_anti_spoof_status_with("veth1a2b", &journal).expect("status after");
    assert!(!st_after.active);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_journal_permissions_symlink_rejection_and_atomic_replace() {
    let dir = make_temp_dir("journal");
    let journal_path = dir.join("sub").join("test.json");

    assert!(QuarantineJournal::new(Some(Path::new("relative.json"))).is_err());

    let qj = QuarantineJournal::new(Some(&journal_path)).expect("abs path");
    let mut data = BTreeMap::new();
    data.insert("k1".to_string(), JsonVal::Num(12345.0));
    qj.write(&data).expect("write 1");

    // Overwrite existing file cleanly on all platforms
    data.insert("k2".to_string(), JsonVal::Bool(true));
    qj.write(&data).expect("write 2");
    let read_back = qj.read().expect("read");
    assert_eq!(read_back.get("k1").and_then(JsonVal::as_i64), Some(12345));
    assert_eq!(read_back.get("k2").and_then(JsonVal::as_bool), Some(true));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let mode = fs::metadata(&journal_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let link_path = dir.join("symlink.json");
        symlink(&journal_path, &link_path).unwrap();
        assert!(read_json_journal(&link_path).is_err());
        assert!(write_json_journal(&link_path, &data, ".t-", false).is_err());
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_quarantine_target_and_safe_evidence() {
    let vm_id = "11111111-2222-3333-4444-555555555555";
    let gen_id = "22222222-2222-4222-8222-222222222222";
    assert_eq!(
        quarantine_target("runman", "default", vm_id, gen_id).unwrap(),
        format!("[\"runman\",\"default\",\"{vm_id}\",\"{gen_id}\"]")
    );
    assert!(quarantine_target("docker", "", "cust", gen_id).is_err());
    assert!(quarantine_target("podman", "", "narwhal-monitor-server", gen_id).is_err());
    assert!(quarantine_target("incus", "", "x;evil", gen_id).is_err());
    assert!(quarantine_target("incus", "", "cust", "short").is_err());
    assert!(quarantine_target("runman", "other", vm_id, gen_id).is_err());
    assert!(quarantine_target("runman", "default", "cust", gen_id).is_err());
    assert!(quarantine_target("runman", "default", vm_id, "generation-1").is_err());

    let unsafe_ev = vec![JsonVal::parse(r#"{"source":"secret-code","argv":["--pass"]}"#).unwrap()];
    assert!(safe_evidence(&unsafe_ev).is_err());

    let mixed_ev = vec![JsonVal::parse(
        r#"{"kind":"identity_enumeration","confidence":"high","pid":20,"source":"strip-me","argv":["secret"],"features":{"http_calls":true,"unknown":1}}"#,
    )
    .unwrap()];
    let cleaned = safe_evidence(&mixed_ev).unwrap();
    assert_eq!(cleaned.len(), 1);
    let serialized = json_val_to_string(&JsonVal::Arr(cleaned), false);
    assert!(!serialized.contains("strip-me"));
    assert!(!serialized.contains("secret"));
    assert!(serialized.contains("\"kind\":\"identity_enumeration\""));
    assert!(serialized.contains("\"http_calls\":true"));
    assert!(!serialized.contains("\"unknown\""));
}

struct MockRunman {
    isolated: bool,
    interface_up: bool,
    running: bool,
    instance_id: String,
    deleted: bool,
}

impl RunmanTransport for MockRunman {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), String> {
        if method == "GET" && path == "/v1/inventory" {
            let items = if self.deleted {
                "[]".to_string()
            } else {
                format!(
                    "[{{\"id\":\"11111111-2222-3333-4444-555555555555\",\"instance_id\":\"{}\"}}]",
                    self.instance_id
                )
            };
            return Ok((200, format!("{{\"schema\":1,\"items\":{items}}}").into_bytes()));
        }
        if method == "POST" && path == "/v1/network-quarantine" {
            if self.deleted {
                return Ok((404, b"{}".to_vec()));
            }
            let req = JsonVal::parse(std::str::from_utf8(body.unwrap()).unwrap()).unwrap();
            match req.get_str("action") {
                Some("isolate") => {
                    self.isolated = true;
                    self.interface_up = false;
                }
                Some("release") => {
                    self.isolated = false;
                    self.interface_up = true;
                }
                Some("replacement") => {
                    self.instance_id = "33333333-3333-4333-8333-333333333333".to_string();
                }
                _ => {}
            }
            let resp = format!(
                "{{\"ok\":true,\"instance_id\":\"{}\",\"isolated\":{},\"interface_up\":{},\"running\":{}}}",
                self.instance_id, self.isolated, self.interface_up, self.running
            );
            return Ok((200, resp.into_bytes()));
        }
        Err("unexpected request".to_string())
    }
}

#[test]
fn test_runman_quarantine_release_deleted_and_replaced() {
    let dir = make_temp_dir("runman_q");
    let journal = QuarantineJournal::new(Some(&dir.join("q.json"))).unwrap();
    let vm = "11111111-2222-3333-4444-555555555555";
    let gen1 = "22222222-2222-4222-8222-222222222222";
    let key = quarantine_target("runman", "default", vm, gen1).unwrap();
    let evidence = vec![JsonVal::parse(r#"{"kind":"outbound_scan","pid":20}"#).unwrap()];

    let transport = MockRunman {
        isolated: false,
        interface_up: true,
        running: true,
        instance_id: gen1.to_string(),
        deleted: false,
    };
    let mut driver = RunmanIsolation::new(transport, vm, gen1);

    let res = quarantine_entry(&journal, &key, &mut driver, &evidence, 1000).unwrap();
    assert_eq!(res.get_str("status"), Some("isolated"));
    assert!(driver.transport.isolated);

    // Release normal
    let out = release_network_quarantine_with("runman", "default", vm, gen1, &journal, &mut driver, &key);
    assert!(out.ok);
    assert_eq!(
        out.message,
        "Network quarantine released; data preserved; fresh prohibited activity will be isolated again"
    );
    assert!(!driver.transport.isolated);
    assert!(journal.read().unwrap().is_empty());

    // Re-quarantine then simulate deletion -> release returns container_deleted_verified
    quarantine_entry(&journal, &key, &mut driver, &evidence, 2000).unwrap();
    driver.transport.deleted = true;
    let del_out = release_network_quarantine_with("runman", "default", vm, gen1, &journal, &mut driver, &key);
    assert!(del_out.ok);
    assert_eq!(
        del_out.message,
        "container_deleted_verified old_instance_absent=true old_journal_cleared=true"
    );
    assert!(journal.read().unwrap().is_empty());

    // Confirm replaced (new generation)
    driver.transport.deleted = false;
    driver.transport.isolated = false;
    driver.transport.interface_up = true;
    quarantine_entry(&journal, &key, &mut driver, &evidence, 3000).unwrap();
    let rep_out = confirm_replaced_network_quarantine_with(
        "runman",
        "default",
        vm,
        gen1,
        &journal,
        &mut driver,
        &key,
    );
    assert!(rep_out.ok);
    assert_eq!(
        rep_out.message,
        "replacement_verified current_instance_id=33333333-3333-4333-8333-333333333333 old_instance_absent=true old_journal_cleared=true"
    );
    assert!(journal.read().unwrap().is_empty());

    // Confirm replaced when deleted -> current_instance_id=none
    driver.transport.deleted = true;
    let rep_del = confirm_replaced_network_quarantine_with(
        "runman",
        "default",
        vm,
        gen1,
        &journal,
        &mut driver,
        &key,
    );
    assert!(rep_del.ok);
    assert_eq!(
        rep_del.message,
        "replacement_verified current_instance_id=none container_deleted=true old_instance_absent=true old_journal_cleared=true"
    );

    let _ = fs::remove_dir_all(&dir);
}

struct FakeIncusApi {
    profile: BTreeMap<String, JsonVal>,
    item: Option<JsonVal>,
    revision: u64,
    fail_update: bool,
}

impl FakeIncusApi {
    fn new(uuid: &str) -> Self {
        let profile = BTreeMap::from([(
            "eth0".to_string(),
            JsonVal::parse(r#"{"type":"nic","name":"eth0","network":"incusbr0"}"#).unwrap(),
        )]);
        let item = JsonVal::parse(&format!(
            r#"{{
                "config": {{
                    "volatile.uuid": "{uuid}",
                    "user.note": "preserved",
                    "volatile.eth0.hwaddr": "10:66:6a:00:00:11",
                    "volatile.eth0.name": "eth0"
                }},
                "devices": {{
                    "root": {{"type":"disk","path":"/","pool":"default"}},
                    "ssh": {{"type":"proxy","listen":"tcp:0.0.0.0:12345","connect":"tcp:127.0.0.1:22"}}
                }},
                "profiles": ["default"],
                "description": "customer data",
                "ephemeral": false
            }}"#
        ))
        .unwrap();
        Self {
            profile,
            item: Some(item),
            revision: 0,
            fail_update: false,
        }
    }
}

impl IncusTransport for FakeIncusApi {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&JsonVal>,
        etag: Option<&str>,
    ) -> Result<(JsonVal, Option<String>), String> {
        if path.starts_with("/1.0/instances?recursion=2") {
            return match &self.item {
                None => Ok((JsonVal::Arr(Vec::new()), None)),
                Some(item) => {
                    let cfg = item.get("config").cloned().unwrap_or(JsonVal::Null);
                    let row = JsonVal::Obj(BTreeMap::from([
                        ("name".to_string(), JsonVal::Str("customer".to_string())),
                        ("config".to_string(), cfg),
                    ]));
                    Ok((JsonVal::Arr(vec![row]), None))
                }
            };
        }
        let Some(ref cur) = self.item else {
            return Err("Incus API request failed: status 404".to_string());
        };
        if path.ends_with("/state") {
            let mut expanded = self.profile.clone();
            if let Some(devs) = cur.get("devices").and_then(JsonVal::as_obj) {
                for (k, v) in devs {
                    expanded.insert(k.clone(), v.clone());
                }
            }
            let mut nets = BTreeMap::new();
            let cfg = cur.get("config").and_then(JsonVal::as_obj);
            for (k, v) in expanded {
                if v.get_str("type") == Some("nic") {
                    let name = v
                        .get_str("name")
                        .or_else(|| {
                            cfg.and_then(|c| {
                                c.get(&format!("volatile.{k}.name")).and_then(JsonVal::as_str)
                            })
                        })
                        .unwrap_or("eth0")
                        .to_string();
                    let hw = v
                        .get_str("hwaddr")
                        .or_else(|| {
                            cfg.and_then(|c| {
                                c.get(&format!("volatile.{k}.hwaddr"))
                                    .and_then(JsonVal::as_str)
                            })
                        })
                        .unwrap_or("")
                        .to_string();
                    nets.insert(
                        name,
                        JsonVal::Obj(BTreeMap::from([
                            ("state".to_string(), JsonVal::Str("up".to_string())),
                            ("hwaddr".to_string(), JsonVal::Str(hw)),
                        ])),
                    );
                }
            }
            return Ok((
                JsonVal::Obj(BTreeMap::from([("network".to_string(), JsonVal::Obj(nets))])),
                None,
            ));
        }
        if method == "PUT" {
            if self.fail_update || etag != Some(self.revision.to_string().as_str()) {
                return Err("conditional update failed".to_string());
            }
            let before_devs = cur
                .get("devices")
                .and_then(JsonVal::as_obj)
                .cloned()
                .unwrap_or_default();
            let mut before = self.profile.clone();
            before.extend(before_devs);

            let mut next_item = body.unwrap().as_obj().cloned().unwrap();
            let after_devs = next_item
                .get("devices")
                .and_then(JsonVal::as_obj)
                .cloned()
                .unwrap_or_default();
            let mut after = self.profile.clone();
            after.extend(after_devs);

            let all_keys: BTreeSet<String> =
                before.keys().chain(after.keys()).cloned().collect();
            if let Some(JsonVal::Obj(ref mut cfg)) = next_item.get_mut("config") {
                for k in all_keys {
                    let b_ty = before.get(&k).and_then(|d| d.get_str("type"));
                    let a_ty = after.get(&k).and_then(|d| d.get_str("type"));
                    if b_ty != a_ty {
                        for f in ["hwaddr", "name", "host_name"] {
                            cfg.remove(&format!("volatile.{k}.{f}"));
                        }
                        if a_ty == Some("nic") {
                            let dev = &after[&k];
                            if dev.get_str("hwaddr").unwrap_or("").is_empty() {
                                cfg.insert(
                                    format!("volatile.{k}.hwaddr"),
                                    JsonVal::Str("10:66:6a:00:00:99".to_string()),
                                );
                            }
                            if dev.get_str("name").unwrap_or("").is_empty() {
                                cfg.insert(
                                    format!("volatile.{k}.name"),
                                    JsonVal::Str("eth0".to_string()),
                                );
                            }
                        }
                    }
                }
            }
            self.item = Some(JsonVal::Obj(next_item));
            self.revision += 1;
            return Ok((JsonVal::Obj(BTreeMap::new()), None));
        }
        let mut res = cur.as_obj().cloned().unwrap();
        let mut expanded = self.profile.clone();
        if let Some(devs) = res.get("devices").and_then(JsonVal::as_obj) {
            expanded.extend(devs.clone());
        }
        res.insert("expanded_devices".to_string(), JsonVal::Obj(expanded));
        Ok((JsonVal::Obj(res), Some(self.revision.to_string())))
    }
}

#[test]
fn test_incus_quarantine_release_and_volatile_mac_restore() {
    let dir = make_temp_dir("incus_q");
    let journal = QuarantineJournal::new(Some(&dir.join("q.json"))).unwrap();
    let uuid = "c7a35d5c-e17c-4e25-8479-123456789abc";
    let key = quarantine_target("incus", "default", "customer", uuid).unwrap();
    let evidence = vec![JsonVal::parse(r#"{"kind":"identity_enumeration","pid":20}"#).unwrap()];

    let api = FakeIncusApi::new(uuid);
    let original_item = api.item.clone().unwrap();
    let mut driver = IncusIsolation::new(api, "customer", uuid);

    let res = quarantine_entry(&journal, &key, &mut driver, &evidence, 1000).unwrap();
    assert_eq!(res.get_str("status"), Some("isolated"));
    let cur_devs = driver
        .api
        .item
        .as_ref()
        .unwrap()
        .get("devices")
        .unwrap();
    assert_eq!(cur_devs.get("eth0").and_then(|d| d.get_str("type")), Some("none"));
    assert_eq!(cur_devs.get("ssh").and_then(|d| d.get_str("type")), Some("none"));

    let out = release_network_quarantine_with("incus", "default", "customer", uuid, &journal, &mut driver, &key);
    assert!(out.ok);
    assert_eq!(driver.api.item.as_ref().unwrap(), &original_item);
    assert!(journal.read().unwrap().is_empty());

    // Deletion case
    quarantine_entry(&journal, &key, &mut driver, &evidence, 2000).unwrap();
    driver.api.item = None;
    let del_out = release_network_quarantine_with("incus", "default", "customer", uuid, &journal, &mut driver, &key);
    assert!(del_out.ok);
    assert!(del_out.message.contains("container_deleted_verified"));

    let _ = fs::remove_dir_all(&dir);
}

struct FakePodmanRunner {
    item: JsonVal,
    deleted: bool,
    corrupt_ip_on_connect: bool,
}

impl FakePodmanRunner {
    fn new(id: &str) -> Self {
        let item = JsonVal::parse(&format!(
            r#"{{
                "Id": "{id}",
                "Pod": "",
                "HostConfig": {{"NetworkMode": "bridge", "PidMode": "", "Privileged": false, "Devices": []}},
                "NetworkSettings": {{
                    "Networks": {{
                        "one": {{"IPAddress": "10.90.0.2", "Aliases": ["customer"]}},
                        "two": {{"GlobalIPv6Address": "fd00::2", "MacAddress": "02:00:00:00:00:02"}}
                    }}
                }},
                "State": {{"Pid": 123}}
            }}"#
        ))
        .unwrap();
        Self {
            item,
            deleted: false,
            corrupt_ip_on_connect: false,
        }
    }
}

impl CommandRunner for FakePodmanRunner {
    fn run(&mut self, args: &[String], _stdin: Option<&str>) -> (bool, String) {
        if self.deleted {
            return (false, "Error: no such container".to_string());
        }
        if args.get(1).map(String::as_str) == Some("inspect") {
            return (
                true,
                json_val_to_string(&JsonVal::Arr(vec![self.item.clone()]), false),
            );
        }
        if args.get(1).map(String::as_str) == Some("network") {
            let op = args[2].as_str();
            let net_name = args[args.len() - 2].clone();
            let JsonVal::Obj(ref mut root) = self.item else {
                return (false, "bad state".to_string());
            };
            let JsonVal::Obj(ref mut ns) = root.get_mut("NetworkSettings").unwrap() else {
                return (false, "bad ns".to_string());
            };
            let JsonVal::Obj(ref mut nets) = ns.get_mut("Networks").unwrap() else {
                return (false, "bad nets".to_string());
            };
            if op == "disconnect" {
                nets.remove(&net_name);
                return (true, String::new());
            } else if op == "connect" {
                let opts = &args[3..args.len() - 2];
                let mut restored = BTreeMap::new();
                let mut aliases = Vec::new();
                let mut i = 0;
                while i < opts.len() {
                    match opts[i].as_str() {
                        "--ip" => {
                            let ip = if self.corrupt_ip_on_connect {
                                "10.0.0.99".to_string()
                            } else {
                                opts[i + 1].clone()
                            };
                            restored.insert("IPAddress".to_string(), JsonVal::Str(ip));
                            i += 2;
                        }
                        "--ip6" => {
                            restored.insert(
                                "GlobalIPv6Address".to_string(),
                                JsonVal::Str(opts[i + 1].clone()),
                            );
                            i += 2;
                        }
                        "--mac-address" => {
                            restored.insert(
                                "MacAddress".to_string(),
                                JsonVal::Str(opts[i + 1].clone()),
                            );
                            i += 2;
                        }
                        "--alias" => {
                            aliases.push(JsonVal::Str(opts[i + 1].clone()));
                            i += 2;
                        }
                        _ => i += 1,
                    }
                }
                restored.insert("Aliases".to_string(), JsonVal::Arr(aliases));
                nets.insert(net_name, JsonVal::Obj(restored));
                return (true, String::new());
            }
        }
        (false, "unsupported".to_string())
    }
}

#[test]
fn test_podman_quarantine_release_and_rollback_on_mismatch() {
    let dir = make_temp_dir("podman_q");
    let journal = QuarantineJournal::new(Some(&dir.join("q.json"))).unwrap();
    let pod_id = "a".repeat(64);
    let key = quarantine_target("podman", "", "customer", &pod_id).unwrap();
    let evidence = vec![JsonVal::parse(r#"{"kind":"outbound_scan","pid":20}"#).unwrap()];

    let mut runner = FakePodmanRunner::new(&pod_id);
    {
        let mut driver = PodmanIsolation::new(&mut runner, "podman", "customer", &pod_id);
        quarantine_entry(&journal, &key, &mut driver, &evidence, 1000).unwrap();

        // Corrupt IP during connect -> release fails, rolls back connections, keeps journal!
        driver.runner = &mut *(driver.runner); // keep borrow clear
    }
    runner.corrupt_ip_on_connect = true;
    {
        let mut driver = PodmanIsolation::new(&mut runner, "podman", "customer", &pod_id);
        let fail_out = release_network_quarantine_with(
            "podman",
            "",
            "customer",
            &pod_id,
            &journal,
            &mut driver,
            &key,
        );
        assert!(!fail_out.ok);
        assert!(fail_out.message.contains("Network restore could not be verified"));
    }
    let nets_after_rollback = runner
        .item
        .get("NetworkSettings")
        .unwrap()
        .get("Networks")
        .unwrap()
        .as_obj()
        .unwrap();
    assert!(nets_after_rollback.is_empty());
    assert!(journal.read().unwrap().contains_key(&key));

    // Now release cleanly
    runner.corrupt_ip_on_connect = false;
    {
        let mut driver = PodmanIsolation::new(&mut runner, "podman", "customer", &pod_id);
        let ok_out = release_network_quarantine_with(
            "podman",
            "",
            "customer",
            &pod_id,
            &journal,
            &mut driver,
            &key,
        );
        assert!(ok_out.ok);
    }
    let nets_after_ok = runner
        .item
        .get("NetworkSettings")
        .unwrap()
        .get("Networks")
        .unwrap()
        .as_obj()
        .unwrap();
    assert_eq!(nets_after_ok.len(), 2);
    assert!(journal.read().unwrap().is_empty());

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn test_unix_incus_api_and_runman_isolation_over_unix_socket() {
    use std::os::unix::net::UnixListener;

    let dir = make_temp_dir("unix_sock");
    let incus_sock = dir.join("incus.sock");
    let listener = UnixListener::bind(&incus_sock).expect("bind unix socket");

    let handle = thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 2048];
        let n = conn.read(&mut buf).expect("read");
        let req = String::from_utf8_lossy(&buf[..n]);
        assert!(req.contains("GET /1.0/instances/cust?project=default HTTP/1.1"));

        let body = br#"{"type":"sync","metadata":{"config":{"volatile.uuid":"uuid-123456789012"}}}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"rev-1\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        conn.write_all(resp.as_bytes()).unwrap();
        conn.write_all(body).unwrap();
    });

    let mut api = UnixIncusApi::new("", incus_sock.to_string_lossy().into_owned());
    let (meta, etag) = api
        .request("GET", "/1.0/instances/cust", None, None)
        .expect("unix incus request");
    assert_eq!(etag.as_deref(), Some("\"rev-1\""));
    assert_eq!(
        meta.get("config").and_then(|c| c.get_str("volatile.uuid")),
        Some("uuid-123456789012")
    );
    handle.join().unwrap();

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_http_response_parser_headers_and_chunked() {
    let raw = b"HTTP/1.1 200 OK\r\nETag: \"abc-1\"\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
    let (status, headers, body) = parse_http_response_with_headers(raw).expect("parse http");
    assert_eq!(status, 200);
    assert_eq!(headers.get("etag").map(String::as_str), Some("\"abc-1\""));
    assert_eq!(body, b"{\"a\":1}");
}

#[test]
fn test_incus_safety_guards_refresh_and_confirm_replaced() {
    let dir = make_temp_dir("incus_extra");
    let journal = QuarantineJournal::new(Some(&dir.join("q.json"))).unwrap();
    let uuid = "c7a35d5c-e17c-4e25-8479-123456789abc";
    let key = quarantine_target("incus", "default", "customer", uuid).unwrap();
    let evidence = vec![JsonVal::parse(r#"{"kind":"identity_enumeration","pid":20}"#).unwrap()];

    // Unmanaged raw.lxc network must be rejected without PUT
    let mut raw_lxc_api = FakeIncusApi::new(uuid);
    if let Some(JsonVal::Obj(ref mut root)) = raw_lxc_api.item {
        if let Some(JsonVal::Obj(ref mut cfg)) = root.get_mut("config") {
            cfg.insert(
                "raw.lxc".to_string(),
                JsonVal::Str("lxc.net.0.type = phys".to_string()),
            );
        }
    }
    let mut raw_driver = IncusIsolation::new(raw_lxc_api, "customer", uuid);
    assert!(raw_driver.snapshot().is_err());

    // PCI passthrough device must be rejected
    let mut pci_api = FakeIncusApi::new(uuid);
    if let Some(JsonVal::Obj(ref mut root)) = pci_api.item {
        if let Some(JsonVal::Obj(ref mut devs)) = root.get_mut("devices") {
            devs.insert(
                "gpu".to_string(),
                JsonVal::Obj(BTreeMap::from([("type".to_string(), JsonVal::Str("pci".to_string()))])),
            );
        }
    }
    let mut pci_driver = IncusIsolation::new(pci_api, "customer", uuid);
    assert!(pci_driver.snapshot().is_err());

    // Operator modification blocks release & retains journal
    let mut op_driver = IncusIsolation::new(FakeIncusApi::new(uuid), "customer", uuid);
    quarantine_entry(&journal, &key, &mut op_driver, &evidence, 1000).unwrap();

    // Adding a new NIC while quarantined is automatically refreshed and masked
    if let Some(JsonVal::Obj(ref mut root)) = op_driver.api.item {
        if let Some(JsonVal::Obj(ref mut devs)) = root.get_mut("devices") {
            devs.insert(
                "eth1".to_string(),
                JsonVal::parse(r#"{"type":"nic","name":"eth1","network":"br1"}"#).unwrap(),
            );
        }
    }
    quarantine_entry(&journal, &key, &mut op_driver, &evidence, 1100).unwrap();
    assert_eq!(
        op_driver
            .api
            .item
            .as_ref()
            .unwrap()
            .get("devices")
            .unwrap()
            .get("eth1")
            .unwrap()
            .get_str("type"),
        Some("none")
    );

    // Operator overwrites quarantine mask -> release refused & journal preserved
    if let Some(JsonVal::Obj(ref mut root)) = op_driver.api.item {
        if let Some(JsonVal::Obj(ref mut devs)) = root.get_mut("devices") {
            devs.insert(
                "ssh".to_string(),
                JsonVal::parse(r#"{"type":"disk","path":"/new","pool":"default"}"#).unwrap(),
            );
        }
    }
    let rel_fail =
        release_network_quarantine_with("incus", "default", "customer", uuid, &journal, &mut op_driver, &key);
    assert!(!rel_fail.ok);
    assert!(journal.read().unwrap().contains_key(&key));

    // Replacement verification fails while old UUID exists, succeeds with new UUID
    let rep_fail = confirm_replaced_network_quarantine_with(
        "incus",
        "default",
        "customer",
        uuid,
        &journal,
        &mut op_driver,
        &key,
    );
    assert!(!rep_fail.ok);
    assert!(journal.read().unwrap().contains_key(&key));

    let new_uuid = "d8b46e6d-f28d-4f36-9580-abcdef012345";
    if let Some(JsonVal::Obj(ref mut root)) = op_driver.api.item {
        if let Some(JsonVal::Obj(ref mut cfg)) = root.get_mut("config") {
            cfg.insert("volatile.uuid".to_string(), JsonVal::Str(new_uuid.to_string()));
        }
    }
    let rep_ok = confirm_replaced_network_quarantine_with(
        "incus",
        "default",
        "customer",
        uuid,
        &journal,
        &mut op_driver,
        &key,
    );
    assert!(rep_ok.ok);
    assert_eq!(
        rep_ok.message,
        format!("replacement_verified current_instance_id={new_uuid} old_instance_absent=true old_journal_cleared=true")
    );
    assert!(journal.read().unwrap().is_empty());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_podman_shared_network_rejection_and_deleted_release() {
    let dir = make_temp_dir("podman_extra");
    let journal = QuarantineJournal::new(Some(&dir.join("q.json"))).unwrap();
    let pod_id = "b".repeat(64);
    let key = quarantine_target("podman", "", "customer", &pod_id).unwrap();
    let evidence = vec![JsonVal::parse(r#"{"kind":"outbound_scan","pid":20}"#).unwrap()];

    for mode in ["host", "container:other", "pasta", "slirp4netns"] {
        let mut r = FakePodmanRunner::new(&pod_id);
        if let JsonVal::Obj(ref mut root) = r.item {
            if let Some(JsonVal::Obj(ref mut hc)) = root.get_mut("HostConfig") {
                hc.insert("NetworkMode".to_string(), JsonVal::Str(mode.to_string()));
            }
        }
        let mut drv = PodmanIsolation::new(&mut r, "podman", "customer", &pod_id);
        assert!(drv.snapshot().is_err(), "mode {mode} must be rejected");
    }

    let mut runner = FakePodmanRunner::new(&pod_id);
    {
        let mut drv = PodmanIsolation::new(&mut runner, "podman", "customer", &pod_id);
        quarantine_entry(&journal, &key, &mut drv, &evidence, 1000).unwrap();
    }
    runner.deleted = true;
    {
        let mut drv = PodmanIsolation::new(&mut runner, "podman", "customer", &pod_id);
        let del_out = release_network_quarantine_with(
            "podman",
            "",
            "customer",
            &pod_id,
            &journal,
            &mut drv,
            &key,
        );
        assert!(del_out.ok);
        assert_eq!(
            del_out.message,
            "container_deleted_verified old_instance_absent=true old_journal_cleared=true"
        );
    }
    assert!(journal.read().unwrap().is_empty());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_journal_corrupt_and_capacity_limits_and_outcomes() {
    let dir = make_temp_dir("j_limits");
    let bad_json = dir.join("bad.json");
    fs::write(&bad_json, "{corrupt").unwrap();
    assert!(read_json_journal(&bad_json).is_err());

    let arr_json = dir.join("arr.json");
    fs::write(&arr_json, "[]").unwrap();
    assert!(read_json_journal(&arr_json).is_err());

    let mut big = BTreeMap::new();
    for i in 0..=MAX_JOURNAL_ENTRIES {
        big.insert(format!("k{i}"), JsonVal::Bool(true));
    }
    assert!(write_json_journal(&dir.join("big.json"), &big, ".b-", false).is_err());

    let ok_out = ActionOutcome::ok("done");
    assert_eq!(ok_out.clone().into_result(), Ok("done".to_string()));
    let err_out = ActionOutcome::err("nope");
    assert_eq!(Result::<String, String>::from(err_out), Err("nope".to_string()));

    let _ = fs::remove_dir_all(&dir);
}
