#![forbid(unsafe_code)]

//! Pure-Rust 4D socket abuse evaluation, suspicious process detection,
//! and command-line secret redaction.
//!
//! Mirrors the detection and redaction contracts of:
//! - `client/socket_collector.py` (`_evaluate_socket_abuse`, `_build_socket_investigation`)
//! - `client/proc_scanner.py` (`_redact_process_command`)
//! - `client/agent.py` (`collect_suspicious_processes`, `_SOCKS_PROCESS_NAMES`)

use std::collections::BTreeSet;
use std::fmt::Write as _;

const PROXY_BINARIES: &[&str] = &[
    "xray",
    "v2ray",
    "sing-box",
    "clash",
    "mihomo",
    "gost",
    "3proxy",
    "microsocks",
    "sockd",
    "danted",
    "srelay",
    "hev-socks5-server",
    "hysteria",
    "tuic",
    "trojan",
    "trojan-go",
    "ss-server",
    "ssserver",
    "naiveproxy",
    "brook",
];

const EXACT_MINER_BINARIES: &[&str] = &[
    "xmrig",
    "kinsing",
    "kdevtmpfsi",
    "watchbog",
    "cryptonight",
    "minerd",
    "pwnrig",
    "cpuminer",
    "nbminer",
    "t-rex",
    "lolminer",
    "gminer",
    "teamredminer",
    "ethminer",
    "phoenixminer",
    "nanominer",
];

const MINER_CMD_PATTERNS: &[&str] = &[
    "stratum+tcp",
    "stratum+ssl",
    "stratum2+tcp",
    "teamtnt",
];

const REVERSE_SHELL_PATTERNS: &[&str] = &[
    "/dev/tcp/",
    "nc -e",
    "ncat -e",
    "socat exec:",
    "mkfifo /tmp",
];

const HIGH_RISK_PORTS_STRICT: &[u16] = &[23, 25, 445, 465, 587, 1433, 3389, 6379, 6667];
const HIGH_RISK_PORTS_AUTH: &[u16] = &[22, 3306, 5432];

const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "api-key",
    "apikey",
    "authorization",
    "auth",
    "psk",
    "pass",
];

const QUERY_SECRET_KEYS: &[&str] = &[
    "auth",
    "key",
    "secret",
    "token",
    "password",
    "pass",
    "psk",
];

fn round_1(val: f64) -> f64 {
    if !val.is_finite() {
        return 0.0;
    }
    (val * 10.0).round() / 10.0
}

fn round_3(val: f64) -> f64 {
    if !val.is_finite() {
        return 0.0;
    }
    (val * 1000.0).round() / 1000.0
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn posix_basename(token: &str) -> String {
    let trimmed = token.trim_matches(|c| c == '"' || c == '\'');
    let base = trimmed.rsplit('/').next().unwrap_or(trimmed);
    base.to_ascii_lowercase()
}

fn first_argv_token(command: &str) -> String {
    let trimmed = command.trim_start();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut chars = trimmed.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return String::new(),
    };
    if first == '"' || first == '\'' {
        let mut tok = String::new();
        for c in chars {
            if c == first {
                break;
            }
            tok.push(c);
        }
        tok
    } else {
        let mut tok = String::new();
        tok.push(first);
        for c in chars {
            if c.is_whitespace() {
                break;
            }
            tok.push(c);
        }
        tok
    }
}

fn is_proxy_binary(name: &str) -> bool {
    let lower = posix_basename(name);
    PROXY_BINARIES.iter().any(|&p| p == lower)
}

// ============================================================================
// 1. 4D Socket Abuse Evaluation
// ============================================================================

/// Per-port outbound statistics for sensitive port checks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SensitivePortStat {
    pub port: u16,
    pub service: String,
    pub connections: u64,
    pub unique_ips: u64,
    pub syn_sent: u64,
}

/// Input metrics for 4-dimension socket & proxy abuse evaluation.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SocketAbuseInput {
    pub evaluated_at: u64,
    pub conn_count: u64,
    pub cm_total: u64,
    pub cm_valid: bool,
    pub has_tcp_states: bool,
    pub tcp_established: u64,
    pub tcp_time_wait: u64,
    pub tcp_syn_sent: u64,
    pub tcp_syn_recv: u64,
    pub tcp_close_wait: u64,
    pub tcp_fin_wait: u64,
    pub udp_sockets: u64,
    pub incoming_established: u64,
    pub outbound_established: u64,
    pub inbound_unique_ips: u64,
    pub inbound_established_unique_ips: u64,
    pub inbound_syn_recv_unique_ips: u64,
    pub outbound_unique_ips: u64,
    pub outbound_unique_ports: u64,
    pub outbound_syn_sent_unique_ips: u64,
    pub suspicious_outbound_connections: u64,
    pub sensitive_outbound_ports: Vec<SensitivePortStat>,
    pub socks_detected: bool,
    pub socks_auth_mode: String,
    pub hy2_detected: bool,
    pub proxy_processes: Vec<String>,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_pps: f64,
    pub tx_pps: f64,
}

/// Triggered abuse category from the 4D socket evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseCategory {
    pub code: String,
    pub title: String,
    pub severity: String,
    pub value: u64,
    pub threshold: u64,
    pub reason: String,
}

/// Assessment for one of the 4 evaluation dimensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DimensionAssessment {
    pub key: String,
    pub risk: String,
    pub summary: String,
}

/// Output of `evaluate_socket_abuse`.
#[derive(Debug, Clone, PartialEq)]
pub struct SocketAbuseVerdict {
    pub schema: u8,
    pub evaluated_at: u64,
    pub valid_evidence: bool,
    pub suspected: bool,
    pub verdict: String,
    pub verdict_label: String,
    pub severity: String,
    pub confidence: f64,
    pub symmetry_ratio: f64,
    pub proxy_like: bool,
    pub established_ratio: f64,
    pub time_wait_ratio: f64,
    pub syn_sent_ratio: f64,
    pub syn_recv_ratio: f64,
    pub total_sockets: u64,
    pub avg_tx_packet_size: f64,
    pub matched_proxy_processes: Vec<String>,
    pub categories: Vec<AbuseCategory>,
    pub dimensions: Vec<DimensionAssessment>,
}

impl SocketAbuseVerdict {
    /// Serialize the verdict to a compact JSON object string (std-only).
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(1024);
        let _ = write!(
            out,
            "{{\"schema\":{},\"evaluated_at\":{},\"valid_evidence\":{},\"suspected\":{},\
             \"verdict\":\"{}\",\"verdict_label\":\"{}\",\"severity\":\"{}\",\
             \"confidence\":{:.3},\"symmetry_ratio\":{:.3},\"proxy_like\":{},\
             \"established_ratio\":{:.3},\"time_wait_ratio\":{:.3},\
             \"syn_sent_ratio\":{:.3},\"syn_recv_ratio\":{:.3},\
             \"total_sockets\":{},\"avg_tx_packet_size\":{:.1},\"matched_proxy_processes\":[",
            self.schema,
            self.evaluated_at,
            self.valid_evidence,
            self.suspected,
            json_escape(&self.verdict),
            json_escape(&self.verdict_label),
            json_escape(&self.severity),
            self.confidence,
            self.symmetry_ratio,
            self.proxy_like,
            self.established_ratio,
            self.time_wait_ratio,
            self.syn_sent_ratio,
            self.syn_recv_ratio,
            self.total_sockets,
            self.avg_tx_packet_size,
        );
        for (i, proc_name) in self.matched_proxy_processes.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(out, "\"{}\"", json_escape(proc_name));
        }
        out.push_str("],\"categories\":[");
        for (i, cat) in self.categories.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"code\":\"{}\",\"title\":\"{}\",\"severity\":\"{}\",\"value\":{},\"threshold\":{},\"reason\":\"{}\"}}",
                json_escape(&cat.code),
                json_escape(&cat.title),
                json_escape(&cat.severity),
                cat.value,
                cat.threshold,
                json_escape(&cat.reason),
            );
        }
        out.push_str("],\"dimensions\":[");
        for (i, dim) in self.dimensions.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"key\":\"{}\",\"risk\":\"{}\",\"summary\":\"{}\"}}",
                json_escape(&dim.key),
                json_escape(&dim.risk),
                json_escape(&dim.summary),
            );
        }
        out.push_str("]}");
        out
    }
}

/// Evaluate 4-dimension socket & proxy abuse evidence (observation-only).
pub fn evaluate_socket_abuse(input: &SocketAbuseInput) -> SocketAbuseVerdict {
    let tcp_established = input
        .tcp_established
        .max(input.incoming_established.saturating_add(input.outbound_established));
    let state_sum = tcp_established
        .saturating_add(input.tcp_time_wait)
        .saturating_add(input.tcp_syn_sent)
        .saturating_add(input.tcp_syn_recv)
        .saturating_add(input.tcp_close_wait)
        .saturating_add(input.tcp_fin_wait)
        .saturating_add(input.udp_sockets);
    let total_sockets = input.conn_count.max(input.cm_total).max(state_sum);

    let denom_u64 = total_sockets
        .max(
            tcp_established
                .saturating_add(input.tcp_time_wait)
                .saturating_add(input.tcp_syn_sent)
                .saturating_add(input.tcp_syn_recv)
                .saturating_add(input.udp_sockets),
        )
        .max(1);
    let denom = denom_u64 as f64;

    let established_ratio = round_3(tcp_established as f64 / denom);
    let time_wait_ratio = round_3(input.tcp_time_wait as f64 / denom);
    let syn_sent_ratio = round_3(input.tcp_syn_sent as f64 / denom);
    let syn_recv_ratio = round_3(input.tcp_syn_recv as f64 / denom);

    let pair_max = input
        .incoming_established
        .max(input.outbound_established)
        .max(1) as f64;
    let symmetry_ratio = if input.incoming_established > 0 && input.outbound_established > 0 {
        round_3(input.incoming_established.min(input.outbound_established) as f64 / pair_max)
    } else {
        0.0
    };

    let mut matched_set = BTreeSet::new();
    for raw_proc in &input.proxy_processes {
        let tok = first_argv_token(raw_proc);
        let base = if tok.is_empty() {
            posix_basename(raw_proc)
        } else {
            posix_basename(&tok)
        };
        if is_proxy_binary(&base) {
            matched_set.insert(base);
        }
    }
    let matched_proxy_processes: Vec<String> = matched_set.into_iter().collect();

    let proxy_like = input.socks_detected
        || !matched_proxy_processes.is_empty()
            && input.incoming_established >= 10
            && input.outbound_established >= 10
            && symmetry_ratio >= 0.6
        || (input.incoming_established >= 10
            && input.outbound_established >= 10
            && symmetry_ratio >= 0.6);

    let avg_tx_packet_size =
        if input.tx_pps > 0.0 && input.tx_pps.is_finite() && input.tx_bps.is_finite() {
            round_1((input.tx_bps / input.tx_pps).max(0.0))
        } else {
            0.0
        };

    let valid_evidence = input.cm_valid
        || input.has_tcp_states
        || input.cm_total > 0
        || input.inbound_established_unique_ips > 0
        || !input.sensitive_outbound_ports.is_empty()
        || input.socks_detected
        || !matched_proxy_processes.is_empty();

    let mut high_risk_ports_hit: Vec<String> = Vec::new();
    for item in &input.sensitive_outbound_ports {
        let svc = if item.service.is_empty() {
            item.port.to_string()
        } else {
            item.service.clone()
        };
        if HIGH_RISK_PORTS_STRICT.contains(&item.port)
            && (item.connections >= 3 || item.unique_ips >= 3)
        {
            high_risk_ports_hit.push(format!(
                "{}/{} ({} conns, {} IPs)",
                item.port, svc, item.connections, item.unique_ips
            ));
        } else if HIGH_RISK_PORTS_AUTH.contains(&item.port)
            && (item.unique_ips >= 5 || item.syn_sent >= 5)
        {
            high_risk_ports_hit.push(format!(
                "{}/{} ({} conns, {} IPs, SYN_SENT {})",
                item.port, svc, item.connections, item.unique_ips, item.syn_sent
            ));
        }
    }

    let mut categories: Vec<AbuseCategory> = Vec::new();
    let auth_mode = if input.socks_auth_mode.is_empty() {
        "none"
    } else {
        input.socks_auth_mode.as_str()
    };
    let weak_or_no_auth = auth_mode == "no_auth" || auth_mode == "weak_password";

    if valid_evidence {
        // Category 1: Outbound port scan / brute-force
        if (input.tcp_syn_sent >= 20
            && (input.outbound_syn_sent_unique_ips >= 8 || input.outbound_unique_ips >= 15))
            || !high_risk_ports_hit.is_empty()
            || (input.suspicious_outbound_connections >= 5
                && (input.has_tcp_states
                    || input.cm_valid
                    || !input.sensitive_outbound_ports.is_empty()))
        {
            let mut reasons = Vec::new();
            if input.tcp_syn_sent >= 20 {
                reasons.push(format!(
                    "SYN_SENT={} targeting {} IPs",
                    input.tcp_syn_sent,
                    input
                        .outbound_syn_sent_unique_ips
                        .max(input.outbound_unique_ips)
                ));
            }
            if !high_risk_ports_hit.is_empty() {
                reasons.push(format!(
                    "high-risk ports: {}",
                    high_risk_ports_hit
                        .iter()
                        .take(4)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            } else if input.suspicious_outbound_connections >= 5 {
                reasons.push(format!(
                    "suspicious outbound connections={}",
                    input.suspicious_outbound_connections
                ));
            }
            categories.push(AbuseCategory {
                code: "outbound_scan_bruteforce".to_string(),
                title: "Outbound Port Scan / Brute-force".to_string(),
                severity: "critical".to_string(),
                value: input
                    .tcp_syn_sent
                    .max(input.suspicious_outbound_connections)
                    .max(high_risk_ports_hit.len() as u64),
                threshold: if input.tcp_syn_sent >= 20 { 20 } else { 5 },
                reason: reasons.join("; "),
            });
        }

        // Category 2: Shared proxy / SOCKS multi-IP abuse
        let proxy_signal = input.socks_detected || !matched_proxy_processes.is_empty();
        if (input.socks_detected
            && (input.inbound_established_unique_ips >= 6
                || (weak_or_no_auth && input.incoming_established >= 10)))
            || (input.inbound_established_unique_ips >= 10
                && (input.incoming_established >= 50
                    || input.outbound_established >= 50
                    || input.outbound_unique_ips >= 35))
            || (!matched_proxy_processes.is_empty()
                && proxy_like
                && input.inbound_established_unique_ips >= 6)
        {
            let sev = if input.inbound_established_unique_ips >= 15
                || (input.socks_detected && weak_or_no_auth)
            {
                "critical"
            } else {
                "warning"
            };
            let mut reasons = Vec::new();
            if input.socks_detected {
                reasons.push(format!("SOCKS5 detected (auth={})", auth_mode));
            }
            if !matched_proxy_processes.is_empty() {
                reasons.push(format!(
                    "proxy binaries=[{}]",
                    matched_proxy_processes.join(",")
                ));
            }
            reasons.push(format!(
                "inbound_established_ips={}, incoming={}, outbound={}, outbound_ips={}, symmetry={:.2}",
                input.inbound_established_unique_ips,
                input.incoming_established,
                input.outbound_established,
                input.outbound_unique_ips,
                symmetry_ratio
            ));
            categories.push(AbuseCategory {
                code: "shared_proxy_socks_abuse".to_string(),
                title: "Shared Proxy / SOCKS Multi-IP Abuse".to_string(),
                severity: sev.to_string(),
                value: input
                    .inbound_established_unique_ips
                    .max(input.incoming_established),
                threshold: if proxy_signal { 6 } else { 10 },
                reason: reasons.join("; "),
            });
        }

        // Category 3: High outbound fanout / P2P / crawler abuse
        if input.outbound_unique_ips >= 120
            && (input.udp_sockets >= 80
                || input.outbound_unique_ports >= 30
                || input.outbound_unique_ips >= 300)
        {
            categories.push(AbuseCategory {
                code: "p2p_or_outbound_fanout_abuse".to_string(),
                title: "High Outbound Fanout / P2P".to_string(),
                severity: "warning".to_string(),
                value: input.outbound_unique_ips,
                threshold: 120,
                reason: format!(
                    "outbound_ips={}, outbound_ports={}, outbound_established={}, udp={}",
                    input.outbound_unique_ips,
                    input.outbound_unique_ports,
                    input.outbound_established,
                    input.udp_sockets
                ),
            });
        }

        // Category 4: High socket count + high small-packet flood
        if total_sockets >= 400
            && input.tx_pps >= 1500.0
            && avg_tx_packet_size > 0.0
            && avg_tx_packet_size <= 160.0
        {
            categories.push(AbuseCategory {
                code: "high_socket_packet_flood".to_string(),
                title: "High Socket Count & Small-Packet Flood".to_string(),
                severity: "critical".to_string(),
                value: input.tx_pps.round() as u64,
                threshold: 1500,
                reason: format!(
                    "total_sockets={}, tx_pps={:.0}, avg_tx_pkt={:.1}B",
                    total_sockets, input.tx_pps, avg_tx_packet_size
                ),
            });
        }
    }

    // Build 4 dimension assessments
    let (dim1_risk, dim1_summary) = if input.tcp_syn_sent >= 20 {
        (
            "high",
            format!(
                "SYN_SENT={} ({} target IPs), active outbound scan/bruteforce",
                input.tcp_syn_sent,
                input
                    .outbound_syn_sent_unique_ips
                    .max(input.outbound_unique_ips)
            ),
        )
    } else if total_sockets >= 300 && time_wait_ratio >= 0.50 {
        (
            "low",
            format!(
                "TIME_WAIT ratio {:.0}% ({}/{}), ESTABLISHED {}",
                time_wait_ratio * 100.0,
                input.tcp_time_wait,
                total_sockets,
                tcp_established
            ),
        )
    } else if input.tcp_syn_recv >= 30 && input.tcp_syn_recv > tcp_established {
        (
            "low",
            format!(
                "Inbound SYN_RECV {} from {} IPs (passive external scan)",
                input.tcp_syn_recv, input.inbound_syn_recv_unique_ips
            ),
        )
    } else if tcp_established >= 400 {
        (
            "medium",
            format!(
                "High ESTABLISHED={} (in={}, out={}), TIME_WAIT={}, UDP={}",
                tcp_established,
                input.incoming_established,
                input.outbound_established,
                input.tcp_time_wait,
                input.udp_sockets
            ),
        )
    } else {
        (
            "low",
            format!(
                "total={} (ESTABLISHED {} [{:.0}%], TIME_WAIT {} [{:.0}%], SYN_SENT {}, SYN_RECV {}, UDP {})",
                total_sockets,
                tcp_established,
                established_ratio * 100.0,
                input.tcp_time_wait,
                time_wait_ratio * 100.0,
                input.tcp_syn_sent,
                input.tcp_syn_recv,
                input.udp_sockets
            ),
        )
    };

    let (dim2_risk, dim2_summary) = if input.socks_detected
        && (input.inbound_established_unique_ips >= 6 || weak_or_no_auth)
    {
        (
            "high",
            format!(
                "SOCKS5 (auth={}) with {} inbound public IPs ({} active)",
                auth_mode, input.inbound_established_unique_ips, input.incoming_established
            ),
        )
    } else if input.inbound_established_unique_ips >= 10 {
        let r = if input.incoming_established >= 50 || input.outbound_established >= 50 {
            "high"
        } else {
            "medium"
        };
        (
            r,
            format!(
                "{} inbound established IPs ({} active, {} SYN_RECV IPs)",
                input.inbound_established_unique_ips,
                input.incoming_established,
                input.inbound_syn_recv_unique_ips
            ),
        )
    } else {
        (
            "low",
            format!(
                "{} inbound established IPs ({} active, {} SYN_RECV IPs)",
                input.inbound_established_unique_ips,
                input.incoming_established,
                input.inbound_syn_recv_unique_ips
            ),
        )
    };

    let (dim3_risk, dim3_summary) = if !high_risk_ports_hit.is_empty()
        || (input.suspicious_outbound_connections >= 5 && valid_evidence)
    {
        (
            "high",
            format!(
                "Sensitive outbound hits ({} conns), outbound_ips={}, proxy_procs={}",
                input.suspicious_outbound_connections,
                input.outbound_unique_ips,
                matched_proxy_processes.len()
            ),
        )
    } else if input.outbound_unique_ips >= 120 {
        let r = if input.udp_sockets >= 100 || input.outbound_unique_ports >= 60 {
            "high"
        } else {
            "medium"
        };
        (
            r,
            format!(
                "High outbound fanout: {} IPs / {} ports, established={}",
                input.outbound_unique_ips, input.outbound_unique_ports, input.outbound_established
            ),
        )
    } else {
        (
            "low",
            format!(
                "outbound_established={}, outbound_ips={}, outbound_ports={}, proxy_procs={}",
                input.outbound_established,
                input.outbound_unique_ips,
                input.outbound_unique_ports,
                matched_proxy_processes.len()
            ),
        )
    };

    let (dim4_risk, dim4_summary) =
        if input.tx_pps >= 1500.0 && avg_tx_packet_size > 0.0 && avg_tx_packet_size <= 160.0 {
            (
                "high",
                format!(
                    "tx_pps={:.0}, avg_tx_pkt={:.1}B (small-packet flood profile)",
                    input.tx_pps, avg_tx_packet_size
                ),
            )
        } else {
            (
                "low",
                format!(
                    "tx_pps={:.0}, rx_pps={:.0}, avg_tx_pkt={:.1}B",
                    input.tx_pps, input.rx_pps, avg_tx_packet_size
                ),
            )
        };

    let dimensions = vec![
        DimensionAssessment {
            key: "state_breakdown".to_string(),
            risk: dim1_risk.to_string(),
            summary: dim1_summary,
        },
        DimensionAssessment {
            key: "inbound_fanout".to_string(),
            risk: dim2_risk.to_string(),
            summary: dim2_summary,
        },
        DimensionAssessment {
            key: "outbound_profile".to_string(),
            risk: dim3_risk.to_string(),
            summary: dim3_summary,
        },
        DimensionAssessment {
            key: "traffic_profile".to_string(),
            risk: dim4_risk.to_string(),
            summary: dim4_summary,
        },
    ];

    // Confidence score in [0.0, 1.0]
    let mut conf: f64 = 0.0;
    if valid_evidence {
        for cat in &categories {
            match cat.code.as_str() {
                "outbound_scan_bruteforce" => conf += 0.35,
                "shared_proxy_socks_abuse" => conf += 0.35,
                "p2p_or_outbound_fanout_abuse" => conf += 0.25,
                "high_socket_packet_flood" => conf += 0.35,
                _ => conf += 0.20,
            }
        }
        if input.socks_detected {
            conf += 0.15;
        }
        if !matched_proxy_processes.is_empty() {
            conf += 0.10;
        }
        if proxy_like && symmetry_ratio >= 0.6 {
            conf += 0.10;
        }
        if input.inbound_established_unique_ips >= 15 || (input.socks_detected && weak_or_no_auth) {
            conf += 0.15;
        }
        if input.hy2_detected && !categories.is_empty() {
            conf += 0.05;
        }
    }
    let confidence = round_3(conf.clamp(0.0, 1.0));

    let suspected = !categories.is_empty();
    let (verdict, verdict_label, severity) = if suspected {
        let sev = if categories.iter().any(|c| c.severity == "critical") {
            "critical"
        } else {
            "warning"
        };
        let codes: Vec<&str> = categories.iter().map(|c| c.code.as_str()).collect();
        (
            "suspected_abuse".to_string(),
            format!("Suspected Abuse ({})", codes.join(", ")),
            sev.to_string(),
        )
    } else if total_sockets >= 400 {
        (
            "benign_high_sockets".to_string(),
            "Benign High Sockets (TIME_WAIT / Single-Client)".to_string(),
            "info".to_string(),
        )
    } else {
        (
            "normal".to_string(),
            "Normal Traffic".to_string(),
            "info".to_string(),
        )
    };

    SocketAbuseVerdict {
        schema: 1,
        evaluated_at: input.evaluated_at,
        valid_evidence,
        suspected,
        verdict,
        verdict_label,
        severity,
        confidence,
        symmetry_ratio,
        proxy_like,
        established_ratio,
        time_wait_ratio,
        syn_sent_ratio,
        syn_recv_ratio,
        total_sockets,
        avg_tx_packet_size,
        matched_proxy_processes,
        categories,
        dimensions,
    }
}

// ============================================================================
// 2. Suspicious Process Detection & Command-Line Secret Redaction
// ============================================================================

/// Process entry supplied to `detect_suspicious_processes`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub cpu_percent: f64,
    pub rss_bytes: u64,
    pub process: String,
    pub command: String,
}

/// Finding emitted for a detected miner, proxy, or reverse-shell process.
#[derive(Debug, Clone, PartialEq)]
pub struct SuspiciousProcFinding {
    pub pid: u32,
    pub cpu_percent: f64,
    pub process: String,
    pub category: String,
    pub pattern: String,
    pub severity: String,
    pub redacted_command: String,
}

impl SuspiciousProcFinding {
    /// Serialize the finding to a compact JSON object string (std-only).
    pub fn to_json(&self) -> String {
        format!(
            "{{\"pid\":{},\"cpu_percent\":{:.2},\"process\":\"{}\",\"category\":\"{}\",\"pattern\":\"{}\",\"severity\":\"{}\",\"redacted_command\":\"{}\"}}",
            self.pid,
            self.cpu_percent,
            json_escape(&self.process),
            json_escape(&self.category),
            json_escape(&self.pattern),
            json_escape(&self.severity),
            json_escape(&self.redacted_command),
        )
    }
}

/// Detect crypto-miners, reverse shells, and proxy binaries in a process list,
/// returning findings with command-line secrets redacted.
pub fn detect_suspicious_processes(procs: &[ProcInfo]) -> Vec<SuspiciousProcFinding> {
    let mut findings = Vec::new();
    for proc_info in procs {
        let proc_base = posix_basename(&proc_info.process);
        let argv0 = posix_basename(&first_argv_token(&proc_info.command));
        let cmd_lower = proc_info.command.to_ascii_lowercase();

        let mut matched: Option<(&str, String, &str)> = None;

        // 1. Exact miner binary match (process name or argv[0])
        for &miner in EXACT_MINER_BINARIES {
            if proc_base == miner || argv0 == miner {
                matched = Some(("miner", miner.to_string(), "critical"));
                break;
            }
        }

        // 2. Miner command-line patterns (e.g. stratum+tcp)
        if matched.is_none() {
            for &pat in MINER_CMD_PATTERNS {
                if cmd_lower.contains(pat) {
                    matched = Some(("miner", pat.to_string(), "critical"));
                    break;
                }
            }
        }

        // 3. Reverse shell patterns
        if matched.is_none() {
            for &pat in REVERSE_SHELL_PATTERNS {
                if cmd_lower.contains(pat) {
                    matched = Some(("reverse_shell", pat.to_string(), "critical"));
                    break;
                }
            }
        }

        // 4. Proxy binary match (process name or argv[0])
        if matched.is_none() {
            for &proxy in PROXY_BINARIES {
                if proc_base == proxy || argv0 == proxy {
                    matched = Some(("proxy", proxy.to_string(), "warning"));
                    break;
                }
            }
        }

        if let Some((category, pattern, severity)) = matched {
            let raw_cmd = if proc_info.command.is_empty() {
                proc_info.process.as_str()
            } else {
                proc_info.command.as_str()
            };
            let display_proc = if proc_base.is_empty() {
                argv0
            } else {
                proc_base
            };
            findings.push(SuspiciousProcFinding {
                pid: proc_info.pid,
                cpu_percent: proc_info.cpu_percent,
                process: display_proc,
                category: category.to_string(),
                pattern,
                severity: severity.to_string(),
                redacted_command: redact_process_command(raw_cmd),
            });
            if findings.len() >= 200 {
                break;
            }
        }
    }
    findings
}

/// Redact inline credentials, tokens, passwords, and URL userinfo from a command string.
pub fn redact_process_command(command: &str) -> String {
    if command.is_empty() {
        return String::new();
    }
    let step1 = redact_key_value_secrets(command);
    let step2 = redact_short_password_flags(&step1);
    let step3 = redact_url_userinfo(&step2);
    let step4 = redact_url_query_secrets(&step3);
    step4.chars().take(500).collect()
}

fn is_word_boundary_before(s: &str, idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    match s[..idx].chars().next_back() {
        Some(c) => !(c.is_ascii_alphanumeric() || c == '_'),
        None => true,
    }
}

fn consume_secret_value(s: &str, start: usize, stop_at_amp: bool) -> usize {
    let bytes = s.as_bytes();
    if start >= bytes.len() {
        return start;
    }
    let quote = bytes[start];
    if quote == b'"' || quote == b'\'' {
        let mut i = start + 1;
        while i < bytes.len() {
            if bytes[i] == quote {
                return i + 1;
            }
            i += 1;
        }
        return bytes.len();
    }
    let mut i = start;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !(stop_at_amp && bytes[i] == b'&') {
        i += 1;
    }
    i
}

fn redact_key_value_secrets(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut out = String::with_capacity(input.len());
    let mut pos = 0;

    while pos < input.len() {
        let mut matched_key_len = 0;
        if is_word_boundary_before(input, pos) {
            for &key in SECRET_KEYS {
                if lower[pos..].starts_with(key) {
                    let after_key = pos + key.len();
                    if after_key < input.len() {
                        let rest = &input[after_key..];
                        let mut sep_len = 0;
                        let mut has_eq_or_colon = false;
                        let mut has_ws = false;
                        for b in rest.bytes() {
                            if b == b'=' || b == b':' {
                                has_eq_or_colon = true;
                                sep_len += 1;
                                break;
                            } else if b.is_ascii_whitespace() {
                                has_ws = true;
                                sep_len += 1;
                            } else {
                                break;
                            }
                        }
                        if has_eq_or_colon {
                            // Consume optional whitespace after '=' or ':'
                            while after_key + sep_len < input.len()
                                && input.as_bytes()[after_key + sep_len].is_ascii_whitespace()
                            {
                                sep_len += 1;
                            }
                            if after_key + sep_len < input.len() {
                                matched_key_len = key.len() + sep_len;
                            }
                        } else if has_ws && after_key + sep_len < input.len() {
                            matched_key_len = key.len() + sep_len;
                        }
                    }
                    if matched_key_len > 0 {
                        break;
                    }
                }
            }
        }

        if matched_key_len > 0 {
            let val_start = pos + matched_key_len;
            let is_url_query_param =
                pos > 0 && matches!(input.as_bytes()[pos - 1], b'?' | b'&');
            let val_end = consume_secret_value(input, val_start, is_url_query_param);
            out.push_str(&input[pos..val_start]);
            out.push_str("[REDACTED]");
            pos = val_end;
        } else if let Some(ch) = input[pos..].chars().next() {
            out.push(ch);
            pos += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn contains_microsocks(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    let mut start = 0;
    while let Some(idx) = lower[start..].find("microsocks") {
        let abs = start + idx;
        let before_ok = is_word_boundary_before(&lower, abs);
        let after = abs + "microsocks".len();
        let after_ok = after >= lower.len()
            || !lower.as_bytes()[after].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        start = abs + 1;
    }
    false
}

fn redact_short_password_flags(input: &str) -> String {
    let has_microsocks = contains_microsocks(input);
    let mut out = String::with_capacity(input.len());
    let mut pos = 0;

    while pos < input.len() {
        let at_tok_start = pos == 0 || input.as_bytes()[pos - 1].is_ascii_whitespace();
        let mut matched_flag_end = None;

        if at_tok_start && input.as_bytes()[pos] == b'-' && pos + 2 <= input.len() {
            let flag_char = input.as_bytes()[pos + 1];
            let is_target_flag =
                flag_char == b'p' || (has_microsocks && (flag_char == b'P' || flag_char == b'u'));
            if is_target_flag {
                let after_flag = pos + 2;
                if after_flag < input.len() {
                    let next_b = input.as_bytes()[after_flag];
                    if next_b == b'=' || next_b.is_ascii_whitespace() {
                        let mut val_start = after_flag + 1;
                        while val_start < input.len()
                            && input.as_bytes()[val_start].is_ascii_whitespace()
                        {
                            val_start += 1;
                        }
                        if val_start < input.len() && input.as_bytes()[val_start] != b'-' {
                            matched_flag_end = Some((after_flag, val_start));
                        }
                    }
                }
            }
        }

        if let Some((after_flag, val_start)) = matched_flag_end {
            let val_end = consume_secret_value(input, val_start, false);
            out.push_str(&input[pos..after_flag]);
            out.push_str(" [REDACTED]");
            pos = val_end;
        } else if let Some(ch) = input[pos..].chars().next() {
            out.push(ch);
            pos += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn redact_url_userinfo(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut pos = 0;

    while let Some(rel_scheme) = input[pos..].find("://") {
        let scheme_end = pos + rel_scheme + 3;
        out.push_str(&input[pos..scheme_end]);
        pos = scheme_end;

        // Look ahead within the same whitespace-delimited URL token for user:pass@
        let tok_end = input[pos..]
            .find(|c: char| c.is_whitespace())
            .map(|i| pos + i)
            .unwrap_or(input.len());
        let tok = &input[pos..tok_end];
        if let Some(at_idx) = tok.find('@') {
            let auth_part = &tok[..at_idx];
            if let Some(colon_idx) = auth_part.find(':') {
                if colon_idx > 0 && !auth_part[..colon_idx].contains('/') {
                    out.push_str(&auth_part[..=colon_idx]);
                    out.push_str("[REDACTED]@");
                    pos += at_idx + 1;
                }
            }
        }
    }
    out.push_str(&input[pos..]);
    out
}

fn redact_url_query_secrets(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut out = String::with_capacity(input.len());
    let mut pos = 0;

    while pos < input.len() {
        let b = input.as_bytes()[pos];
        if b == b'?' || b == b'&' {
            let mut matched_len = 0;
            for &key in QUERY_SECRET_KEYS {
                let after = pos + 1;
                if lower[after..].starts_with(key)
                    && after + key.len() < input.len()
                    && input.as_bytes()[after + key.len()] == b'='
                {
                    matched_len = 1 + key.len() + 1;
                    break;
                }
            }
            if matched_len > 0 {
                let val_start = pos + matched_len;
                let mut val_end = val_start;
                while val_end < input.len() {
                    let vb = input.as_bytes()[val_end];
                    if vb == b'&' || vb.is_ascii_whitespace() {
                        break;
                    }
                    val_end += 1;
                }
                out.push_str(&input[pos..val_start]);
                out.push_str("[REDACTED]");
                pos = val_end;
                continue;
            }
        }
        if let Some(ch) = input[pos..].chars().next() {
            out.push(ch);
            pos += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_traffic_is_normal_with_zero_confidence() {
        let input = SocketAbuseInput {
            evaluated_at: 1_700_000_000,
            conn_count: 24,
            cm_total: 24,
            cm_valid: true,
            has_tcp_states: true,
            tcp_established: 18,
            tcp_time_wait: 4,
            tcp_syn_sent: 1,
            tcp_syn_recv: 1,
            udp_sockets: 2,
            incoming_established: 12,
            outbound_established: 6,
            inbound_unique_ips: 3,
            inbound_established_unique_ips: 2,
            outbound_unique_ips: 4,
            outbound_unique_ports: 2,
            rx_bps: 120_000.0,
            tx_bps: 240_000.0,
            rx_pps: 120.0,
            tx_pps: 200.0,
            ..Default::default()
        };

        let verdict = evaluate_socket_abuse(&input);
        assert!(!verdict.suspected);
        assert_eq!(verdict.verdict, "normal");
        assert_eq!(verdict.severity, "info");
        assert_eq!(verdict.confidence, 0.0);
        assert!(verdict.categories.is_empty());
        assert_eq!(verdict.dimensions.len(), 4);
        assert_eq!(verdict.symmetry_ratio, 0.5);

        let json = verdict.to_json();
        assert!(json.contains("\"verdict\":\"normal\""));
        assert!(json.contains("\"suspected\":false"));
        assert!(json.contains("\"confidence\":0.000"));
    }

    #[test]
    fn benign_high_sockets_time_wait_does_not_trigger_abuse() {
        let input = SocketAbuseInput {
            conn_count: 520,
            cm_total: 520,
            cm_valid: true,
            has_tcp_states: true,
            tcp_established: 80,
            tcp_time_wait: 420,
            tcp_syn_sent: 2,
            tcp_syn_recv: 4,
            incoming_established: 40,
            outbound_established: 40,
            inbound_established_unique_ips: 2,
            outbound_unique_ips: 15,
            outbound_unique_ports: 2,
            ..Default::default()
        };

        let verdict = evaluate_socket_abuse(&input);
        assert!(!verdict.suspected);
        assert_eq!(verdict.verdict, "benign_high_sockets");
        assert_eq!(verdict.severity, "info");
        assert!(verdict.time_wait_ratio > 0.75);
    }

    #[test]
    fn symmetric_proxy_abuse_triggers_shared_proxy_verdict_and_json() {
        let input = SocketAbuseInput {
            evaluated_at: 1_700_000_123,
            conn_count: 260,
            cm_total: 260,
            cm_valid: true,
            has_tcp_states: true,
            tcp_established: 220,
            tcp_time_wait: 30,
            incoming_established: 110,
            outbound_established: 105,
            inbound_unique_ips: 25,
            inbound_established_unique_ips: 18,
            outbound_unique_ips: 64,
            outbound_unique_ports: 12,
            socks_detected: true,
            socks_auth_mode: "no_auth".to_string(),
            proxy_processes: vec!["/usr/local/bin/xray -config /etc/xray/config.json".to_string()],
            rx_bps: 2_000_000.0,
            tx_bps: 2_100_000.0,
            rx_pps: 1800.0,
            tx_pps: 1850.0,
            ..Default::default()
        };

        let verdict = evaluate_socket_abuse(&input);
        assert!(verdict.suspected);
        assert_eq!(verdict.verdict, "suspected_abuse");
        assert_eq!(verdict.severity, "critical");
        assert!(verdict.proxy_like);
        assert!(verdict.symmetry_ratio > 0.9);
        assert!(verdict.confidence >= 0.8);
        assert_eq!(verdict.matched_proxy_processes, vec!["xray".to_string()]);
        assert!(verdict
            .categories
            .iter()
            .any(|c| c.code == "shared_proxy_socks_abuse"));

        let json = verdict.to_json();
        assert!(json.contains("\"suspected\":true"));
        assert!(json.contains("\"shared_proxy_socks_abuse\""));
        assert!(json.contains("\"matched_proxy_processes\":[\"xray\"]"));
    }

    #[test]
    fn detects_xmrig_miner_and_proxy_binaries_without_script_false_positives() {
        let procs = vec![
            ProcInfo {
                pid: 101,
                ppid: 1,
                cpu_percent: 195.5,
                rss_bytes: 256 * 1024 * 1024,
                process: "xmrig".to_string(),
                command: "/tmp/xmrig -o stratum+tcp://pool.minexmr.com:4444 -u 44AFFq -p secretpass"
                    .to_string(),
            },
            ProcInfo {
                pid: 102,
                ppid: 1,
                cpu_percent: 12.0,
                rss_bytes: 32 * 1024 * 1024,
                process: "sing-box".to_string(),
                command: "/usr/bin/sing-box run -c /etc/sing-box/config.json --token=my_secret_tok"
                    .to_string(),
            },
            ProcInfo {
                pid: 103,
                ppid: 1,
                cpu_percent: 0.1,
                rss_bytes: 2 * 1024 * 1024,
                process: "sh".to_string(),
                command: "sh -c echo checking for xmrig in logs".to_string(),
            },
            ProcInfo {
                pid: 104,
                ppid: 1,
                cpu_percent: 5.0,
                rss_bytes: 16 * 1024 * 1024,
                process: "nginx".to_string(),
                command: "nginx: master process /usr/sbin/nginx -g daemon off;".to_string(),
            },
        ];

        let findings = detect_suspicious_processes(&procs);
        assert_eq!(findings.len(), 2);

        assert_eq!(findings[0].pid, 101);
        assert_eq!(findings[0].category, "miner");
        assert_eq!(findings[0].pattern, "xmrig");
        assert_eq!(findings[0].severity, "critical");
        assert!(!findings[0].redacted_command.contains("secretpass"));
        assert!(findings[0].redacted_command.contains("-p [REDACTED]"));

        assert_eq!(findings[1].pid, 102);
        assert_eq!(findings[1].category, "proxy");
        assert_eq!(findings[1].pattern, "sing-box");
        assert_eq!(findings[1].severity, "warning");
        assert!(!findings[1].redacted_command.contains("my_secret_tok"));
        assert!(findings[1].redacted_command.contains("--token=[REDACTED]"));
    }

    #[test]
    fn secret_redaction_handles_tokens_passwords_flags_and_urls() {
        let cmd1 = "gost -L socks5://admin:supersecret@127.0.0.1:1080 --token=tok_abc123 password=hunter2 -p myflagpass";
        let red1 = redact_process_command(cmd1);
        assert!(!red1.contains("supersecret"));
        assert!(!red1.contains("tok_abc123"));
        assert!(!red1.contains("hunter2"));
        assert!(!red1.contains("myflagpass"));
        assert!(red1.contains("socks5://admin:[REDACTED]@127.0.0.1:1080"));
        assert!(red1.contains("--token=[REDACTED]"));
        assert!(red1.contains("password=[REDACTED]"));
        assert!(red1.contains("-p [REDACTED]"));

        let cmd2 = "microsocks -i 0.0.0.0 -p 1080 -u alice -P s3cr3t";
        let red2 = redact_process_command(cmd2);
        assert!(!red2.contains("s3cr3t"));
        assert!(!red2.contains("alice"));
        assert!(red2.contains("-u [REDACTED]"));
        assert!(red2.contains("-P [REDACTED]"));

        let cmd3 = "curl https://example.com/api?token=xyz987&page=1";
        let red3 = redact_process_command(cmd3);
        assert_eq!(red3, "curl https://example.com/api?token=[REDACTED]&page=1");
    }
}
