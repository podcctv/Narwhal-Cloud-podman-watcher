#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead as _, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

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

fn decode_hex_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let raw = hex.as_bytes();
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let s = std::str::from_utf8(pair).ok()?;
        let byte = u8::from_str_radix(s, 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

pub fn decode_hex_ip_port(endpoint: &str, is_v6: bool) -> Option<(String, u16)> {
    let (ip_hex, port_hex) = endpoint.rsplit_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let bytes = decode_hex_bytes(ip_hex)?;

    if !is_v6 {
        if bytes.len() != 4 {
            return None;
        }
        let addr = Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0]);
        return Some((addr.to_string(), port));
    }

    if bytes.len() != 16 {
        return None;
    }
    let mut norm = [0u8; 16];
    for chunk in 0..4 {
        let base = chunk * 4;
        norm[base] = bytes[base + 3];
        norm[base + 1] = bytes[base + 2];
        norm[base + 2] = bytes[base + 1];
        norm[base + 3] = bytes[base];
    }
    if norm[..10] == [0u8; 10] && norm[10] == 0xff && norm[11] == 0xff {
        let mapped = Ipv4Addr::new(norm[12], norm[13], norm[14], norm[15]);
        return Some((mapped.to_string(), port));
    }
    Some((Ipv6Addr::from(norm).to_string(), port))
}

struct SocketEntry {
    proto: &'static str,
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    state_hex: String,
    inode: u64,
}

fn write_socket_entries(out: &mut String, entries: &[SocketEntry]) {
    out.push('[');
    for (idx, entry) in entries.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"proto\":\"{}\",\"local_ip\":\"{}\",\"local_port\":{},\"remote_ip\":\"{}\",\"remote_port\":{},\"state_hex\":\"{}\",\"inode\":{}}}",
            entry.proto,
            json_escape(&entry.local_ip),
            entry.local_port,
            json_escape(&entry.remote_ip),
            entry.remote_port,
            json_escape(&entry.state_hex),
            entry.inode,
        );
    }
    out.push(']');
}

fn write_u16_set(out: &mut String, ports: &BTreeSet<u16>) {
    out.push('[');
    for (idx, port) in ports.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let _ = write!(out, "{port}");
    }
    out.push(']');
}

pub fn collect_socket_tables(pid: u32) -> String {
    collect_socket_tables_from_root(Path::new("/proc"), pid)
}

pub fn collect_socket_tables_from_root(proc_root: &Path, pid: u32) -> String {
    if pid == 0 {
        return "{\"available\":false,\"read_files\":0,\"malformed\":false,\"tcp_established\":0,\"tcp_time_wait\":0,\"syn_sent_count\":0,\"syn_recv_count\":0,\"udp_sockets\":0,\"listening_ports\":[],\"udp_listening_ports\":[],\"tcp_entries\":[],\"udp_entries\":[]}".to_string();
    }

    let net_dir = proc_root.join(pid.to_string()).join("net");
    let tables = [
        ("tcp", false, "tcp"),
        ("tcp6", true, "tcp"),
        ("udp", false, "udp"),
        ("udp6", true, "udp"),
    ];

    let mut read_files: usize = 0;
    let mut malformed = false;
    let mut tcp_established: usize = 0;
    let mut tcp_time_wait: usize = 0;
    let mut syn_sent_count: usize = 0;
    let mut syn_recv_count: usize = 0;
    let mut udp_sockets: usize = 0;
    let mut listening_ports: BTreeSet<u16> = BTreeSet::new();
    let mut udp_listening_ports: BTreeSet<u16> = BTreeSet::new();
    let mut tcp_entries: Vec<SocketEntry> = Vec::new();
    let mut udp_entries: Vec<SocketEntry> = Vec::new();

    for (filename, is_v6, proto) in tables {
        let Ok(content) = fs::read_to_string(net_dir.join(filename)) else {
            continue;
        };
        read_files += 1;
        for line in content.lines().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 4 {
                malformed = true;
                continue;
            }
            let Some((local_ip, local_port)) = decode_hex_ip_port(parts[1], is_v6) else {
                malformed = true;
                continue;
            };
            let Some((remote_ip, remote_port)) = decode_hex_ip_port(parts[2], is_v6) else {
                malformed = true;
                continue;
            };
            let state_hex = parts[3].to_ascii_uppercase();
            let inode = parts
                .get(9)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            if proto == "tcp" {
                match state_hex.as_str() {
                    "01" => tcp_established += 1,
                    "02" => syn_sent_count += 1,
                    "03" => syn_recv_count += 1,
                    "06" => tcp_time_wait += 1,
                    "0A" if local_port > 0 => {
                        listening_ports.insert(local_port);
                    }
                    _ => {}
                }
                tcp_entries.push(SocketEntry {
                    proto: "tcp",
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    state_hex,
                    inode,
                });
            } else {
                udp_sockets += 1;
                if local_port > 0 && remote_port == 0 {
                    udp_listening_ports.insert(local_port);
                }
                udp_entries.push(SocketEntry {
                    proto: "udp",
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    state_hex,
                    inode,
                });
            }
        }
    }

    let available = read_files > 0;
    let mut out = String::with_capacity(512 + (tcp_entries.len() + udp_entries.len()) * 140);
    let _ = write!(
        out,
        "{{\"available\":{},\"read_files\":{},\"malformed\":{},\"tcp_established\":{},\"tcp_time_wait\":{},\"syn_sent_count\":{},\"syn_recv_count\":{},\"udp_sockets\":{},\"listening_ports\":",
        available,
        read_files,
        malformed,
        tcp_established,
        tcp_time_wait,
        syn_sent_count,
        syn_recv_count,
        udp_sockets,
    );
    write_u16_set(&mut out, &listening_ports);
    out.push_str(",\"udp_listening_ports\":");
    write_u16_set(&mut out, &udp_listening_ports);
    out.push_str(",\"tcp_entries\":");
    write_socket_entries(&mut out, &tcp_entries);
    out.push_str(",\"udp_entries\":");
    write_socket_entries(&mut out, &udp_entries);
    out.push('}');
    out
}

pub struct ConntrackEntry {
    pub proto: &'static str,
    pub state: String,
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
    pub reply_src: String,
    pub reply_dst: String,
    pub reply_sport: u16,
    pub reply_dport: u16,
    pub unreplied: bool,
    pub original_packets: u64,
    pub reply_packets: u64,
}

pub fn parse_conntrack_line(line: &str) -> Option<ConntrackEntry> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }

    let mut proto: Option<&'static str> = None;
    let mut proto_idx: Option<usize> = None;
    for (idx, tok) in tokens.iter().take(8).enumerate() {
        if tok.eq_ignore_ascii_case("tcp") {
            proto = Some("tcp");
            proto_idx = Some(idx);
            break;
        } else if tok.eq_ignore_ascii_case("udp") {
            proto = Some("udp");
            proto_idx = Some(idx);
            break;
        }
    }
    let proto = proto?;

    let mut state = String::new();
    if proto == "tcp" {
        if let Some(i) = proto_idx {
            if i + 3 < tokens.len()
                && tokens[i + 1].bytes().all(|b| b.is_ascii_digit())
                && tokens[i + 2].bytes().all(|b| b.is_ascii_digit())
                && !tokens[i + 3].contains('=')
                && !tokens[i + 3].starts_with('[')
            {
                state = tokens[i + 3].to_ascii_uppercase();
            }
        }
    }

    let mut src_vals: Vec<&str> = Vec::with_capacity(2);
    let mut dst_vals: Vec<&str> = Vec::with_capacity(2);
    let mut sport_vals: Vec<u16> = Vec::with_capacity(2);
    let mut dport_vals: Vec<u16> = Vec::with_capacity(2);
    let mut packet_vals: Vec<u64> = Vec::with_capacity(2);

    for tok in &tokens {
        if let Some(v) = tok.strip_prefix("src=") {
            if src_vals.len() < 2 {
                src_vals.push(v);
            }
        } else if let Some(v) = tok.strip_prefix("dst=") {
            if dst_vals.len() < 2 {
                dst_vals.push(v);
            }
        } else if let Some(v) = tok.strip_prefix("sport=") {
            if sport_vals.len() < 2 {
                sport_vals.push(v.parse::<u16>().unwrap_or(0));
            }
        } else if let Some(v) = tok.strip_prefix("dport=") {
            if dport_vals.len() < 2 {
                dport_vals.push(v.parse::<u16>().unwrap_or(0));
            }
        } else if let Some(v) = tok.strip_prefix("packets=") {
            if packet_vals.len() < 2 {
                packet_vals.push(v.parse::<u64>().unwrap_or(0));
            }
        }
    }

    if src_vals.len() < 2 || dst_vals.len() < 2 {
        return None;
    }

    Some(ConntrackEntry {
        proto,
        state,
        src: src_vals[0].to_string(),
        dst: dst_vals[0].to_string(),
        sport: *sport_vals.first().unwrap_or(&0),
        dport: *dport_vals.first().unwrap_or(&0),
        reply_src: src_vals[1].to_string(),
        reply_dst: dst_vals[1].to_string(),
        reply_sport: *sport_vals.get(1).unwrap_or(&0),
        reply_dport: *dport_vals.get(1).unwrap_or(&0),
        unreplied: line.contains("[UNREPLIED]"),
        original_packets: *packet_vals.first().unwrap_or(&0),
        reply_packets: *packet_vals.get(1).unwrap_or(&0),
    })
}

pub fn collect_conntrack(path: &str, max_lines: usize) -> String {
    let Ok(file) = fs::File::open(path) else {
        return "{\"available\":false,\"entries\":[]}".to_string();
    };
    let reader = BufReader::new(file);
    let mut entries: Vec<ConntrackEntry> = Vec::new();

    for line_res in reader.lines().take(max_lines) {
        let Ok(line) = line_res else {
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(entry) = parse_conntrack_line(trimmed) {
            entries.push(entry);
        }
    }

    let mut out = String::with_capacity(64 + entries.len() * 192);
    out.push_str("{\"available\":true,\"entries\":[");
    for (idx, e) in entries.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"proto\":\"{}\",\"state\":\"{}\",\"src\":\"{}\",\"dst\":\"{}\",\"sport\":{},\"dport\":{},\"reply_src\":\"{}\",\"reply_dst\":\"{}\",\"reply_sport\":{},\"reply_dport\":{},\"unreplied\":{},\"original_packets\":{},\"reply_packets\":{}}}",
            e.proto,
            json_escape(&e.state),
            json_escape(&e.src),
            json_escape(&e.dst),
            e.sport,
            e.dport,
            json_escape(&e.reply_src),
            json_escape(&e.reply_dst),
            e.reply_sport,
            e.reply_dport,
            e.unreplied,
            e.original_packets,
            e.reply_packets,
        );
    }
    out.push_str("]}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "narwhal_socket_sec_{}_{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn test_decode_hex_ip_port_ipv4() {
        // 127.0.0.1 in LE hex is 0100007F, port 8080 is 1F90
        let decoded = decode_hex_ip_port("0100007F:1F90", false).expect("ipv4");
        assert_eq!(decoded, ("127.0.0.1".to_string(), 8080));

        // 192.168.1.10 -> 0A01A8C0, port 443 -> 01BB
        let decoded2 = decode_hex_ip_port("0A01A8C0:01BB", false).expect("ipv4 2");
        assert_eq!(decoded2, ("192.168.1.10".to_string(), 443));
    }

    #[test]
    fn test_decode_hex_ip_port_ipv6_and_mapped() {
        // ::ffff:10.0.0.1 in 4x32-bit LE words:
        // word0=00000000, word1=00000000, word2=FFFF0000 (BE bytes 00 00 ff ff), word3=0100000A (BE bytes 0a 00 00 01)
        let decoded = decode_hex_ip_port("0000000000000000FFFF00000100000A:0050", true)
            .expect("ipv4-mapped ipv6");
        assert_eq!(decoded, ("10.0.0.1".to_string(), 80));

        // ::1 -> word3 = 01000000
        let loopback = decode_hex_ip_port("00000000000000000000000001000000:1F90", true)
            .expect("ipv6 loopback");
        assert_eq!(loopback, ("::1".to_string(), 8080));
    }

    #[test]
    fn test_collect_socket_tables_counts() {
        let root = make_temp_dir("tables");
        let net_dir = root.join("42").join("net");
        fs::create_dir_all(&net_dir).unwrap();

        let tcp_data = concat!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
            "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0 0 0\n",
            "   1: 0100007F:0050 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 1002 1 0 0 0\n",
            "   2: 0100007F:0050 0100007F:D432 06 00000000:00000000 00:00000000 00000000     0        0 1003 1 0 0 0\n",
            "   3: 0100007F:9999 0A000002:01BB 02 00000000:00000000 00:00000000 00000000     0        0 1004 1 0 0 0\n",
            "   4: 0100007F:01BB 0A000003:ABCD 03 00000000:00000000 00:00000000 00000000     0        0 1005 1 0 0 0\n",
        );
        fs::write(net_dir.join("tcp"), tcp_data).unwrap();
        fs::write(net_dir.join("tcp6"), "  sl local_address rem_address st\n").unwrap();
        fs::write(
            net_dir.join("udp"),
            "  sl local_address rem_address st tx rx tr tm retrnsmt uid timeout inode\n   0: 00000000:0035 00000000:0000 07 0:0 0:0 0 0 0 2001\n",
        )
        .unwrap();
        fs::write(net_dir.join("udp6"), "  sl local_address rem_address st\n").unwrap();

        let json = collect_socket_tables_from_root(&root, 42);
        assert!(json.contains("\"available\":true"));
        assert!(json.contains("\"read_files\":4"));
        assert!(json.contains("\"malformed\":false"));
        assert!(json.contains("\"tcp_established\":1"));
        assert!(json.contains("\"tcp_time_wait\":1"));
        assert!(json.contains("\"syn_sent_count\":1"));
        assert!(json.contains("\"syn_recv_count\":1"));
        assert!(json.contains("\"udp_sockets\":1"));
        assert!(json.contains("\"listening_ports\":[80]"));
        assert!(json.contains("\"udp_listening_ports\":[53]"));
        assert!(json.contains("\"inode\":1002"));
        assert!(json.contains("\"inode\":2001"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_collect_conntrack() {
        let dir = make_temp_dir("conntrack");
        let path = dir.join("nf_conntrack");
        let data = concat!(
            "ipv4     2 tcp      6 431999 ESTABLISHED src=203.0.113.5 dst=10.0.0.2 sport=51234 dport=443 packets=12 bytes=1024 src=10.0.0.2 dst=203.0.113.5 sport=443 dport=51234 packets=10 bytes=2048 [ASSURED] mark=0\n",
            "ipv4     2 udp      17 29 src=198.51.100.9 dst=10.0.0.2 sport=40000 dport=53 packets=1 bytes=64 [UNREPLIED] src=10.0.0.2 dst=198.51.100.9 sport=53 dport=40000 packets=0 bytes=0 mark=0\n",
        );
        fs::write(&path, data).unwrap();

        let json = collect_conntrack(path.to_str().unwrap(), 10);
        assert!(json.contains("\"available\":true"));
        assert!(json.contains("\"proto\":\"tcp\",\"state\":\"ESTABLISHED\",\"src\":\"203.0.113.5\",\"dst\":\"10.0.0.2\",\"sport\":51234,\"dport\":443"));
        assert!(json.contains("\"proto\":\"udp\",\"state\":\"\",\"src\":\"198.51.100.9\",\"dst\":\"10.0.0.2\",\"sport\":40000,\"dport\":53"));
        assert!(json.contains("\"unreplied\":true"));

        let _ = fs::remove_dir_all(&dir);
    }
}
