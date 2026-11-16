#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn is_global_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    if o[0] == 0
        || o[0] == 10
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (o[1] & 0xf0) == 16)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 224
    {
        return false;
    }
    true
}

pub fn is_allowed_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for (idx, label) in labels.iter().enumerate() {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return false;
        }
        if idx == labels.len() - 1 {
            if label.len() < 2 || !bytes.iter().all(|b| b.is_ascii_alphabetic()) {
                return false;
            }
        } else if !bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-') {
            return false;
        }
    }
    true
}

pub fn probe_tcp_target(target_id: &str, host: &str, port: u16, samples: usize) -> String {
    let sample_count = samples.clamp(1, 3);
    if !is_allowed_host(host) || port == 0 {
        return format!(
            "{{\"available\":true,\"target_id\":{},\"ip\":\"\",\"samples_ms\":[],\"error\":\"blocked_dns\"}}",
            json_escape(target_id)
        );
    }

    let addrs = match (host, port).to_socket_addrs() {
        Ok(iter) => iter.collect::<Vec<_>>(),
        Err(_) => {
            return format!(
                "{{\"available\":true,\"target_id\":{},\"ip\":\"\",\"samples_ms\":[],\"error\":\"dns_error\"}}",
                json_escape(target_id)
            );
        }
    };

    let global_v4 = addrs.into_iter().find_map(|sa| match sa {
        SocketAddr::V4(v4) if is_global_ipv4(*v4.ip()) => Some(*v4.ip()),
        _ => None,
    });
    let Some(ip) = global_v4 else {
        return format!(
            "{{\"available\":true,\"target_id\":{},\"ip\":\"\",\"samples_ms\":[],\"error\":\"blocked_dns\"}}",
            json_escape(target_id)
        );
    };

    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let timeout = Duration::from_millis(1500);
    let mut samples_json = String::from("[");
    let mut last_error = "";

    for attempt in 0..sample_count {
        if attempt > 0 {
            samples_json.push(',');
        }
        let started = Instant::now();
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_stream) => {
                let elapsed_ms = (started.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
                let _ = write!(samples_json, "{elapsed_ms:.2}");
            }
            Err(err) => {
                samples_json.push_str("null");
                last_error = match err.kind() {
                    ErrorKind::TimedOut => "timeout",
                    ErrorKind::ConnectionRefused => "refused",
                    _ => "network_error",
                };
            }
        }
        if attempt + 1 < sample_count {
            thread::sleep(Duration::from_millis(150));
        }
    }
    samples_json.push(']');

    format!(
        "{{\"available\":true,\"target_id\":{},\"ip\":{},\"samples_ms\":{},\"error\":{}}}",
        json_escape(target_id),
        json_escape(&ip.to_string()),
        samples_json,
        json_escape(last_error),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_is_global_ipv4_and_allowed_host() {
        assert!(is_global_ipv4("1.1.1.1".parse().unwrap()));
        assert!(is_global_ipv4("8.8.8.8".parse().unwrap()));
        assert!(!is_global_ipv4("127.0.0.1".parse().unwrap()));
        assert!(!is_global_ipv4("10.0.0.1".parse().unwrap()));
        assert!(!is_global_ipv4("100.64.0.1".parse().unwrap()));
        assert!(!is_global_ipv4("172.16.0.1".parse().unwrap()));
        assert!(!is_global_ipv4("192.168.1.1".parse().unwrap()));
        assert!(!is_global_ipv4("224.0.0.1".parse().unwrap()));
        assert!(!is_global_ipv4("198.51.100.1".parse().unwrap()));

        assert!(is_allowed_host("bj-cm-v4.ip.zstaticcdn.com"));
        assert!(is_allowed_host("example.com"));
        assert!(!is_allowed_host("127.0.0.1"));
        assert!(!is_allowed_host("-bad.example.com"));
        assert!(!is_allowed_host("localhost"));
    }

    #[test]
    fn test_probe_tcp_target_blocked_host_and_local_listener() {
        let blocked = probe_tcp_target("t1", "127.0.0.1", 80, 1);
        assert!(blocked.contains("\"error\":\"blocked_dns\""));

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
        let handle = thread::spawn(move || {
            let _ = listener.accept();
        });
        let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500));
        assert!(stream.is_ok());
        let _ = handle.join();
    }
}
