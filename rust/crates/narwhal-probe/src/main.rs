#![forbid(unsafe_code)]

use std::env;
use std::process;

const VERSION_JSON: &str = "{\"probe\":\"narwhal-probe\",\"version\":\"0.1.0\"}";

enum Command {
    Version,
    ProcSnapshot {
        init_pid: u32,
        scan_limit: usize,
        clock_ticks: f64,
    },
    SocketSec {
        pid: u32,
    },
    Conntrack {
        path: String,
        limit: usize,
    },
}

fn next_arg<'a>(args: &'a [String], idx: &mut usize, flag: &str) -> Result<&'a str, String> {
    *idx += 1;
    args.get(*idx)
        .map(|s| s.as_str())
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    let Some(sub) = args.get(1).map(|s| s.as_str()) else {
        return Err("missing subcommand".to_string());
    };

    match sub {
        "--version" | "-V" | "version" => Ok(Command::Version),
        "proc-snapshot" => {
            let mut init_pid: Option<u32> = None;
            let mut scan_limit: usize = 20_000;
            let mut clock_ticks: f64 = 100.0;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--init-pid" => {
                        let val = next_arg(args, &mut i, "--init-pid")?;
                        init_pid = Some(
                            val.parse::<u32>()
                                .map_err(|_| format!("invalid --init-pid: {val}"))?,
                        );
                    }
                    "--scan-limit" => {
                        let val = next_arg(args, &mut i, "--scan-limit")?;
                        scan_limit = val
                            .parse::<usize>()
                            .map_err(|_| format!("invalid --scan-limit: {val}"))?;
                    }
                    "--clock-ticks" => {
                        let val = next_arg(args, &mut i, "--clock-ticks")?;
                        clock_ticks = val
                            .parse::<f64>()
                            .map_err(|_| format!("invalid --clock-ticks: {val}"))?;
                    }
                    other => return Err(format!("unknown flag for proc-snapshot: {other}")),
                }
                i += 1;
            }
            let init_pid = init_pid.ok_or_else(|| "missing required --init-pid".to_string())?;
            Ok(Command::ProcSnapshot {
                init_pid,
                scan_limit,
                clock_ticks,
            })
        }
        "socket-sec" => {
            let mut pid: Option<u32> = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--pid" => {
                        let val = next_arg(args, &mut i, "--pid")?;
                        pid = Some(
                            val.parse::<u32>()
                                .map_err(|_| format!("invalid --pid: {val}"))?,
                        );
                    }
                    other => return Err(format!("unknown flag for socket-sec: {other}")),
                }
                i += 1;
            }
            let pid = pid.ok_or_else(|| "missing required --pid".to_string())?;
            Ok(Command::SocketSec { pid })
        }
        "conntrack" => {
            let mut path = "/proc/net/nf_conntrack".to_string();
            let mut limit: usize = 50_000;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--path" => {
                        path = next_arg(args, &mut i, "--path")?.to_string();
                    }
                    "--limit" => {
                        let val = next_arg(args, &mut i, "--limit")?;
                        limit = val
                            .parse::<usize>()
                            .map_err(|_| format!("invalid --limit: {val}"))?;
                    }
                    other => return Err(format!("unknown flag for conntrack: {other}")),
                }
                i += 1;
            }
            Ok(Command::Conntrack { path, limit })
        }
        other => Err(format!("unknown subcommand: {other}")),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match parse_args(&args) {
        Ok(Command::Version) => {
            println!("{VERSION_JSON}");
        }
        Ok(Command::ProcSnapshot {
            init_pid,
            scan_limit,
            clock_ticks,
        }) => {
            println!(
                "{}",
                proc_probe::collect_proc_snapshot(init_pid, scan_limit, clock_ticks)
            );
        }
        Ok(Command::SocketSec { pid }) => {
            println!("{}", socket_sec::collect_socket_tables(pid));
        }
        Ok(Command::Conntrack { path, limit }) => {
            println!("{}", socket_sec::collect_conntrack(&path, limit));
        }
        Err(err) => {
            eprintln!("narwhal-probe: {err}");
            process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn test_parse_version() {
        assert!(matches!(
            parse_args(&s(&["narwhal-probe", "--version"])),
            Ok(Command::Version)
        ));
    }

    #[test]
    fn test_parse_proc_snapshot() {
        let cmd = parse_args(&s(&[
            "narwhal-probe",
            "proc-snapshot",
            "--init-pid",
            "1234",
            "--scan-limit",
            "15000",
            "--clock-ticks",
            "100",
        ]))
        .expect("proc-snapshot");
        match cmd {
            Command::ProcSnapshot {
                init_pid,
                scan_limit,
                clock_ticks,
            } => {
                assert_eq!(init_pid, 1234);
                assert_eq!(scan_limit, 15000);
                assert!((clock_ticks - 100.0).abs() < 1e-6);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn test_parse_socket_sec_and_conntrack() {
        let sock = parse_args(&s(&["narwhal-probe", "socket-sec", "--pid", "99"]))
            .expect("socket-sec");
        assert!(matches!(sock, Command::SocketSec { pid: 99 }));

        let ct = parse_args(&s(&["narwhal-probe", "conntrack", "--limit", "5000"]))
            .expect("conntrack");
        match ct {
            Command::Conntrack { path, limit } => {
                assert_eq!(path, "/proc/net/nf_conntrack");
                assert_eq!(limit, 5000);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn test_parse_errors() {
        assert!(parse_args(&s(&["narwhal-probe"])).is_err());
        assert!(parse_args(&s(&["narwhal-probe", "proc-snapshot"])).is_err());
        assert!(parse_args(&s(&["narwhal-probe", "socket-sec"])).is_err());
        assert!(parse_args(&s(&["narwhal-probe", "unknown"])).is_err());
    }
}
