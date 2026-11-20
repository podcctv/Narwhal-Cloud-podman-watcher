use std::env;
use std::fs;
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use runtime_drivers::JsonVal;

use crate::*;

// ---------------------------------------------------------------------------
// 7. Runner trait & live host implementation
// ---------------------------------------------------------------------------

pub trait TcRunner {
    fn run_cmd(&mut self, args: &[&str], output_limit: usize) -> (i32, String);

    fn which(&mut self, binary: &str) -> Option<String> {
        let _ = binary;
        None
    }

    fn host_ifindex(&mut self, interface: &str) -> Result<u32, String> {
        let _ = interface;
        Err("host interface lookup unavailable".to_string())
    }

    fn netns_inode(&mut self, pid: u32) -> Result<u64, NetnsError> {
        let _ = pid;
        Err(NetnsError::Unavailable(
            "network namespace lookup unavailable".to_string(),
        ))
    }

    fn read_proc_stat(&mut self, pid: u32) -> Result<String, String> {
        let _ = pid;
        Err("proc stat unavailable".to_string())
    }

    fn read_text(&mut self, path: &Path) -> std::io::Result<String> {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ))
    }

    fn list_dir(&mut self, path: &Path) -> std::io::Result<Vec<String>> {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "directory not found",
        ))
    }

    fn read_link_basename(&mut self, path: &Path) -> std::io::Result<String> {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "symlink not found",
        ))
    }

    fn now_unix(&self) -> u64 {
        current_unix_ts()
    }
}

pub fn current_unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Default)]
pub struct LiveRunner;

fn read_bounded_pipe<R: std::io::Read>(mut reader: R, max_bytes: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut limited = reader.by_ref().take(max_bytes as u64);
    let _ = limited.read_to_end(&mut buf);
    buf
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    meta.is_file() && (meta.permissions().mode() & 0o111) != 0
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

impl TcRunner for LiveRunner {
    fn run_cmd(&mut self, args: &[&str], output_limit: usize) -> (i32, String) {
        if args.is_empty() {
            return (127, "command unavailable or timed out".to_string());
        }
        let Ok(mut child) = Command::new(args[0])
            .args(&args[1..])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        else {
            return (127, "command unavailable or timed out".to_string());
        };

        let cap = output_limit.saturating_add(4096);
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let stdout_handle = thread::spawn(move || {
            stdout_pipe
                .map(|r| read_bounded_pipe(r, cap))
                .unwrap_or_default()
        });
        let stderr_handle = thread::spawn(move || {
            stderr_pipe
                .map(|r| read_bounded_pipe(r, cap))
                .unwrap_or_default()
        });

        let deadline = Instant::now() + DEFAULT_CMD_TIMEOUT;
        let mut exit_code: Option<i32> = None;
        let mut timed_out = false;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_code = Some(status.code().unwrap_or(1));
                    break;
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
            }
        }

        let stdout_bytes = stdout_handle.join().unwrap_or_default();
        let stderr_bytes = stderr_handle.join().unwrap_or_default();
        if timed_out {
            return (127, "command unavailable or timed out".to_string());
        }
        let stdout_str = String::from_utf8_lossy(&stdout_bytes).trim().to_string();
        let selected = if !stdout_str.is_empty() {
            stdout_str
        } else {
            String::from_utf8_lossy(&stderr_bytes).trim().to_string()
        };
        (
            exit_code.unwrap_or(127),
            truncate_chars(&selected, output_limit),
        )
    }

    fn which(&mut self, binary: &str) -> Option<String> {
        if binary.is_empty() {
            return None;
        }
        if binary.contains('/') || binary.contains('\\') {
            let p = Path::new(binary);
            if is_executable_file(p) {
                let resolved = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
                return Some(resolved.to_string_lossy().into_owned());
            }
            return None;
        }
        if let Some(paths) = env::var_os("PATH") {
            for dir in env::split_paths(&paths) {
                let candidate = dir.join(binary);
                if is_executable_file(&candidate) {
                    let resolved =
                        fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
                    return Some(resolved.to_string_lossy().into_owned());
                }
            }
        }
        for fallback in ["/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"] {
            let candidate = Path::new(fallback).join(binary);
            if is_executable_file(&candidate) {
                let resolved = fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
                return Some(resolved.to_string_lossy().into_owned());
            }
        }
        None
    }

    fn host_ifindex(&mut self, interface: &str) -> Result<u32, String> {
        if !is_safe_sysfs_iface(interface) {
            return Err("invalid interface name".to_string());
        }
        let sysfs_path = Path::new("/sys/class/net").join(interface).join("ifindex");
        match fs::read_to_string(&sysfs_path) {
            Ok(raw) => {
                let idx = raw
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| "invalid sysfs ifindex".to_string())?;
                if idx > 0 {
                    return Ok(idx);
                }
                return Err("zero sysfs ifindex".to_string());
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // Fall back to ip -j link show only if sysfs tree itself is absent
                if Path::new("/sys/class/net").is_dir() {
                    return Err("interface not found".to_string());
                }
            }
            Err(_) => {}
        }
        let (code, output) = self.run_cmd(
            &["ip", "-j", "link", "show", "dev", interface],
            DEFAULT_OUTPUT_LIMIT,
        );
        if code == 0 {
            if let Ok(JsonVal::Arr(arr)) = JsonVal::parse(&output) {
                if let Some(idx) = arr
                    .first()
                    .and_then(|v| v.get_u64("ifindex"))
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|&v| v > 0)
                {
                    return Ok(idx);
                }
            }
        }
        Err("selected host interface no longer exists".to_string())
    }

    fn netns_inode(&mut self, pid: u32) -> Result<u64, NetnsError> {
        #[cfg(unix)]
        {
            let path = format!("/proc/{pid}/ns/net");
            match fs::metadata(&path) {
                Ok(meta) => Ok(meta.ino()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(NetnsError::NotFound),
                Err(err) => Err(NetnsError::Unavailable(err.to_string())),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            Err(NetnsError::Unavailable(
                "network namespaces require Unix".to_string(),
            ))
        }
    }

    fn read_proc_stat(&mut self, pid: u32) -> Result<String, String> {
        fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| e.to_string())
    }

    fn read_text(&mut self, path: &Path) -> std::io::Result<String> {
        fs::read_to_string(path)
    }

    fn list_dir(&mut self, path: &Path) -> std::io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(path)? {
            if let Ok(item) = entry {
                names.push(item.file_name().to_string_lossy().into_owned());
            }
        }
        Ok(names)
    }

    fn read_link_basename(&mut self, path: &Path) -> std::io::Result<String> {
        let target = fs::read_link(path)?;
        target
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no basename"))
    }
}
