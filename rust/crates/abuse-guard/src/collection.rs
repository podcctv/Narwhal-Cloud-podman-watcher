use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use proc_probe::parse_proc_stat;
use transport::sha256_hex;

use crate::detection::{
    bandwidth_monetization_tool_for_name, detect_bandwidth_monetization_markers, public_ip,
    source_evidence, ProcessRecord, SocketRecord,
};

pub const PROCESS_SCRIPT: &str = r#"
command -v base64 >/dev/null 2>&1 || exit 2
printf '@@NW_ABUSE_V1@@\n'
visited=0; emitted=0
for d in /proc/[0-9]*; do
    visited=$((visited+1)); [ "$visited" -le 512 ] || break
    [ "$emitted" -lt 64 ] || break
    p=${d##*/}; [ "$p" -ge 1 ] 2>/dev/null || continue
    [ -r "$d/stat" ] && [ -r "$d/cmdline" ] || continue
    comm=$(cat "$d/comm" 2>/dev/null)
    case "$comm" in python*|node|nmap|masscan|zmap|rustscan|hydra|medusa|ncrack|patator|traffmonetizer*|tmclient|bitping*|antgain|Proxybase*|proxybase*|mysterium|myst|honeygain|earnapp|pawns*|iproyal|packetstream|psclient|peer2profit|p2pclient|repocket|proxyrack|grass|gaganode|titan-edge|castarsdk) ;; *) continue;; esac
    raw=$(cat "$d/stat" 2>/dev/null); rest=${raw##*) }
    ticks=$(printf '%s\n' "$rest" | awk '{print $20}')
    state=$(printf '%s\n' "$rest" | awk '{print $1}')
    [ "$state" != Z ] || continue
    exe=$(readlink "$d/exe" 2>/dev/null | base64 | tr -d '\n')
    cwd=$(readlink "$d/cwd" 2>/dev/null | base64 | tr -d '\n')
    argv=$(head -c 8192 "$d/cmdline" 2>/dev/null | base64 | tr -d '\n')
    printf '%s\t%s\t%s\t%s\t%s\n' "$p" "$ticks" "$exe" "$cwd" "$argv"
    emitted=$((emitted+1))
done
printf '@@NW_END@@:%s:%s\n' "$visited" "$emitted"
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedHostProcess {
    pub host_pid: u32,
    pub pid: u32,
    pub process: String,
}

fn decode_base64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn decode_base64_strict(input: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() % 4 != 0 {
        return Err("invalid base64 length".to_string());
    }
    let pad = if bytes.ends_with(b"==") {
        2
    } else if bytes.ends_with(b"=") {
        1
    } else {
        0
    };
    let est_len = (bytes.len() / 4) * 3 - pad;
    if est_len > maximum {
        return Err("bounded process field exceeded".to_string());
    }

    let mut out = Vec::with_capacity(est_len);
    let chunks = bytes.len() / 4;
    for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
        let is_last = idx + 1 == chunks;
        let a = decode_base64_val(chunk[0]).ok_or_else(|| "invalid base64 char".to_string())?;
        let b = decode_base64_val(chunk[1]).ok_or_else(|| "invalid base64 char".to_string())?;

        if is_last && chunk[2] == b'=' && chunk[3] == b'=' {
            if (b & 0x0f) != 0 {
                return Err("non-zero base64 padding bits".to_string());
            }
            out.push((a << 2) | (b >> 4));
        } else if is_last && chunk[3] == b'=' {
            let c = decode_base64_val(chunk[2]).ok_or_else(|| "invalid base64 char".to_string())?;
            if (c & 0x03) != 0 {
                return Err("non-zero base64 padding bits".to_string());
            }
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
        } else {
            let c = decode_base64_val(chunk[2]).ok_or_else(|| "invalid base64 char".to_string())?;
            let d = decode_base64_val(chunk[3]).ok_or_else(|| "invalid base64 char".to_string())?;
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
            out.push((c << 6) | d);
        }
    }
    if out.len() > maximum {
        return Err("bounded process field exceeded".to_string());
    }
    Ok(out)
}

pub fn parse_processes(output: &str) -> Result<Vec<ProcessRecord>, String> {
    if output.len() > 1024 * 1024 || !output.contains("@@NW_ABUSE_V1@@") {
        return Err("process collector unavailable".to_string());
    }
    let mut processes = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 5
            || fields[0].is_empty()
            || !fields[0].bytes().all(|b| b.is_ascii_digit())
            || fields[1].is_empty()
            || !fields[1].bytes().all(|b| b.is_ascii_digit())
        {
            continue;
        }
        if seen.contains(fields[0]) {
            continue;
        }
        let Ok(pid) = fields[0].parse::<u32>() else {
            continue;
        };
        let Ok(raw) = decode_base64_strict(fields[4], 8192) else {
            continue;
        };
        if raw.len() >= 8192 {
            // A truncated argument vector is not safe actuation evidence.
            continue;
        }
        let Ok(exe_bytes) = decode_base64_strict(fields[2], 4096) else {
            continue;
        };
        let Ok(cwd_bytes) = decode_base64_strict(fields[3], 4096) else {
            continue;
        };
        let argv: Vec<String> = raw
            .split(|&b| b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
        let executable = String::from_utf8_lossy(&exe_bytes).trim().to_string();
        let cwd = String::from_utf8_lossy(&cwd_bytes).trim().to_string();

        seen.insert(fields[0].to_string());
        processes.push(ProcessRecord {
            pid,
            start_ticks: fields[1].to_string(),
            executable,
            cwd,
            argv,
            source: None,
            target_ips: BTreeMap::new(),
            host_pid: None,
            source_coverage: None,
            exe_sha256: None,
            binary_fingerprint: None,
        });
        if processes.len() >= 64 {
            break;
        }
    }
    if !output.contains("@@NW_END@@:") {
        return Err("process collector incomplete".to_string());
    }
    Ok(processes)
}

fn posix_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

fn is_python_exe_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("python") else {
        return false;
    };
    rest.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

pub fn posix_normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let initial_slashes = if path.starts_with("//") && !path.starts_with("///") {
        2
    } else if path.starts_with('/') {
        1
    } else {
        0
    };
    let mut comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".." || (initial_slashes == 0 && comps.is_empty())
            || (!comps.is_empty() && comps.last() == Some(&".."))
        {
            comps.push(comp);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let mut out = "/".repeat(initial_slashes);
    out.push_str(&comps.join("/"));
    if out.is_empty() {
        ".".to_string()
    } else {
        out
    }
}

pub fn python_entrypoint(process: &ProcessRecord) -> (Option<String>, Option<String>) {
    if process.argv.is_empty() || !is_python_exe_name(posix_basename(&process.executable)) {
        return (None, None);
    }
    for (idx, argument) in process.argv.iter().enumerate().skip(1) {
        if argument == "-m" {
            return (None, None);
        }
        if argument == "-c" {
            return (process.argv.get(idx + 1).cloned(), None);
        }
        if argument == "-W" || argument == "-X" {
            return (None, None);
        }
        if argument.starts_with('-') {
            continue;
        }
        if !argument.ends_with(".py") || argument.contains('\0') || argument.len() > 4096 {
            return (None, None);
        }
        let joined = if argument.starts_with('/') {
            argument.clone()
        } else if process.cwd.is_empty() {
            argument.clone()
        } else if process.cwd.ends_with('/') {
            format!("{}{}", process.cwd, argument)
        } else {
            format!("{}/{}", process.cwd, argument)
        };
        let path = posix_normpath(&joined);
        return if path.starts_with('/') {
            (None, Some(path))
        } else {
            (None, None)
        };
    }
    (None, None)
}

/// Prioritize socket owners, including custom-named scanning binaries.
pub fn process_script(sockets: &[SocketRecord]) -> String {
    let mut owners: BTreeMap<u32, usize> = BTreeMap::new();
    for item in sockets {
        if item.direction == "outbound" && item.pid > 1 && item.pid <= 4_194_304 {
            *owners.entry(item.pid).or_insert(0) += 1;
        }
    }
    let mut sorted: Vec<(u32, usize)> = owners.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let pids: Vec<u32> = sorted.into_iter().take(64).map(|(p, _)| p).collect();
    if pids.is_empty() {
        return PROCESS_SCRIPT.to_string();
    }
    let paths: String = pids
        .iter()
        .map(|p| format!("/proc/{p}"))
        .collect::<Vec<_>>()
        .join(" ");
    let pid_list: String = pids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("|");
    let script = PROCESS_SCRIPT.replace(
        "for d in /proc/[0-9]*;",
        &format!("for d in {paths} /proc/[0-9]*;"),
    );
    let old = "case \"$comm\" in python*|node|nmap|masscan|zmap|rustscan|hydra|medusa|ncrack|patator|traffmonetizer*|tmclient|bitping*|antgain|Proxybase*|proxybase*|mysterium|myst|honeygain|earnapp|pawns*|iproyal|packetstream|psclient|peer2profit|p2pclient|repocket|proxyrack|grass|gaganode|titan-edge|castarsdk) ;; *) continue;; esac";
    script.replace(old, &format!("case \"$p\" in {pid_list}) ;; *) {old};; esac"))
}

pub fn shlex_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(b, b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-')
    }) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

pub fn resolve_targets<C, F>(container: &C, execute: &mut F, process: &mut ProcessRecord)
where
    F: FnMut(&C, &str) -> (bool, String),
{
    let evidence = source_evidence(process.source.as_deref());
    if evidence.kinds.is_empty() {
        return;
    }
    process.target_ips.clear();
    for host in evidence.target_hosts.into_iter().take(4) {
        let literal = public_ip(&host);
        if !literal.is_empty() {
            process.target_ips.insert(host, vec![literal]);
            continue;
        }
        let quoted = shlex_quote(&host);
        let command = format!(
            "command -v timeout >/dev/null 2>&1 || exit 2; \
             if command -v getent >/dev/null 2>&1; then timeout 2 getent ahosts {quoted} 2>/dev/null | awk '{{print $1}}'; fi; \
             if command -v nslookup >/dev/null 2>&1; then timeout 2 nslookup {quoted} 2>/dev/null | \
             awk '/^Name[[:space:]]*:/ {{answer=1; next}} answer && /^Address/ {{print $NF}}'; fi"
        );
        let (success, addresses) = execute(container, &command);
        if success {
            let mut resolved: BTreeSet<String> = BTreeSet::new();
            for token in addresses.split_whitespace() {
                let ip = public_ip(token);
                if !ip.is_empty() {
                    resolved.insert(ip);
                }
            }
            process
                .target_ips
                .insert(host, resolved.into_iter().take(20).collect());
        }
    }
}

pub fn collect<C, F>(
    container: &C,
    execute: &mut F,
    sockets: &[SocketRecord],
) -> Result<Vec<ProcessRecord>, String>
where
    F: FnMut(&C, &str) -> (bool, String),
{
    let (ok, output) = execute(container, &process_script(sockets));
    if !ok {
        return Err("process metadata unavailable".to_string());
    }
    let mut processes = parse_processes(&output)?;
    let mut owned_counts: BTreeMap<u32, usize> = BTreeMap::new();
    for item in sockets {
        if item.direction == "outbound" {
            *owned_counts.entry(item.pid).or_insert(0) += 1;
        }
    }
    processes.sort_by(|a, b| {
        let ca = owned_counts.get(&a.pid).copied().unwrap_or(0);
        let cb = owned_counts.get(&b.pid).copied().unwrap_or(0);
        cb.cmp(&ca)
    });

    let mut read_sources = 0usize;
    for process in &mut processes {
        if owned_counts.get(&process.pid).copied().unwrap_or(0) == 0 {
            continue;
        }
        let (inline, path) = python_entrypoint(process);
        if let Some(code) = inline {
            process.source = Some(code);
        } else if let Some(script_path) = path {
            if read_sources < 4 {
                read_sources += 1;
                let quoted = shlex_quote(&script_path);
                let command = format!(
                    "if [ -f {quoted} ] && [ ! -L {quoted} ]; then head -c 65537 -- {quoted} 2>/dev/null | base64; fi"
                );
                let (success, encoded) = execute(container, &command);
                if success {
                    let compact: String = encoded.split_whitespace().collect();
                    if let Ok(raw) = decode_base64_strict(&compact, 65537) {
                        if raw.len() <= 65536 {
                            if let Ok(text) = String::from_utf8(raw) {
                                process.source = Some(text);
                            }
                        }
                    }
                }
            }
        }
        if process.source.is_some() {
            resolve_targets(container, execute, process);
        }
    }
    Ok(processes)
}

fn read_bounded_bytes(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(limit.min(8192));
    file.take(limit as u64)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

fn parse_nspid(status: &str) -> Option<u32> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("NSpid:") {
            let trimmed = rest.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(last) = trimmed.split_whitespace().last() {
                if let Ok(val) = last.parse::<u32>() {
                    return Some(val);
                }
            }
        }
    }
    None
}

/// Kernel-owned process incarnation; transient argv is never reported.
pub fn host_metadata(host_pid: u32) -> Result<ProcessRecord, String> {
    host_metadata_from(Path::new("/proc"), host_pid)
}

pub fn host_metadata_from(proc_root: &Path, host_pid: u32) -> Result<ProcessRecord, String> {
    if host_pid <= 1 {
        return Err("invalid host process identity".to_string());
    }
    let base = proc_root.join(host_pid.to_string());

    let stat_bytes = read_bounded_bytes(&base.join("stat"), 4096)?;
    let stat_str = std::str::from_utf8(&stat_bytes).map_err(|e| e.to_string())?;
    let close_paren = stat_str
        .rfind(')')
        .ok_or_else(|| "host process is no longer live".to_string())?;
    let after = stat_str
        .get(close_paren + 1..)
        .ok_or_else(|| "host process is no longer live".to_string())?;
    let mut fields = after.split_whitespace();
    let state = fields
        .next()
        .ok_or_else(|| "host process is no longer live".to_string())?;
    if state == "Z" {
        return Err("host process is no longer live".to_string());
    }
    let (start_ticks, _) =
        parse_proc_stat(stat_str).ok_or_else(|| "host process is no longer live".to_string())?;

    let status_bytes = read_bounded_bytes(&base.join("status"), 16384)?;
    let status_str = std::str::from_utf8(&status_bytes).map_err(|e| e.to_string())?;
    let pid = parse_nspid(status_str)
        .ok_or_else(|| "kernel PID namespace identity unavailable".to_string())?;

    let cmdline_bytes = read_bounded_bytes(&base.join("cmdline"), 8192)?;
    if cmdline_bytes.len() >= 8192 {
        return Err("truncated host argument vector".to_string());
    }
    let argv: Vec<String> = cmdline_bytes
        .split(|&b| b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();

    let executable = fs::read_link(base.join("exe"))
        .map_err(|e| e.to_string())?
        .to_string_lossy()
        .into_owned();
    let cwd = fs::read_link(base.join("cwd"))
        .map_err(|e| e.to_string())?
        .to_string_lossy()
        .into_owned();

    Ok(ProcessRecord {
        pid,
        start_ticks,
        executable,
        cwd,
        argv,
        source: None,
        target_ips: BTreeMap::new(),
        host_pid: Some(host_pid),
        source_coverage: None,
        exe_sha256: None,
        binary_fingerprint: None,
    })
}

pub fn inspect_host_executable_under(
    proc_root: &Path,
    host_pid: u32,
) -> (Option<String>, Option<String>) {
    let exe_path = proc_root.join(host_pid.to_string()).join("exe");
    let Ok(bytes) = read_bounded_bytes(&exe_path, 8 * 1024 * 1024) else {
        return (None, None);
    };
    if bytes.is_empty() {
        return (None, None);
    }
    let sha = sha256_hex(&bytes);
    let marker = detect_bandwidth_monetization_markers(&bytes).map(str::to_string);
    (Some(sha), marker)
}

/// Select by kernel PID namespace, not ancestry (`podman exec` has another parent).
#[cfg(unix)]
pub fn scoped_host_processes(
    init_pid: u32,
    proc_root: &Path,
    scan_limit: usize,
) -> Result<Vec<ScopedHostProcess>, String> {
    let init_ns_path = proc_root.join(init_pid.to_string()).join("ns/pid");
    let namespace = fs::metadata(&init_ns_path)
        .map_err(|e| format!("unable to inspect container PID namespace: {e}"))?
        .ino();

    let mut pids: Vec<u32> = Vec::new();
    let entries = fs::read_dir(proc_root)
        .map_err(|e| format!("unable to list proc root: {e}"))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if let Some(s) = name.to_str() {
            if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(pid) = s.parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
    }
    pids.sort_unstable();
    if pids.len() > scan_limit {
        return Err(
            "kernel process inventory exceeded safe bound; coverage unavailable".to_string(),
        );
    }

    let mut result = Vec::new();
    for host_pid in pids {
        let base = proc_root.join(host_pid.to_string());
        let Ok(ns_meta) = fs::metadata(base.join("ns/pid")) else {
            continue;
        };
        if ns_meta.ino() != namespace {
            continue;
        }
        let Ok(status_bytes) = read_bounded_bytes(&base.join("status"), 16384) else {
            continue;
        };
        let Ok(status_str) = std::str::from_utf8(&status_bytes) else {
            continue;
        };
        let Some(pid) = parse_nspid(status_str) else {
            continue;
        };
        let Ok(comm_bytes) = read_bounded_bytes(&base.join("comm"), 256) else {
            continue;
        };
        let comm: String = String::from_utf8_lossy(&comm_bytes)
            .trim()
            .chars()
            .take(120)
            .collect();
        result.push(ScopedHostProcess {
            host_pid,
            pid,
            process: comm,
        });
    }

    if !result.iter().any(|p| p.host_pid == init_pid) {
        return Err("container init incarnation disappeared during process discovery".to_string());
    }
    Ok(result)
}

#[cfg(not(unix))]
pub fn scoped_host_processes(
    _init_pid: u32,
    _proc_root: &Path,
    _scan_limit: usize,
) -> Result<Vec<ScopedHostProcess>, String> {
    Err("kernel PID namespace inspection requires Unix".to_string())
}

/// Read ONLY a running `.py` entrypoint through its process root/cwd.
///
/// Walk every component without following symlinks. No traversal, magic links,
/// recursive search, history files or reads outside the target process root.
pub fn read_host_entrypoint(process: &ProcessRecord) -> Result<Option<String>, String> {
    let cloned = ProcessRecord {
        cwd: "/".to_string(),
        ..process.clone()
    };
    let (inline, parsed) = python_entrypoint(&cloned);
    if let Some(code) = inline {
        return Ok(Some(code));
    }
    if parsed.is_none() {
        return Ok(None);
    }
    let Some(host_pid) = process.host_pid else {
        return Err("host_pid required to read entrypoint".to_string());
    };
    let argument = process
        .argv
        .iter()
        .skip(1)
        .find(|v| !v.starts_with('-'))
        .map(String::as_str)
        .unwrap_or("");
    let base_sub = if argument.starts_with('/') {
        "root"
    } else {
        "cwd"
    };
    let base = PathBuf::from(format!("/proc/{host_pid}/{base_sub}"));
    read_host_entrypoint_under(&base, process)
}

pub fn read_host_entrypoint_under(
    base_dir: &Path,
    process: &ProcessRecord,
) -> Result<Option<String>, String> {
    let cloned = ProcessRecord {
        cwd: "/".to_string(),
        ..process.clone()
    };
    let (inline, parsed) = python_entrypoint(&cloned);
    if let Some(code) = inline {
        return Ok(Some(code));
    }
    if parsed.is_none() {
        return Ok(None);
    }
    let argument = process
        .argv
        .iter()
        .skip(1)
        .find(|v| !v.starts_with('-'))
        .map(String::as_str)
        .unwrap_or("");
    let pieces: Vec<&str> = argument.split('/').collect();
    if pieces.contains(&"..") || pieces.len() > 64 || argument.contains('\0') {
        return Ok(None);
    }
    let components: Vec<&str> = pieces
        .into_iter()
        .filter(|&v| !v.is_empty() && v != ".")
        .collect();
    if components.is_empty() {
        return Ok(None);
    }

    let base_meta = fs::metadata(base_dir).map_err(|e| e.to_string())?;
    if !base_meta.is_dir() {
        return Err("entrypoint base is not a directory".to_string());
    }

    let mut cur = base_dir.to_path_buf();
    for &comp in &components[..components.len() - 1] {
        cur.push(comp);
        let lmeta = fs::symlink_metadata(&cur).map_err(|e| e.to_string())?;
        if lmeta.file_type().is_symlink() || !lmeta.is_dir() {
            return Err("symlink or non-directory component rejected".to_string());
        }
        #[cfg(unix)]
        {
            let dir_file = File::open(&cur).map_err(|e| e.to_string())?;
            let fmeta = dir_file.metadata().map_err(|e| e.to_string())?;
            if !fmeta.is_dir()
                || fmeta.dev() != lmeta.dev()
                || fmeta.ino() != lmeta.ino()
            {
                return Err("directory component changed during walk".to_string());
            }
        }
    }

    cur.push(components[components.len() - 1]);
    let lmeta = fs::symlink_metadata(&cur).map_err(|e| e.to_string())?;
    if lmeta.file_type().is_symlink() {
        return Err("symlink entrypoint refused".to_string());
    }
    if !lmeta.is_file() {
        return Ok(None);
    }

    let file = File::open(&cur).map_err(|e| e.to_string())?;
    let fmeta = file.metadata().map_err(|e| e.to_string())?;
    if !fmeta.is_file() {
        return Ok(None);
    }
    #[cfg(unix)]
    if fmeta.dev() != lmeta.dev() || fmeta.ino() != lmeta.ino() {
        return Err("entrypoint file identity changed during open".to_string());
    }

    let mut buf = Vec::new();
    file.take(65537)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() > 65536 {
        return Ok(None);
    }
    let text = String::from_utf8(buf).map_err(|e| e.to_string())?;
    Ok(Some(text))
}

pub fn collect_host<C, F>(
    host_processes: &[ScopedHostProcess],
    sockets: &[SocketRecord],
    container: &C,
    execute: &mut F,
) -> Result<Vec<ProcessRecord>, String>
where
    F: FnMut(&C, &str) -> (bool, String),
{
    collect_host_with(
        host_processes,
        sockets,
        container,
        execute,
        &mut host_metadata,
        &mut read_host_entrypoint,
    )
}

pub fn collect_host_with<C, F, M, R>(
    host_processes: &[ScopedHostProcess],
    sockets: &[SocketRecord],
    container: &C,
    execute: &mut F,
    read_metadata: &mut M,
    read_entrypoint: &mut R,
) -> Result<Vec<ProcessRecord>, String>
where
    F: FnMut(&C, &str) -> (bool, String),
    M: FnMut(u32) -> Result<ProcessRecord, String>,
    R: FnMut(&ProcessRecord) -> Result<Option<String>, String>,
{
    let mut owners: BTreeMap<u32, usize> = BTreeMap::new();
    for flow in sockets {
        if flow.direction == "outbound" {
            *owners.entry(flow.pid).or_insert(0) += 1;
        }
    }
    let mut selected: Vec<&ScopedHostProcess> = host_processes.iter().collect();
    selected.sort_by(|a, b| {
        let ca = owners.get(&a.pid).copied().unwrap_or(0);
        let cb = owners.get(&b.pid).copied().unwrap_or(0);
        cb.cmp(&ca)
    });
    selected.truncate(64);

    let mut result = Vec::new();
    let mut read_sources = 0usize;
    for observed in selected {
        let Ok(mut process) = read_metadata(observed.host_pid) else {
            continue;
        };
        if process.pid < 1 || process.pid != observed.pid {
            continue;
        }
        let is_bm_name = bandwidth_monetization_tool_for_name(&process.executable).is_some()
            || process
                .argv
                .first()
                .and_then(|arg| bandwidth_monetization_tool_for_name(arg))
                .is_some();
        let has_outbound = owners.get(&process.pid).copied().unwrap_or(0) > 0;
        if has_outbound && read_sources < 4 {
            read_sources += 1;
            match read_entrypoint(&process) {
                Ok(Some(src)) => {
                    process.source = Some(src);
                    resolve_targets(container, execute, &mut process);
                }
                Ok(None) => {}
                Err(_) => {
                    process.source_coverage = Some("unavailable".to_string());
                }
            }
        }
        if process.source.is_none()
            && process.exe_sha256.is_none()
            && (is_bm_name || (has_outbound && read_sources <= 4))
        {
            let (sha, marker) = inspect_host_executable_under(Path::new("/proc"), observed.host_pid);
            if sha.is_some() {
                process.exe_sha256 = sha;
            }
            if process.binary_fingerprint.is_none() && marker.is_some() {
                process.binary_fingerprint = marker;
            }
        }
        if let Ok(fresh) = read_metadata(observed.host_pid) {
            if fresh.start_ticks == process.start_ticks {
                result.push(process);
            }
        }
    }
    if result.is_empty() {
        return Err("no fresh kernel process metadata; not a clean observation".to_string());
    }
    Ok(result)
}

pub fn verify_host_processes(
    host_processes: &[ProcessRecord],
    findings: &[crate::detection::Finding],
) -> Result<(), String> {
    verify_host_processes_with(host_processes, findings, &mut host_metadata)
}

pub fn verify_host_processes_with<M>(
    host_processes: &[ProcessRecord],
    findings: &[crate::detection::Finding],
    read_metadata: &mut M,
) -> Result<(), String>
where
    M: FnMut(u32) -> Result<ProcessRecord, String>,
{
    for process in host_processes {
        let matches = findings
            .iter()
            .any(|f| f.pid == process.pid && f.start_ticks == process.start_ticks);
        if !matches {
            continue;
        }
        let Some(host_pid) = process.host_pid else {
            continue;
        };
        if let Ok(current) = read_metadata(host_pid) {
            if current.pid == process.pid && current.start_ticks == process.start_ticks {
                return Ok(());
            }
        }
    }
    Err("offending kernel process incarnation is no longer fresh".to_string())
}

/// Check fresh PID incarnation before a destructive network operation.
pub fn verify_live_processes<C, F>(
    container: &C,
    execute: &mut F,
    findings: &[crate::detection::Finding],
) -> Result<(), String>
where
    F: FnMut(&C, &str) -> (bool, String),
{
    let sockets: Vec<SocketRecord> = findings
        .iter()
        .map(|f| SocketRecord {
            pid: f.pid,
            remote_ip: String::new(),
            remote: String::new(),
            state: String::new(),
            proto: String::new(),
            direction: "outbound".to_string(),
        })
        .collect();
    let (ok, output) = execute(container, &process_script(&sockets));
    if !ok {
        return Err("fresh process verification unavailable; no new quarantine".to_string());
    }
    let parsed = parse_processes(&output)?;
    let current: BTreeMap<u32, String> = parsed
        .into_iter()
        .map(|p| (p.pid, p.start_ticks))
        .collect();
    if findings
        .iter()
        .any(|f| current.get(&f.pid) == Some(&f.start_ticks))
    {
        return Ok(());
    }
    Err("offending process evidence is no longer fresh; no new quarantine".to_string())
}
