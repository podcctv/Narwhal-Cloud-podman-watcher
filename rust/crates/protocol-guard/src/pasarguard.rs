//! Exact PasarGuard-node identity detection and surgical service remediation.
//!
//! Migrated from `client/pasarguard_guard.py`.
//! Matches official images (`pasarguard/node`, `docker.io/pasarguard/node`,
//! `ghcr.io/pasarguard/node`) or ELF `.go.buildinfo` module identity
//! `github.com/pasarguard/node/cmd/node`; never kills generic `main`/`node`/`xray` names.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;

use net_guard::PROTECTED_CONTAINERS;
use proc_probe::parse_proc_stat;

use crate::util::{current_unix_secs, env_bool_enabled, posix_normpath, JsonBuilder};

pub const PASARGUARD_MODULE: &str = "github.com/pasarguard/node/cmd/node";
pub const PASARGUARD_ALERT_TTL_SECS: i64 = 900;
pub const PASARGUARD_STATE_RETENTION_SECS: i64 = 86_400;

const ALLOWED_IMAGE_REPOS: &[&str] = &[
    "pasarguard/node",
    "docker.io/pasarguard/node",
    "ghcr.io/pasarguard/node",
];

const EXEC_ALLOWED_PREFIXES: &[&str] = &[
    "/app/",
    "/opt/",
    "/usr/local/bin/",
    "/var/lib/",
    "/root/",
    "/home/",
    "/srv/",
];

/// Matches `pasarguard_guard.image_match(value)`.
pub fn image_match(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let without_digest = lower.split('@').next().unwrap_or("");
    let last_segment = without_digest.rsplit('/').next().unwrap_or("");
    let repo = if last_segment.contains(':') {
        without_digest
            .rsplit_once(':')
            .map(|(left, _)| left)
            .unwrap_or(without_digest)
    } else {
        without_digest
    };
    ALLOWED_IMAGE_REPOS.contains(&repo)
}

fn read_u16(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    let arr = [slice[0], slice[1]];
    Some(if little_endian {
        u16::from_le_bytes(arr)
    } else {
        u16::from_be_bytes(arr)
    })
}

fn read_u32(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    let arr = [slice[0], slice[1], slice[2], slice[3]];
    Some(if little_endian {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    })
}

fn read_u64(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u64> {
    let slice = bytes.get(offset..offset + 8)?;
    let arr = [
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ];
    Some(if little_endian {
        u64::from_le_bytes(arr)
    } else {
        u64::from_be_bytes(arr)
    })
}

#[derive(Debug, Clone, Copy)]
struct ElfSectionHeader {
    sh_name: u32,
    sh_offset: u64,
    sh_size: u64,
}

fn decode_uvarint_slice<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let mut length: usize = 0;
    let mut saw_terminator = false;
    for shift in (0..35).step_by(7) {
        let part = *data.get(*pos)?;
        *pos += 1;
        length |= ((part & 0x7f) as usize) << shift;
        if part < 0x80 {
            saw_terminator = true;
            break;
        }
    }
    if !saw_terminator || length > 65536 {
        return None;
    }
    let end = (*pos).checked_add(length)?;
    let slice = data.get(*pos..end)?;
    *pos = end;
    Some(slice)
}

/// Reads bounded ELF32/ELF64 (LE & BE) `.go.buildinfo` section and returns
/// `Some("github.com/pasarguard/node/cmd/node")` when matched.
pub fn go_module(path: &Path) -> Option<String> {
    let mut stream = File::open(path).ok()?;
    let mut header = [0u8; 64];
    let n = stream.read(&mut header).ok()?;
    if n < 52 || &header[0..4] != b"\x7fELF" {
        return None;
    }
    let little_endian = match header[5] {
        1 => true,
        2 => false,
        _ => return None,
    };

    let (shoff, shentsize, shnum, shstrndx, is_64) = match header[4] {
        2 => {
            if n < 64 {
                return None;
            }
            let offset = read_u64(&header, 40, little_endian)?;
            let size = read_u16(&header, 58, little_endian)? as usize;
            let count = read_u16(&header, 60, little_endian)? as usize;
            let index = read_u16(&header, 62, little_endian)? as usize;
            if size != 64 {
                return None;
            }
            (offset, size, count, index, true)
        }
        1 => {
            let offset = read_u32(&header, 32, little_endian)? as u64;
            let size = read_u16(&header, 46, little_endian)? as usize;
            let count = read_u16(&header, 48, little_endian)? as usize;
            let index = read_u16(&header, 50, little_endian)? as usize;
            if size != 40 {
                return None;
            }
            (offset, size, count, index, false)
        }
        _ => return None,
    };

    if shnum == 0 || shnum > 4096 || shstrndx >= shnum {
        return None;
    }

    let table_bytes = shentsize.checked_mul(shnum)?;
    stream.seek(SeekFrom::Start(shoff)).ok()?;
    let mut sections = vec![0u8; table_bytes];
    stream.read_exact(&mut sections).ok()?;

    let mut entries = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let base = i * shentsize;
        let sh_name = read_u32(&sections, base, little_endian)?;
        let (sh_offset, sh_size) = if is_64 {
            (
                read_u64(&sections, base + 24, little_endian)?,
                read_u64(&sections, base + 32, little_endian)?,
            )
        } else {
            (
                read_u32(&sections, base + 16, little_endian)? as u64,
                read_u32(&sections, base + 20, little_endian)? as u64,
            )
        };
        entries.push(ElfSectionHeader {
            sh_name,
            sh_offset,
            sh_size,
        });
    }

    let names_entry = entries.get(shstrndx)?;
    if names_entry.sh_size > 1024 * 1024 {
        return None;
    }
    stream.seek(SeekFrom::Start(names_entry.sh_offset)).ok()?;
    let mut names = vec![0u8; names_entry.sh_size as usize];
    stream.read_exact(&mut names).ok()?;

    for entry in &entries {
        let start = entry.sh_name as usize;
        let Some(tail) = names.get(start..) else {
            continue;
        };
        let section_name = tail.split(|&b| b == 0).next().unwrap_or(b"");
        if section_name != b".go.buildinfo" {
            continue;
        }
        if !(32..=65536).contains(&entry.sh_size) {
            return None;
        }
        stream.seek(SeekFrom::Start(entry.sh_offset)).ok()?;
        let mut data = vec![0u8; entry.sh_size as usize];
        stream.read_exact(&mut data).ok()?;

        if !data.starts_with(b"\xff Go buildinf:") || (data[15] & 2) == 0 {
            return None;
        }

        let mut pos = 32usize;
        let _go_ver = decode_uvarint_slice(&data, &mut pos)?;
        let mut module = decode_uvarint_slice(&data, &mut pos)?;

        if module.len() >= 33 && module[module.len() - 17] == b'\n' {
            module = &module[16..module.len() - 16];
        }
        let module_text = String::from_utf8_lossy(module);
        let framed = format!("\n{module_text}");
        if framed.contains("\npath\tgithub.com/pasarguard/node/cmd/node\n") {
            return Some(PASARGUARD_MODULE.to_string());
        }
    }

    None
}

/// Validates `EXEC_PATH`: `^/(?:app|opt|usr/local/bin|var/lib|root|home|srv)/[A-Za-z0-9_./+-]{1,200}$`
/// and `posix_normpath(exe) == exe`.
pub fn is_valid_exec_path(exe: &str) -> bool {
    if posix_normpath(exe) != exe {
        return false;
    }
    for prefix in EXEC_ALLOWED_PREFIXES {
        if let Some(rest) = exe.strip_prefix(prefix) {
            let bytes = rest.as_bytes();
            if (1..=200).contains(&bytes.len())
                && bytes.iter().all(|b| {
                    b.is_ascii_alphanumeric()
                        || matches!(b, b'_' | b'.' | b'/' | b'+' | b'-')
                })
            {
                return true;
            }
        }
    }
    false
}

/// Validates a systemd service unit name: `^[A-Za-z0-9_@.-]+\.service$`.
pub fn is_valid_service_unit(unit: &str) -> bool {
    let Some(stem) = unit.strip_suffix(".service") else {
        return false;
    };
    !stem.is_empty()
        && stem.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'@' | b'.' | b'-')
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasarFinding {
    pub pid: u32,
    pub host_pid: u32,
    pub start_ticks: String,
    pub executable: String,
    pub unit: String,
    pub module: String,
}

impl PasarFinding {
    pub fn to_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.u64("pid", self.pid as u64);
        b.u64("host_pid", self.host_pid as u64);
        b.str("start_ticks", &self.start_ticks);
        b.str("executable", &self.executable);
        b.str("unit", &self.unit);
        b.str("module", &self.module);
        b.finish()
    }
}

fn extract_nspid_inner(status_text: &str) -> Option<u32> {
    for line in status_text.lines() {
        if let Some(rest) = line.strip_prefix("NSpid:") {
            let last = rest.split_whitespace().last()?;
            return last.parse::<u32>().ok();
        }
    }
    None
}

fn extract_proc_state_and_ticks(stat_text: &str) -> Option<(char, String)> {
    let close = stat_text.rfind(')')?;
    let after = stat_text.get(close + 2..)?;
    let fields: Vec<&str> = after.split_whitespace().collect();
    if fields.len() <= 19 {
        return None;
    }
    let state = fields[0].chars().next()?;
    let ticks = fields[19];
    if ticks.is_empty() || !ticks.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let _ = parse_proc_stat(stat_text);
    Some((state, ticks.to_string()))
}

fn extract_cgroup_service_unit(init_group: &str, proc_group: &str) -> String {
    let initial = init_group
        .trim()
        .splitn(3, ':')
        .last()
        .unwrap_or("")
        .trim_end_matches('/');
    let current = proc_group.trim().splitn(3, ':').last().unwrap_or("");
    let prefix = format!("{initial}/");
    if current.starts_with(&prefix) {
        let suffix = &current[initial.len()..];
        let mut found = String::new();
        for seg in suffix.split('/') {
            if is_valid_service_unit(seg) {
                found = seg.to_string();
            }
        }
        return found;
    }
    String::new()
}

#[cfg(unix)]
fn file_dev_ino(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn file_dev_ino(path: &Path) -> Option<(u64, u64)> {
    // On non-Unix test environments, allow simulated namespace files containing `dev:ino` text
    let raw = fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if let Some((d, i)) = trimmed.split_once(':') {
        Some((d.parse().ok()?, i.parse().ok()?))
    } else {
        Some((1, trimmed.parse().ok()?))
    }
}

fn read_exe_target(proc_pid_dir: &Path) -> Option<String> {
    let exe_path = proc_pid_dir.join("exe");
    if let Ok(link) = fs::read_link(&exe_path) {
        let s = link.to_string_lossy().into_owned();
        return Some(s.strip_suffix(" (deleted)").unwrap_or(&s).to_string());
    }
    // Fallback for synthetic non-symlink test fixtures (`exe_link` file)
    if let Ok(raw) = fs::read_to_string(proc_pid_dir.join("exe_link")) {
        let s = raw.trim();
        return Some(s.strip_suffix(" (deleted)").unwrap_or(s).to_string());
    }
    None
}

/// Discovers processes in the same kernel PID namespace as `init_pid`, matching
/// `abuse_collection.scoped_host_processes`.
pub fn scoped_host_processes_from(
    proc_root: &Path,
    init_pid: u32,
    scan_limit: usize,
) -> Result<Vec<(u32, u32, String)>, String> {
    if init_pid <= 1 {
        return Err("invalid init pid".to_string());
    }
    let init_ns = file_dev_ino(&proc_root.join(init_pid.to_string()).join("ns").join("pid"))
        .ok_or_else(|| "unable to stat init pid namespace".to_string())?;

    let entries = fs::read_dir(proc_root).map_err(|e| format!("read_dir failed: {e}"))?;
    let mut pids = Vec::new();
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if name.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(p) = name.parse::<u32>() {
                    pids.push(p);
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
        let Some(ns) = file_dev_ino(&base.join("ns").join("pid")) else {
            continue;
        };
        if ns.1 != init_ns.1 {
            continue;
        }
        let Ok(status) = fs::read_to_string(base.join("status")) else {
            continue;
        };
        let Some(inner_pid) = extract_nspid_inner(&status) else {
            continue;
        };
        let Ok(comm_raw) = fs::read_to_string(base.join("comm")) else {
            continue;
        };
        let comm: String = comm_raw.trim().chars().take(120).collect();
        result.push((host_pid, inner_pid, comm));
    }

    if !result.iter().any(|(hp, _, _)| *hp == init_pid) {
        return Err("container init incarnation disappeared during process discovery".to_string());
    }
    Ok(result)
}

/// Scans `/proc` for PasarGuard Node processes inside `pid`'s PID namespace.
pub fn native_matches(pid: u32) -> Vec<PasarFinding> {
    native_matches_from(Path::new("/proc"), pid)
}

/// Scans `proc_root` for PasarGuard Node processes inside `pid`'s PID namespace.
pub fn native_matches_from(proc_root: &Path, pid: u32) -> Vec<PasarFinding> {
    if pid <= 1 {
        return Vec::new();
    }
    let init_dir = proc_root.join(pid.to_string());
    let Ok(init_group) = fs::read_to_string(init_dir.join("cgroup")) else {
        return Vec::new();
    };
    let Some(root_ns) = file_dev_ino(&init_dir.join("ns").join("pid")) else {
        return Vec::new();
    };
    let Ok(scoped) = scoped_host_processes_from(proc_root, pid, 20_000) else {
        return Vec::new();
    };

    let mut result = Vec::new();
    for (host_pid, _, _) in scoped.into_iter().take(256) {
        if host_pid <= 1 {
            continue;
        }
        let pdir = proc_root.join(host_pid.to_string());
        let Some(p_ns) = file_dev_ino(&pdir.join("ns").join("pid")) else {
            continue;
        };
        if p_ns.1 != root_ns.1 {
            continue;
        }
        let Some(module) = go_module(&pdir.join("exe")) else {
            continue;
        };
        let Ok(stat_text) = fs::read_to_string(pdir.join("stat")) else {
            continue;
        };
        let Some((state_ch, start_ticks)) = extract_proc_state_and_ticks(&stat_text) else {
            continue;
        };
        if state_ch == 'Z' {
            continue;
        }
        let Ok(cmdline) = fs::read(pdir.join("cmdline")) else {
            continue;
        };
        if cmdline.len() >= 8192 {
            continue;
        }
        let Ok(status_text) = fs::read_to_string(pdir.join("status")) else {
            continue;
        };
        let Some(inner) = extract_nspid_inner(&status_text) else {
            continue;
        };
        let Some(executable) = read_exe_target(&pdir) else {
            continue;
        };
        if inner <= 1 || !is_valid_exec_path(&executable) {
            continue;
        }
        let Ok(group) = fs::read_to_string(pdir.join("cgroup")) else {
            continue;
        };
        let unit = extract_cgroup_service_unit(&init_group, &group);
        result.push(PasarFinding {
            pid: inner,
            host_pid,
            start_ticks,
            executable,
            unit,
            module,
        });
        if result.len() >= 8 {
            break;
        }
    }
    result
}

/// Builds the guest cleanup shell script for a verified `PasarFinding`, matching
/// `pasarguard_guard.cleanup_script(finding)`.
pub fn cleanup_script(finding: &PasarFinding) -> Result<String, String> {
    let pid = finding.pid;
    let ticks = finding.start_ticks.trim();
    let exe = finding.executable.as_str();
    let unit = finding.unit.as_str();

    if pid <= 1
        || ticks.is_empty()
        || !ticks.bytes().all(|b| b.is_ascii_digit())
        || !is_valid_exec_path(exe)
    {
        return Err("invalid exact software scope".to_string());
    }
    if !unit.is_empty() && !is_valid_service_unit(unit) {
        return Err("invalid service scope".to_string());
    }

    Ok(format!(
        "set -eu\n\
p={pid}; expected={ticks}; exe='{exe}'; unit='{unit}'\n\
[ -r /proc/$p/stat ] || exit 0\n\
line=$(cat /proc/$p/stat); rest=${{line##*) }}; actual=$(printf '%s' \"$rest\" | awk '{{print $20}}')\n\
[ \"$actual\" = \"$expected\" ] || exit 31\n\
case \"$(readlink /proc/$p/exe)\" in \"$exe\"|\"$exe (deleted)\") :;; *) exit 32;; esac\n\
backup=/var/lib/narwhal-disabled-pasarguard\n\
[ ! -L \"$backup\" ] || exit 37\n\
mkdir -p \"$backup\"; chmod 700 \"$backup\"\n\
if [ -n \"$unit\" ] && command -v systemctl >/dev/null 2>&1; then\n\
 launch=$(systemctl show --property=ExecStart --value \"$unit\" 2>/dev/null || true)\n\
 case \"$launch\" in *\"path=$exe ;\"*)\n\
  systemctl disable --now \"$unit\" >/dev/null 2>&1 || exit 33\n\
  for base in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do\n\
   if [ -f \"$base/$unit\" ] && [ ! -L \"$base/$unit\" ]; then mv -- \"$base/$unit\" \"$backup/$unit.$expected\"; fi\n\
  done\n\
  systemctl daemon-reload;;\n\
 esac\n\
fi\n\
for base in /etc/init.d /etc/supervisor/conf.d; do\n\
 [ -d \"$base\" ] || continue\n\
 for f in \"$base\"/*; do\n\
  [ -f \"$f\" ] && [ ! -L \"$f\" ] || continue\n\
  grep -Fq -- \"$exe\" \"$f\" || continue\n\
  grep -Eiq 'pasarguard|pg-node' \"$f\" || continue\n\
  service=${{f##*/}}\n\
  case \"$service\" in *pasarguard*|*pg-node*) :;; *) continue;; esac\n\
  if [ \"$base\" = /etc/init.d ]; then\n\
   command -v rc-service >/dev/null 2>&1 && rc-service \"$service\" stop >/dev/null 2>&1 || true\n\
   command -v rc-update >/dev/null 2>&1 && rc-update del \"$service\" >/dev/null 2>&1 || true\n\
  else command -v supervisorctl >/dev/null 2>&1 && supervisorctl stop \"$service\" >/dev/null 2>&1 || true; fi\n\
  mv -- \"$f\" \"$backup/$service.$expected\"\n\
 done\n\
done\n\
for base in /etc/cron.d /var/spool/cron/crontabs; do\n\
 [ -d \"$base\" ] || continue\n\
 for f in \"$base\"/*; do\n\
  [ -f \"$f\" ] && [ ! -L \"$f\" ] || continue\n\
  grep -Fq -- \"$exe\" \"$f\" || continue\n\
  grep -Eiq 'pasarguard|pg-node' \"$f\" || continue\n\
  tmp=$(mktemp)\n\
  awk -v exe=\"$exe\" '!(index($0,exe) && tolower($0) ~ /pasarguard|pg-node/)' \"$f\" > \"$tmp\"\n\
  cp -p -- \"$f\" \"$backup/cron.${{f##*/}}.$expected\"\n\
  cat \"$tmp\" > \"$f\"; rm -f -- \"$tmp\"\n\
 done\n\
done\n\
if [ -r /proc/$p/stat ]; then\n\
 line=$(cat /proc/$p/stat); rest=${{line##*) }}\n\
 [ \"$(printf '%s' \"$rest\" | awk '{{print $20}}')\" = \"$expected\" ] || exit 34\n\
 kill -TERM \"$p\"\n\
 for n in 1 2 3 4 5 6 7 8 9 10; do [ -d /proc/$p ] || break; sleep 1; done\n\
 if [ -r /proc/$p/stat ]; then\n\
  line=$(cat /proc/$p/stat); rest=${{line##*) }}\n\
  [ \"$(printf '%s' \"$rest\" | awk '{{print $20}}')\" = \"$expected\" ] || exit 35\n\
  kill -KILL \"$p\"\n\
 fi\n\
fi\n\
if [ -f \"$exe\" ] && [ ! -L \"$exe\" ]; then mv -- \"$exe\" \"$backup/program.$expected\"; fi\n\
[ ! -e /proc/$p/exe ] || exit 36\n\
printf 'PasarGuard node service removed; private rollback files retained; outer instance preserved'\n"
    ))
}

/// Returns the guest script for removing nested Docker `pasarguard/node` containers.
pub fn nested_script() -> &'static str {
    "set -eu\n\
unset DOCKER_HOST DOCKER_CONTEXT\n\
count=0\n\
for runtime in docker; do\n\
 command -v \"$runtime\" >/dev/null 2>&1 || continue\n\
 ids=$(\"$runtime\" --host unix:///var/run/docker.sock ps -aq --no-trunc) || exit 41\n\
 for id in $ids; do\n\
  case \"$id\" in *[!a-f0-9]*|'') exit 42;; esac\n\
  image=$(\"$runtime\" --host unix:///var/run/docker.sock inspect --format '{{.Config.Image}}' \"$id\") || exit 43\n\
  repo=${image%%@*}; repo=${repo%:*}\n\
  case \"$repo\" in pasarguard/node|docker.io/pasarguard/node|ghcr.io/pasarguard/node)\n\
   \"$runtime\" --host unix:///var/run/docker.sock update --restart=no \"$id\" >/dev/null || exit 44\n\
   \"$runtime\" --host unix:///var/run/docker.sock stop --time 10 \"$id\" >/dev/null || exit 45\n\
   \"$runtime\" --host unix:///var/run/docker.sock rm \"$id\" >/dev/null || exit 46\n\
   count=$((count+1));;\n\
  esac\n\
 done\n\
done\n\
printf 'NW_PASAR_REMOVED=%s\\n' \"$count\"\n"
}

/// Verifies that `/proc/{pid}/root/var/run/docker.sock` belongs to a private `dockerd`
/// inside the container and is NOT bind-mounted from the host `/var/run/docker.sock`.
pub fn private_docker(pid: u32) -> bool {
    private_docker_from(
        Path::new("/proc"),
        Path::new("/var/run/docker.sock"),
        pid,
    )
}

/// Testable implementation of `private_docker` using explicit `proc_root` and `mother_sock`.
pub fn private_docker_from(proc_root: &Path, mother_sock: &Path, pid: u32) -> bool {
    if pid <= 1 {
        return false;
    }
    let nested_path = proc_root
        .join(pid.to_string())
        .join("root")
        .join("var")
        .join("run")
        .join("docker.sock");
    let Some(nested_id) = file_dev_ino(&nested_path) else {
        return false;
    };
    if let Some(mother_id) = file_dev_ino(mother_sock) {
        if nested_id == mother_id {
            return false;
        }
    }
    let Ok(scoped) = scoped_host_processes_from(proc_root, pid, 20_000) else {
        return false;
    };
    scoped.iter().any(|(_, _, comm)| comm == "dockerd")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasarRemediationItem {
    pub kind: String,
    pub target: String,
    pub status: String,
}

impl PasarRemediationItem {
    pub fn new(kind: impl Into<String>, target: impl Into<String>, status: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            target: target.into(),
            status: status.into(),
        }
    }

    pub fn to_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.str("kind", &self.kind);
        b.str("target", &self.target);
        b.str("status", &self.status);
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasarAlert {
    pub alert_type: String,
    pub severity: String,
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub instance_id: String,
    pub title: String,
    pub message: String,
    pub attempted: bool,
    pub succeeded: bool,
    pub items: Vec<PasarRemediationItem>,
    pub value: usize,
    pub threshold: usize,
    pub observed_at: i64,
}

impl PasarAlert {
    pub fn to_json(&self) -> String {
        let items_json: Vec<String> = self.items.iter().map(PasarRemediationItem::to_json).collect();
        let mut rem = JsonBuilder::new();
        rem.bool("attempted", self.attempted);
        rem.bool("succeeded", self.succeeded);
        rem.raw("items", &format!("[{}]", items_json.join(",")));

        let mut b = JsonBuilder::new();
        b.str("type", &self.alert_type);
        b.str("severity", &self.severity);
        b.str("runtime", &self.runtime);
        b.str("project", &self.project);
        b.str("container_name", &self.container_name);
        b.str("instance_id", &self.instance_id);
        b.str("title", &self.title);
        b.str("message", &self.message);
        b.raw("automatic_remediation", &rem.finish());
        b.usize("value", self.value);
        b.usize("threshold", self.threshold);
        b.i64("observed_at", self.observed_at);
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasarContainerTarget {
    pub runtime: String,
    pub project: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasarContainerSnapshot {
    pub instance_id: String,
    pub epoch: String,
    pub pid: u32,
}

/// Trait abstracting host/guest introspection and remediation commands for `PasarGuardMonitor`.
pub trait PasarGuardBackend {
    fn snapshot(&mut self, container: &PasarContainerTarget) -> Result<PasarContainerSnapshot, String>;
    fn podman_bin(&self) -> Option<String>;
    fn run_host(&mut self, args: &[String]) -> (bool, String);
    fn guest_exec(&mut self, container: &PasarContainerTarget, script: &str) -> (bool, String);
    fn find_native_matches(&mut self, pid: u32) -> Vec<PasarFinding> {
        native_matches(pid)
    }
    fn has_private_docker(&mut self, pid: u32) -> bool {
        private_docker(pid)
    }
    fn emit_event(&mut self, _container: &PasarContainerTarget, _alert: &PasarAlert) {}
}

fn parse_nested_removed_count(output: &str) -> Option<u32> {
    for line in output.lines() {
        if let Some(rest) = line.trim().strip_prefix("NW_PASAR_REMOVED=") {
            if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
                return rest.parse::<u32>().ok();
            }
        }
    }
    None
}

/// Stateful monitor for PasarGuard Node detection, surgical removal, and alert retention.
#[derive(Debug, Default, Clone)]
pub struct PasarGuardMonitor {
    results: BTreeMap<(String, String, String), PasarAlert>,
}

impl PasarGuardMonitor {
    pub fn new() -> Self {
        Self {
            results: BTreeMap::new(),
        }
    }

    pub fn is_enabled_from_env() -> bool {
        env_bool_enabled("SECURITY_PASARGUARD_BAN_ENABLED", true)
            && env_bool_enabled("SECURITY_MONITOR_ENABLED", true)
    }

    /// Scans and remediates a slice of containers, updating active alerts and pruning expired state.
    pub fn scan_containers(
        &mut self,
        targets: &[PasarContainerTarget],
        backend: &mut dyn PasarGuardBackend,
        now_unix: i64,
    ) {
        for container in targets {
            let rt = container.runtime.trim().to_ascii_lowercase();
            if !matches!(rt.as_str(), "incus" | "podman" | "runman")
                || PROTECTED_CONTAINERS.contains(&container.name.as_str())
            {
                continue;
            }
            let key = (
                rt.clone(),
                container.project.clone(),
                container.name.clone(),
            );
            let mut identity = String::new();
            let mut receipt: Vec<PasarRemediationItem> = Vec::new();
            let mut confirmed = false;

            let step = (|| -> Result<bool, String> {
                let snap = backend.snapshot(container)?;
                identity = snap.instance_id.clone();

                if rt == "podman" {
                    if let Some(bin) = backend.podman_bin() {
                        let inspect_args = vec![
                            bin.clone(),
                            "inspect".to_string(),
                            "--format".to_string(),
                            "{{.ImageName}}".to_string(),
                            identity.clone(),
                        ];
                        let (ok, image) = backend.run_host(&inspect_args);
                        if ok && image_match(image.trim()) {
                            confirmed = true;
                            for args in [
                                vec![
                                    bin.clone(),
                                    "update".to_string(),
                                    "--restart=no".to_string(),
                                    identity.clone(),
                                ],
                                vec![
                                    bin,
                                    "stop".to_string(),
                                    "--time".to_string(),
                                    "10".to_string(),
                                    identity.clone(),
                                ],
                            ] {
                                let (success, _) = backend.run_host(&args);
                                if !success {
                                    return Err("exact Podman service cleanup failed".to_string());
                                }
                            }
                            receipt.push(PasarRemediationItem::new("service", &identity, "ok"));
                        }
                    }
                }

                if receipt.is_empty() {
                    let matches = backend.find_native_matches(snap.pid);
                    confirmed = !matches.is_empty();
                    for finding in &matches {
                        let fresh = backend.snapshot(container)?;
                        if fresh.instance_id != identity || fresh.epoch != snap.epoch {
                            return Err("instance changed".to_string());
                        }
                        let script = cleanup_script(finding)?;
                        let (ok, _) = backend.guest_exec(container, &script);
                        let target = if !finding.unit.is_empty() {
                            finding.unit.clone()
                        } else {
                            finding.executable.clone()
                        };
                        receipt.push(PasarRemediationItem::new(
                            "service",
                            target,
                            if ok { "ok" } else { "failed" },
                        ));
                    }

                    let fresh = backend.snapshot(container)?;
                    if fresh.instance_id != identity || fresh.epoch != snap.epoch {
                        return Err("instance changed".to_string());
                    }

                    let (ok, output) = if backend.has_private_docker(snap.pid) {
                        backend.guest_exec(container, nested_script())
                    } else {
                        (true, "NW_PASAR_REMOVED=0".to_string())
                    };
                    if ok {
                        if let Some(removed) = parse_nested_removed_count(&output) {
                            if removed > 0 {
                                confirmed = true;
                                receipt.push(PasarRemediationItem::new(
                                    "service",
                                    "pasarguard/node",
                                    "ok",
                                ));
                            }
                        }
                    }

                    if !matches.is_empty() && !backend.find_native_matches(snap.pid).is_empty() {
                        receipt.push(PasarRemediationItem::new(
                            "service",
                            "pasarguard-node-surviving-process",
                            "failed",
                        ));
                    }

                    if !confirmed {
                        return Ok(false);
                    }
                }

                Ok(true)
            })();

            match step {
                Ok(true) => {
                    let cleaned = !receipt.is_empty()
                        && receipt.iter().all(|item| item.status == "ok");
                    let value = receipt.len();
                    let alert = PasarAlert {
                        alert_type: "pasarguard_node_removed".to_string(),
                        severity: "critical".to_string(),
                        runtime: rt,
                        project: container.project.clone(),
                        container_name: container.name.clone(),
                        instance_id: identity,
                        title: format!(
                            "禁止运行 PasarGuard Node：{}",
                            if cleaned { "已清理服务" } else { "清理失败" }
                        ),
                        message: if cleaned {
                            "已停止并移除确认归属的 PasarGuard Node 服务；未删除客户实例或磁盘。"
                                .to_string()
                        } else {
                            "PasarGuard Node 清理未全部成功，需管理员处理。".to_string()
                        },
                        attempted: true,
                        succeeded: cleaned,
                        items: receipt,
                        value,
                        threshold: 0,
                        observed_at: now_unix,
                    };
                    backend.emit_event(container, &alert);
                    self.results.insert(key, alert);
                }
                Ok(false) => {}
                Err(_) => {
                    if confirmed {
                        let alert = PasarAlert {
                            alert_type: "pasarguard_node_removed".to_string(),
                            severity: "critical".to_string(),
                            runtime: rt,
                            project: container.project.clone(),
                            container_name: container.name.clone(),
                            instance_id: identity,
                            title: "PasarGuard Node 清理未完成".to_string(),
                            message: "已确认禁止服务，但执行或复查失败，需要管理员处理。"
                                .to_string(),
                            attempted: true,
                            succeeded: false,
                            items: receipt,
                            value: 1,
                            threshold: 0,
                            observed_at: now_unix,
                        };
                        backend.emit_event(container, &alert);
                        self.results.insert(key, alert);
                    }
                }
            }
        }

        self.results
            .retain(|_, v| now_unix.saturating_sub(v.observed_at) <= PASARGUARD_STATE_RETENTION_SECS);
    }

    /// Returns active alerts for `(runtime, project, name)` within the 900s freshness window.
    pub fn alerts(&self, runtime: &str, project: &str, name: &str) -> Vec<PasarAlert> {
        self.alerts_at(runtime, project, name, current_unix_secs())
    }

    pub fn alerts_at(
        &self,
        runtime: &str,
        project: &str,
        name: &str,
        now_unix: i64,
    ) -> Vec<PasarAlert> {
        let key = (
            runtime.trim().to_ascii_lowercase(),
            project.to_string(),
            name.to_string(),
        );
        if let Some(alert) = self.results.get(&key) {
            if now_unix.saturating_sub(alert.observed_at) < PASARGUARD_ALERT_TTL_SECS {
                return vec![alert.clone()];
            }
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_drivers::JsonVal;
    use std::env;

    fn encode_uvarint(mut n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while n >= 0x80 {
            out.push(((n as u8) & 0x7f) | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
        out
    }

    fn build_synthetic_elf(is_64: bool, little_endian: bool, mod_info: &[u8], with_sentinels: bool) -> Vec<u8> {
        let put_u16 = |buf: &mut [u8], off: usize, v: u16| {
            let b = if little_endian { v.to_le_bytes() } else { v.to_be_bytes() };
            buf[off..off + 2].copy_from_slice(&b);
        };
        let put_u32 = |buf: &mut [u8], off: usize, v: u32| {
            let b = if little_endian { v.to_le_bytes() } else { v.to_be_bytes() };
            buf[off..off + 4].copy_from_slice(&b);
        };
        let put_u64 = |buf: &mut [u8], off: usize, v: u64| {
            let b = if little_endian { v.to_le_bytes() } else { v.to_be_bytes() };
            buf[off..off + 8].copy_from_slice(&b);
        };

        let shstrtab = b"\0.shstrtab\0.go.buildinfo\0";
        let shstr_name_off = 1u32;
        let buildinfo_name_off = 11u32;

        let mut buildinfo = Vec::new();
        buildinfo.extend_from_slice(b"\xff Go buildinf:");
        buildinfo.push(8); // ptrSize
        buildinfo.push(2); // endianness bit 2 (inline strings)
        buildinfo.resize(32, 0);
        let go_ver = b"go1.22.5";
        buildinfo.extend_from_slice(&encode_uvarint(go_ver.len()));
        buildinfo.extend_from_slice(go_ver);

        let mut framed_mod = Vec::new();
        if with_sentinels {
            framed_mod.extend_from_slice(b"0123456789abcdef");
            framed_mod.extend_from_slice(mod_info);
            if !framed_mod.ends_with(b"\n") {
                framed_mod.push(b'\n');
            }
            framed_mod.extend_from_slice(b"fedcba9876543210");
        } else {
            framed_mod.extend_from_slice(mod_info);
        }
        buildinfo.extend_from_slice(&encode_uvarint(framed_mod.len()));
        buildinfo.extend_from_slice(&framed_mod);

        let ehdr_size = 64usize;
        let shstr_off = ehdr_size;
        let buildinfo_off = shstr_off + shstrtab.len();
        let shoff = buildinfo_off + buildinfo.len();
        let shentsize = if is_64 { 64usize } else { 40usize };
        let shnum = 3usize;
        let shstrndx = 1usize;

        let mut out = vec![0u8; shoff + shentsize * shnum];
        out[0..4].copy_from_slice(b"\x7fELF");
        out[4] = if is_64 { 2 } else { 1 };
        out[5] = if little_endian { 1 } else { 2 };
        if is_64 {
            put_u64(&mut out, 40, shoff as u64);
            put_u16(&mut out, 58, shentsize as u16);
            put_u16(&mut out, 60, shnum as u16);
            put_u16(&mut out, 62, shstrndx as u16);
        } else {
            put_u32(&mut out, 32, shoff as u32);
            put_u16(&mut out, 46, shentsize as u16);
            put_u16(&mut out, 48, shnum as u16);
            put_u16(&mut out, 50, shstrndx as u16);
        }

        out[shstr_off..shstr_off + shstrtab.len()].copy_from_slice(shstrtab);
        out[buildinfo_off..buildinfo_off + buildinfo.len()].copy_from_slice(&buildinfo);

        // Section 1: .shstrtab
        let s1 = shoff + shentsize;
        put_u32(&mut out, s1, shstr_name_off);
        if is_64 {
            put_u64(&mut out, s1 + 24, shstr_off as u64);
            put_u64(&mut out, s1 + 32, shstrtab.len() as u64);
        } else {
            put_u32(&mut out, s1 + 16, shstr_off as u32);
            put_u32(&mut out, s1 + 20, shstrtab.len() as u32);
        }

        // Section 2: .go.buildinfo
        let s2 = shoff + 2 * shentsize;
        put_u32(&mut out, s2, buildinfo_name_off);
        if is_64 {
            put_u64(&mut out, s2 + 24, buildinfo_off as u64);
            put_u64(&mut out, s2 + 32, buildinfo.len() as u64);
        } else {
            put_u32(&mut out, s2 + 16, buildinfo_off as u32);
            put_u32(&mut out, s2 + 20, buildinfo.len() as u32);
        }

        out
    }

    #[test]
    fn test_exact_images_and_digest() {
        for image in [
            "pasarguard/node",
            "pasarguard/node:latest",
            "pasarguard/node@sha256:abc",
            "docker.io/pasarguard/node:v1.2",
            "ghcr.io/pasarguard/node:v1@sha256:abc",
        ] {
            assert!(image_match(image), "expected match for {image}");
        }
        for image in [
            "main",
            "node",
            "xray",
            "evil/pasarguard/node",
            "pasarguard/node-backup",
            "example.com/pasarguard/node",
            "localhost:5000/pasarguard/node",
        ] {
            assert!(!image_match(image), "expected non-match for {image}");
        }
    }

    #[test]
    fn test_elf_go_buildinfo_parser_elf32_elf64_le_be_and_sentinels() {
        let dir = env::temp_dir().join(format!("narwhal-elf-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mod_payload = b"path\tgithub.com/pasarguard/node/cmd/node\nmod\tgithub.com/pasarguard/node\t(devel)\n";
        for (is_64, le, sentinels) in [
            (true, true, true),
            (true, false, true),
            (false, true, false),
            (false, false, true),
        ] {
            let bin_path = dir.join(format!("node_{is_64}_{le}_{sentinels}"));
            let bytes = build_synthetic_elf(is_64, le, mod_payload, sentinels);
            fs::write(&bin_path, &bytes).unwrap();
            assert_eq!(
                go_module(&bin_path).as_deref(),
                Some("github.com/pasarguard/node/cmd/node")
            );
        }

        // Unrelated Go binary must return None
        let other_path = dir.join("other_go");
        let other_bytes = build_synthetic_elf(
            true,
            true,
            b"path\tgithub.com/xtls/xray-core/main\n",
            true,
        );
        fs::write(&other_path, &other_bytes).unwrap();
        assert_eq!(go_module(&other_path), None);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cleanup_script_validation_and_safety() {
        let finding = PasarFinding {
            pid: 42,
            host_pid: 9001,
            start_ticks: "123".to_string(),
            executable: "/app/main".to_string(),
            unit: "pg-node.service".to_string(),
            module: PASARGUARD_MODULE.to_string(),
        };
        let text = cleanup_script(&finding).expect("valid cleanup script");
        assert!(text.contains("expected=123"));
        assert!(text.contains("readlink /proc/$p/exe"));
        for forbidden in ["pkill", "killall", "rm -rf", "compose down", "incus delete"] {
            assert!(!text.contains(forbidden));
        }

        // PID 1 must be rejected
        let mut bad_pid = finding.clone();
        bad_pid.pid = 1;
        assert!(cleanup_script(&bad_pid).is_err());

        // Traversal path must be rejected
        let mut bad_exe = finding.clone();
        bad_exe.executable = "/app/../etc/passwd".to_string();
        assert!(cleanup_script(&bad_exe).is_err());

        // Invalid unit must be rejected
        let mut bad_unit = finding;
        bad_unit.unit = "bad;rm.service".to_string();
        assert!(cleanup_script(&bad_unit).is_err());
    }

    struct MockPasarBackend {
        snapshot: PasarContainerSnapshot,
        findings_calls: Vec<Vec<PasarFinding>>,
        guest_calls: Vec<String>,
        emitted: Vec<PasarAlert>,
        private_docker: bool,
    }

    impl PasarGuardBackend for MockPasarBackend {
        fn snapshot(
            &mut self,
            _container: &PasarContainerTarget,
        ) -> Result<PasarContainerSnapshot, String> {
            Ok(self.snapshot.clone())
        }

        fn podman_bin(&self) -> Option<String> {
            None
        }

        fn run_host(&mut self, _args: &[String]) -> (bool, String) {
            (false, String::new())
        }

        fn guest_exec(&mut self, _container: &PasarContainerTarget, script: &str) -> (bool, String) {
            self.guest_calls.push(script.to_string());
            (true, String::new())
        }

        fn find_native_matches(&mut self, _pid: u32) -> Vec<PasarFinding> {
            if self.findings_calls.is_empty() {
                Vec::new()
            } else {
                self.findings_calls.remove(0)
            }
        }

        fn has_private_docker(&mut self, _pid: u32) -> bool {
            self.private_docker
        }

        fn emit_event(&mut self, _container: &PasarContainerTarget, alert: &PasarAlert) {
            self.emitted.push(alert.clone());
        }
    }

    #[test]
    fn test_runman_native_service_cleanup_uses_generation_bound_guest_exec() {
        let vm_id = "11111111-2222-3333-4444-555555555555";
        let generation = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let container = PasarContainerTarget {
            runtime: "runman".to_string(),
            project: "default".to_string(),
            name: vm_id.to_string(),
        };
        let finding = PasarFinding {
            pid: 77,
            host_pid: 9001,
            start_ticks: "123456".to_string(),
            executable: "/app/node".to_string(),
            unit: "pg-node.service".to_string(),
            module: PASARGUARD_MODULE.to_string(),
        };
        let mut backend = MockPasarBackend {
            snapshot: PasarContainerSnapshot {
                instance_id: generation.to_string(),
                epoch: "boot:net:4242".to_string(),
                pid: 4242,
            },
            findings_calls: vec![vec![finding], vec![]],
            guest_calls: Vec::new(),
            emitted: Vec::new(),
            private_docker: false,
        };

        let mut monitor = PasarGuardMonitor::new();
        monitor.scan_containers(&[container], &mut backend, 1000);

        assert_eq!(backend.emitted.len(), 1);
        assert_eq!(backend.guest_calls.len(), 1);
        let alert = &backend.emitted[0];
        assert_eq!(alert.runtime, "runman");
        assert_eq!(alert.instance_id, generation);
        assert!(alert.succeeded);

        let active = monitor.alerts_at("runman", "default", vm_id, 1500);
        assert_eq!(active.len(), 1);
        let parsed = JsonVal::parse(&active[0].to_json()).unwrap();
        assert_eq!(parsed.get_str("type"), Some("pasarguard_node_removed"));
        assert_eq!(
            parsed
                .get("automatic_remediation")
                .and_then(|r| r.get_bool("succeeded")),
            Some(true)
        );

        // Expired after 900s
        assert!(monitor.alerts_at("runman", "default", vm_id, 1901).is_empty());
    }

    #[test]
    fn test_native_matches_from_and_private_docker_from() {
        let dir = env::temp_dir().join(format!("narwhal-pasar-proc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let proc_root = dir.join("proc");

        // Init PID 100
        let init_dir = proc_root.join("100");
        fs::create_dir_all(init_dir.join("ns")).unwrap();
        fs::write(init_dir.join("ns").join("pid"), "1:4026532100").unwrap();
        fs::write(init_dir.join("cgroup"), "0::/machine.slice/ct-100.scope\n").unwrap();
        fs::write(init_dir.join("status"), "Name:\tinit\nNSpid:\t100\t1\n").unwrap();
        fs::write(init_dir.join("comm"), "systemd\n").unwrap();

        // PasarGuard process host PID 555 -> inner PID 42
        let p_dir = proc_root.join("555");
        fs::create_dir_all(p_dir.join("ns")).unwrap();
        #[cfg(unix)]
        fs::hard_link(init_dir.join("ns").join("pid"), p_dir.join("ns").join("pid")).unwrap();
        #[cfg(not(unix))]
        fs::write(p_dir.join("ns").join("pid"), "1:4026532100").unwrap();
        fs::write(
            p_dir.join("cgroup"),
            "0::/machine.slice/ct-100.scope/system.slice/pg-node.service\n",
        )
        .unwrap();
        fs::write(p_dir.join("status"), "Name:\tnode\nNSpid:\t555\t42\n").unwrap();
        fs::write(p_dir.join("comm"), "node\n").unwrap();
        fs::write(p_dir.join("cmdline"), b"/app/node\0--config\0/app/cfg.yml\0").unwrap();
        fs::write(p_dir.join("exe_link"), "/app/node (deleted)\n").unwrap();
        let fields = std::iter::once("S")
            .chain(std::iter::repeat("0").take(18))
            .chain(std::iter::once("987654"))
            .collect::<Vec<&str>>()
            .join(" ");
        fs::write(p_dir.join("stat"), format!("555 (node) {fields}\n")).unwrap();
        let elf_bytes = build_synthetic_elf(
            true,
            true,
            b"path\tgithub.com/pasarguard/node/cmd/node\n",
            true,
        );
        fs::write(p_dir.join("exe"), &elf_bytes).unwrap();

        let matches = native_matches_from(&proc_root, 100);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pid, 42);
        assert_eq!(matches[0].host_pid, 555);
        assert_eq!(matches[0].start_ticks, "987654");
        assert_eq!(matches[0].executable, "/app/node");
        assert_eq!(matches[0].unit, "pg-node.service");
        assert_eq!(matches[0].module, PASARGUARD_MODULE);

        let _ = fs::remove_dir_all(&dir);
    }
}
