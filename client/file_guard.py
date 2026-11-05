"""Overlay & Procfs Sensitive Executable Dropper Sensor for Containers.

Monitors sensitive container directories (/tmp, /dev/shm, /var/tmp)
for newly dropped ELF binaries, cryptocurrency miners (XMRig), and suspicious
executable droppers before command-and-control communication is established.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

SENSITIVE_DIRS = ("/tmp", "/dev/shm", "/var/tmp")
MAX_FILES_PER_DIR = 30
MAX_SCAN_DEPTH = 2
MAX_READ_BYTES = 8 * 1024 * 1024  # 8MB


def _is_elf(head: bytes) -> bool:
    return head.startswith(b"\x7fELF")


def _is_shebang(head: bytes) -> bool:
    return head.startswith(b"#!")


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
                if f.tell() > MAX_READ_BYTES:
                    break
        return h.hexdigest()
    except Exception:
        return ""


def scan_container_sensitive_drops(
    pid: int,
    runtime: str = "runman",
    name: str = "",
    proc_root: str = "/proc",
) -> list[dict[str, Any]]:
    """Scan container /tmp, /dev/shm, /var/tmp for suspicious executable droppers."""
    if pid <= 1:
        return []

    container_root = Path(proc_root) / str(pid) / "root"
    if not container_root.exists():
        return []

    suspicious_events: list[dict[str, Any]] = []

    for rel_dir in SENSITIVE_DIRS:
        target_dir = container_root / rel_dir.lstrip("/")
        if not target_dir.is_dir():
            continue

        try:
            # Bounded walk up to MAX_SCAN_DEPTH
            files_scanned = 0
            for root, dirs, files in os.walk(str(target_dir)):
                # Depth limit
                rel_depth = os.path.relpath(root, str(target_dir)).count(os.sep)
                if rel_depth >= MAX_SCAN_DEPTH:
                    dirs.clear()
                    continue

                for fname in files:
                    if files_scanned >= MAX_FILES_PER_DIR:
                        break
                    files_scanned += 1

                    full_path = os.path.join(root, fname)
                    try:
                        st = os.lstat(full_path)
                    except OSError:
                        continue

                    # Skip non-regular files and symlinks for safety
                    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                        continue

                    is_exec = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                    is_hidden = fname.startswith(".")

                    # Read first 512 bytes for magic inspection
                    try:
                        with open(full_path, "rb") as f:
                            head = f.read(512)
                    except OSError:
                        continue

                    is_binary_elf = _is_elf(head)
                    is_script = _is_shebang(head)

                    # Trigger alert if:
                    # 1. File is an ELF binary dropped in /tmp or /dev/shm
                    # 2. File is an executable script with shebang (#!/bin/sh, etc.)
                    # 3. File is executable (+x)
                    # 4. File is a hidden file with executable or script content
                    if is_binary_elf or is_script or (is_exec and st.st_size > 0) or (is_hidden and (is_exec or is_script)):
                        container_path = "/" + os.path.relpath(full_path, str(container_root)).replace("\\", "/")
                        file_sha256 = _hash_file(full_path)
                        suspicious_events.append({
                            "path": container_path,
                            "filename": fname,
                            "size_bytes": st.st_size,
                            "mtime": int(st.st_mtime),
                            "mode_octal": oct(st.st_mode & 0o777),
                            "is_elf": is_binary_elf,
                            "is_executable": is_exec,
                            "is_hidden": is_hidden,
                            "sha256_prefix": file_sha256[:16] if file_sha256 else "",
                            "sha256": file_sha256,
                            "threat_score": 90 if is_binary_elf else (70 if is_exec else 40),
                        })
        except Exception:
            continue

    return suspicious_events
