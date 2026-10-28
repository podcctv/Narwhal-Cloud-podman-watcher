#!/usr/bin/env python3
"""Fetch and safely extract immutable GitHub source archives for Agent updates."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from urllib.error import URLError
from urllib.request import Request, urlopen


OWNER = "podcctv"
REPOSITORY = "Narwhal-Cloud-podman-watcher"
API_COMMIT = f"https://api.github.com/repos/{OWNER}/{REPOSITORY}/commits/main"
ATOM_COMMITS = f"https://github.com/{OWNER}/{REPOSITORY}/commits/main.atom"
RAW_VERSION = f"https://raw.githubusercontent.com/{OWNER}/{REPOSITORY}/main/VERSION"
ARCHIVE_BASE = f"https://codeload.github.com/{OWNER}/{REPOSITORY}/tar.gz/"
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 20000


def _read_url(url: str, *, timeout: int = 15, limit: int = 2 * 1024 * 1024) -> bytes:
    request = Request(url, headers={"User-Agent": "Narwhal-Cloud-podman-watcher-updater/1"})
    with urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"source returned HTTP {response.status}")
        data = response.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError("source response exceeded the size limit")
    return data


def resolve_main_revision() -> str:
    try:
        atom = _read_url(ATOM_COMMITS, timeout=8, limit=1024 * 1024).decode("utf-8", "strict")
        match = re.search(r"[0-9a-f]{40}", atom)
        if match:
            return match.group(0)
    except (OSError, UnicodeError, RuntimeError, URLError):
        pass

    payload = json.loads(_read_url(API_COMMIT, timeout=20, limit=1024 * 1024))
    revision = payload.get("sha") if isinstance(payload, dict) else None
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise RuntimeError("GitHub main revision was not valid")
    return revision


def resolve_main_version() -> str:
    version = _read_url(RAW_VERSION, timeout=15, limit=128).decode("ascii", "strict").strip()
    if not VERSION_RE.fullmatch(version):
        raise RuntimeError("GitHub main VERSION was not valid")
    return version


def download_archive(reference: str, destination: Path) -> None:
    if not REVISION_RE.fullmatch(reference):
        raise RuntimeError("archive reference must be an immutable commit SHA")
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise RuntimeError("archive destination must be empty")
    destination.mkdir(parents=True, exist_ok=True)

    request = Request(
        ARCHIVE_BASE + reference,
        headers={"User-Agent": "Narwhal-Cloud-podman-watcher-updater/1"},
    )
    fd, archive_name = tempfile.mkstemp(prefix="narwhal-source-", suffix=".tar.gz", dir=str(destination.parent))
    os.close(fd)
    archive_path = Path(archive_name)
    try:
        total_downloaded = 0
        with urlopen(request, timeout=120) as response, archive_path.open("wb") as output:
            if response.status != 200:
                raise RuntimeError(f"source archive returned HTTP {response.status}")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total_downloaded += len(chunk)
                if total_downloaded > MAX_ARCHIVE_BYTES:
                    raise RuntimeError("source archive exceeded the download size limit")
                output.write(chunk)

        _extract_safe(archive_path, destination, reference)
        required = (
            destination / "VERSION",
            destination / "scripts" / "install-client.sh",
            destination / "scripts" / "install-server.sh",
            destination / "scripts" / "auto-update.sh",
            destination / "scripts" / "update_archive.py",
        )
        if any(not path.is_file() for path in required):
            raise RuntimeError("source archive is missing required project files")
        version = (destination / "VERSION").read_text(encoding="ascii").strip()
        if not VERSION_RE.fullmatch(version):
            raise RuntimeError("source archive VERSION was not valid")
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    finally:
        archive_path.unlink(missing_ok=True)


def _extract_safe(archive_path: Path, destination: Path, expected_revision: str) -> None:
    if not REVISION_RE.fullmatch(expected_revision):
        raise RuntimeError("expected archive revision was invalid")
    total_bytes = 0
    seen_files: set[Path] = set()
    root_name: str | None = None
    allowed_roots = {f"{REPOSITORY}-{expected_revision}", f"{REPOSITORY}-{expected_revision[:7]}"}
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = archive.getmembers()
        if not members or len(members) > MAX_MEMBERS:
            raise RuntimeError("source archive member count was invalid")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or "\\" in member.name or not path.parts:
                raise RuntimeError("source archive contained an unsafe path")
            if root_name is None:
                root_name = path.parts[0]
                if root_name not in allowed_roots:
                    raise RuntimeError("source archive root did not match the pinned revision")
            elif path.parts[0] != root_name:
                raise RuntimeError("source archive contained multiple roots")
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise RuntimeError("source archive contained an unsupported file type")
            relative_parts = path.parts[1:]
            if not relative_parts:
                continue
            relative = Path(*relative_parts)
            target = destination / relative
            if member.isfile():
                total_bytes += member.size
                if total_bytes > MAX_EXPANDED_BYTES or relative in seen_files:
                    raise RuntimeError("source archive size or duplicate file check failed")
                seen_files.add(relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise RuntimeError("source archive file data was unavailable")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                # Preserve executable bits required by project scripts while
                # stripping group/other write and setuid/setgid permissions.
                os.chmod(target, member.mode & 0o755)
            else:
                target.mkdir(parents=True, exist_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("resolve", "version", "download"))
    parser.add_argument("reference", nargs="?")
    parser.add_argument("destination", nargs="?")
    args = parser.parse_args()
    try:
        if args.command == "resolve":
            print(resolve_main_revision())
        elif args.command == "version":
            print(resolve_main_version())
        else:
            if args.reference is None or args.destination is None:
                parser.error("download requires a reference and destination")
            download_archive(args.reference, Path(args.destination))
    except Exception as exc:
        print(f"archive update failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
