#!/usr/bin/env python3
"""Fetch and safely extract immutable GitHub source archives for Agent updates."""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


OWNER = "podcctv"
REPOSITORY = "Narwhal-Cloud-podman-watcher"
API_COMMIT = f"https://api.github.com/repos/{OWNER}/{REPOSITORY}/commits/main"
ATOM_COMMITS = f"https://github.com/{OWNER}/{REPOSITORY}/commits/main.atom"
RAW_VERSION = f"https://raw.githubusercontent.com/{OWNER}/{REPOSITORY}/main/VERSION"
ARCHIVE_BASE = f"https://codeload.github.com/{OWNER}/{REPOSITORY}/tar.gz/"
TREE_BASE = f"https://api.github.com/repos/{OWNER}/{REPOSITORY}/git/trees/"
RAW_COMMIT_BASE = f"https://raw.githubusercontent.com/{OWNER}/{REPOSITORY}/"
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 20000
MAX_TREE_BYTES = 8 * 1024 * 1024
MAX_CLIENT_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_CLIENT_FILES = 2000
MAX_CLIENT_FILE_BYTES = 16 * 1024 * 1024
CLIENT_REQUIRED_FILES = (
    "VERSION",
    "client/agent.py",
    "client/requirements.txt",
    "scripts/install-client.sh",
    "scripts/lib/interactive.sh",
    "scripts/bootstrap-client-ca.py",
    "scripts/check-server-version.py",
    "scripts/self-uninstall-client.sh",
    "scripts/setup-auto-update.sh",
    "scripts/managed-client-update.sh",
    "scripts/update_archive.py",
)


def _read_url(url: str, *, timeout: int = 15, limit: int = 2 * 1024 * 1024) -> bytes:
    request = Request(url, headers={"User-Agent": "Narwhal-Cloud-podman-watcher-updater/1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise RuntimeError(f"source returned HTTP {response.status}")
            data = response.read(limit + 1)
    except HTTPError as exc:
        exc.close()
        raise
    if len(data) > limit:
        raise RuntimeError("source response exceeded the size limit")
    return data


def _read_url_retry(url: str, *, timeout: int, limit: int, attempts: int = 3) -> bytes:
    last_error: Exception | None = None
    for attempt in range(max(1, attempts)):
        try:
            return _read_url(url, timeout=timeout, limit=limit)
        except HTTPError as exc:
            if exc.code not in {408, 425, 429, 500, 502, 503, 504}:
                raise
            last_error = exc
        except (OSError, URLError) as exc:
            last_error = exc
        if attempt + 1 < max(1, attempts):
            time.sleep(min(4, 2**attempt))
    if last_error:
        raise last_error
    raise RuntimeError("GitHub source request failed")


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


def _client_bundle_entries(payload: object) -> list[dict[str, object]]:
    """Validate and select the immutable Agent source files from a Git tree."""
    if not isinstance(payload, dict) or payload.get("truncated") is True:
        raise RuntimeError("GitHub source tree was invalid or truncated")
    tree = payload.get("tree")
    if not isinstance(tree, list):
        raise RuntimeError("GitHub source tree entries were unavailable")

    selected: list[dict[str, object]] = []
    seen: set[str] = set()
    total_size = 0
    for item in tree:
        if not isinstance(item, dict):
            raise RuntimeError("GitHub source tree entry was invalid")
        path = item.get("path")
        if not isinstance(path, str):
            raise RuntimeError("GitHub source tree path was invalid")
        if path != "VERSION" and not path.startswith(("client/", "scripts/")):
            continue
        posix_path = PurePosixPath(path)
        raw_parts = path.split("/")
        if (
            posix_path.is_absolute()
            or any(part in {"", ".", ".."} for part in raw_parts)
            or "\\" in path
            or not posix_path.parts
        ):
            raise RuntimeError("GitHub source tree contained an unsafe Agent path")

        # Recursive tree responses include directory entries. Only regular
        # blobs are accepted in the Agent bundle; symlinks and submodules are
        # deliberately not followed or materialized.
        if item.get("type") == "tree":
            continue
        if item.get("type") != "blob" or item.get("mode") not in {"100644", "100755"}:
            raise RuntimeError("GitHub Agent source contains an unsupported file type")
        if path in seen:
            raise RuntimeError("GitHub Agent source tree contains duplicate paths")
        seen.add(path)
        try:
            size = int(item.get("size", -1))
        except (TypeError, ValueError, OverflowError):
            size = -1
        if size < 0 or size > MAX_CLIENT_FILE_BYTES:
            raise RuntimeError("GitHub Agent source file size was invalid")
        total_size += size
        if total_size > MAX_CLIENT_BUNDLE_BYTES or len(selected) >= MAX_CLIENT_FILES:
            raise RuntimeError("GitHub Agent source bundle exceeded its safety limits")
        sha = item.get("sha")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise RuntimeError("GitHub Agent source blob hash was invalid")
        selected.append({"path": path, "mode": item["mode"], "size": size, "sha": sha})

    missing = sorted(set(CLIENT_REQUIRED_FILES) - seen)
    if missing:
        raise RuntimeError("GitHub Agent source tree is missing required files")
    return selected


def download_client_bundle(reference: str, destination: Path) -> None:
    """Fetch only Agent and installer files from a pinned commit via raw GitHub.

    Prefer the compact archive when reachable; fall back to pinned API/raw
    files when codeload is unavailable. Each fallback file is checked against
    its Git blob SHA and byte length from the API tree before it is staged.
    """
    if not REVISION_RE.fullmatch(reference):
        raise RuntimeError("Agent bundle reference must be an immutable commit SHA")
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise RuntimeError("Agent bundle destination must be empty")

    archive_error = ""
    try:
        download_archive(reference, destination)
        return
    except Exception as exc:
        archive_error = f"{type(exc).__name__}: {exc}"

    try:
        tree_data = _read_url_retry(
            TREE_BASE + reference + "?recursive=1",
            timeout=30,
            limit=MAX_TREE_BYTES,
        )
        payload = json.loads(tree_data.decode("utf-8", "strict"))
        entries = _client_bundle_entries(payload)

        def fetch(entry: dict[str, object]) -> tuple[dict[str, object], bytes]:
            path = str(entry["path"])
            encoded_path = quote(path, safe="/")
            data = _read_url_retry(
                RAW_COMMIT_BASE + reference + "/" + encoded_path,
                timeout=30,
                limit=int(entry["size"]),
            )
            if len(data) != int(entry["size"]):
                raise RuntimeError(f"Agent source size mismatch for {path}")
            header = b"blob " + str(len(data)).encode("ascii") + b"\0"
            digest = hashlib.sha1(header + data).hexdigest()
            if digest != entry["sha"]:
                raise RuntimeError(f"Agent source integrity check failed for {path}")
            return entry, data

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            for entry, data in pool.map(fetch, entries):
                relative = Path(*PurePosixPath(str(entry["path"])).parts)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output:
                    output.write(data)
                os.chmod(target, 0o755 if entry["mode"] == "100755" else 0o644)

        if any(not (destination / path).is_file() for path in CLIENT_REQUIRED_FILES):
            raise RuntimeError("downloaded Agent bundle is missing required project files")
        version = (destination / "VERSION").read_text(encoding="ascii").strip()
        if not VERSION_RE.fullmatch(version):
            raise RuntimeError("downloaded Agent bundle VERSION was not valid")
    except Exception as exc:
        shutil.rmtree(destination, ignore_errors=True)
        raw_error = f"{type(exc).__name__}: {exc}"
        raise RuntimeError(
            f"archive source failed ({archive_error}); pinned API/raw source failed ({raw_error})"
        ) from None


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
    parser.add_argument("command", choices=("resolve", "version", "download", "download-client"))
    parser.add_argument("reference", nargs="?")
    parser.add_argument("destination", nargs="?")
    args = parser.parse_args()
    try:
        if args.command == "resolve":
            print(resolve_main_revision())
        elif args.command == "version":
            print(resolve_main_version())
        elif args.command == "download-client":
            if args.reference is None or args.destination is None:
                parser.error("download-client requires a reference and destination")
            download_client_bundle(args.reference, Path(args.destination))
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
