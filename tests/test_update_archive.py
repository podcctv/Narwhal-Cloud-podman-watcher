import io
import hashlib
import json
import os
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from scripts import update_archive


class UpdateArchiveTests(unittest.TestCase):
    revision = "a" * 40
    archive_root = f"Narwhal-Cloud-podman-watcher-{revision}"

    def make_archive(self, archive_path, entries):
        with tarfile.open(archive_path, "w:gz") as archive:
            for name, kind, payload in entries:
                item = tarfile.TarInfo(name)
                if kind == "file":
                    data = payload.encode("utf-8")
                    item.size = len(data)
                    item.mode = 0o755
                    archive.addfile(item, io.BytesIO(data))
                elif kind == "symlink":
                    item.type = tarfile.SYMTYPE
                    item.linkname = payload
                    archive.addfile(item)
                elif kind == "directory":
                    item.type = tarfile.DIRTYPE
                    archive.addfile(item)

    def test_extracts_only_project_root_and_preserves_executable_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive_path, destination = root / "source.tar.gz", root / "out"
            self.make_archive(archive_path, [
                (self.archive_root + "/", "directory", ""),
                (self.archive_root + "/scripts/", "directory", ""),
                (self.archive_root + "/scripts/install.sh", "file", "#!/bin/sh\n"),
            ])
            update_archive._extract_safe(archive_path, destination, self.revision)
            self.assertEqual((destination / "scripts" / "install.sh").read_text(), "#!/bin/sh\n")
            if os.name != "nt":
                self.assertEqual((destination / "scripts" / "install.sh").stat().st_mode & 0o777, 0o755)

    def test_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive_path, destination = root / "source.tar.gz", root / "out"
            self.make_archive(archive_path, [(self.archive_root + "/../escape", "file", "bad")])
            with self.assertRaisesRegex(RuntimeError, "unsafe path"):
                update_archive._extract_safe(archive_path, destination, self.revision)
            self.assertFalse((root / "escape").exists())

    def test_rejects_links_and_multiple_roots(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive_path, destination = root / "source.tar.gz", root / "out"
            self.make_archive(archive_path, [(self.archive_root + "/link", "symlink", "/etc/passwd")])
            with self.assertRaisesRegex(RuntimeError, "unsupported file type"):
                update_archive._extract_safe(archive_path, destination, self.revision)
            self.make_archive(archive_path, [
                (self.archive_root + "/VERSION", "file", "1.7.0"),
                ("other-root/VERSION", "file", "1.7.0"),
            ])
            with self.assertRaisesRegex(RuntimeError, "multiple roots"):
                update_archive._extract_safe(archive_path, destination, self.revision)

    def test_client_tree_rejects_unsafe_paths_and_non_regular_files(self):
        valid = {
            "truncated": False,
            "tree": [
                {"path": "VERSION", "mode": "100644", "type": "blob", "size": 5, "sha": "a" * 40},
                {"path": "client/agent.py", "mode": "120000", "type": "blob", "size": 1, "sha": "b" * 40},
            ],
        }
        with self.assertRaisesRegex(RuntimeError, "unsupported file type"):
            update_archive._client_bundle_entries(valid)
        valid["tree"][1]["mode"] = "100644"
        valid["tree"].append({"path": "scripts/../outside", "mode": "100644", "type": "blob", "size": 1, "sha": "c" * 40})
        with self.assertRaisesRegex(RuntimeError, "unsafe Agent path"):
            update_archive._client_bundle_entries(valid)

    def test_transient_github_source_error_is_retried(self):
        calls = []

        def read_url(url, *, timeout, limit):
            calls.append(url)
            if len(calls) == 1:
                raise OSError("temporary connection reset")
            return b"ok"

        with patch.object(update_archive, "_read_url", side_effect=read_url), patch.object(update_archive.time, "sleep"):
            self.assertEqual(update_archive._read_url_retry("https://example.invalid/pinned", timeout=1, limit=8), b"ok")
        self.assertEqual(len(calls), 2)

    def test_downloads_pinned_client_tree_and_checks_blob_hashes(self):
        contents = {}
        files = set(update_archive.CLIENT_REQUIRED_FILES)
        files.update({"client/security_banner.py", "scripts/lib/extra.sh"})
        entries = []
        for path in sorted(files):
            data = b"1.7.0\n" if path == "VERSION" else ("# " + path + "\n").encode()
            header = b"blob " + str(len(data)).encode("ascii") + b"\0"
            digest = hashlib.sha1(header + data).hexdigest()
            mode = "100755" if path.endswith(".sh") else "100644"
            entries.append({"path": path, "mode": mode, "type": "blob", "size": len(data), "sha": digest})
            contents[update_archive.RAW_COMMIT_BASE + self.revision + "/" + path] = data
        tree = json.dumps({"truncated": False, "tree": entries}).encode()

        def read_url(url, *, timeout=15, limit=2 * 1024 * 1024):
            if url == update_archive.TREE_BASE + self.revision + "?recursive=1":
                return tree
            return contents[url]

        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "bundle"
            with patch.object(update_archive, "download_archive", side_effect=RuntimeError("codeload unavailable")), patch.object(update_archive, "_read_url", side_effect=read_url):
                update_archive.download_client_bundle(self.revision, destination)
            self.assertEqual((destination / "VERSION").read_text(), "1.7.0\n")
            self.assertTrue((destination / "client" / "security_banner.py").is_file())
            if os.name != "nt":
                self.assertEqual((destination / "scripts" / "install-client.sh").stat().st_mode & 0o777, 0o755)

    def test_download_client_bundle_removes_partial_source_on_integrity_failure(self):
        path = "VERSION"
        data = b"1.7.0\n"
        entries = [{"path": path, "mode": "100644", "type": "blob", "size": len(data), "sha": "a" * 40}]
        for required in update_archive.CLIENT_REQUIRED_FILES:
            if required == path:
                continue
            stub = ("# " + required + "\n").encode()
            entries.append({"path": required, "mode": "100644", "type": "blob", "size": len(stub), "sha": hashlib.sha1(b"blob " + str(len(stub)).encode() + b"\0" + stub).hexdigest()})
        tree = json.dumps({"truncated": False, "tree": entries}).encode()

        def read_url(url, *, timeout=15, limit=2 * 1024 * 1024):
            if url == update_archive.TREE_BASE + self.revision + "?recursive=1":
                return tree
            return b"wrong"

        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "bundle"
            with patch.object(update_archive, "download_archive", side_effect=RuntimeError("codeload unavailable")), patch.object(update_archive, "_read_url", side_effect=read_url):
                with self.assertRaisesRegex(RuntimeError, "size mismatch|integrity check failed"):
                    update_archive.download_client_bundle(self.revision, destination)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
