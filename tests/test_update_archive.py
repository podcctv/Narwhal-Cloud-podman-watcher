import io
import os
import tarfile
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
