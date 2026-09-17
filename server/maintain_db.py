"""Inspect SQLite storage; explicitly back up and compact an existing database."""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import sqlite3


def inspect_database(path):
    path = Path(path).resolve(strict=True)
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as conn:
        size = conn.execute("PRAGMA page_size").fetchone()[0]
        pages = conn.execute("PRAGMA page_count").fetchone()[0]
        free = conn.execute("PRAGMA freelist_count").fetchone()[0]
        return {"path": str(path), "database_bytes": pages * size,
                "reusable_bytes": free * size,
                "auto_vacuum": conn.execute("PRAGMA auto_vacuum").fetchone()[0],
                "wal_bytes": Path(str(path) + "-wal").stat().st_size if Path(str(path) + "-wal").exists() else 0}


def compact_database(path, backup):
    path = Path(path).resolve(strict=True)
    backup = Path(backup).resolve()
    if path == backup or backup.exists():
        raise ValueError("Backup must be a new, distinct file")
    before = inspect_database(path)
    # Conservative space reserve for backup plus VACUUM temporary pages.
    if shutil.disk_usage(path.parent).free < 3 * before["database_bytes"]:
        raise RuntimeError("Insufficient free space for backup and VACUUM; use a maintenance disk")
    with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=5)) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"reports", "hosts", "host_security"}.issubset(tables):
            raise ValueError("Not a Narwhal monitoring database")
        if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise RuntimeError("Database integrity check failed; compaction aborted")
        fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(backup)) as dest:
            conn.backup(dest)
            if dest.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RuntimeError("Backup integrity check failed")
        conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
        conn.execute("VACUUM")
        if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise RuntimeError("Post-compaction integrity check failed; retain backup")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return {"before": before, "after": inspect_database(path), "backup": str(backup)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database")
    parser.add_argument("--compact", action="store_true")
    parser.add_argument("--server-stopped", action="store_true")
    parser.add_argument("--backup")
    args = parser.parse_args()
    if args.compact and (not args.server_stopped or not args.backup):
        parser.error("Stop the server first, then provide --server-stopped and --backup NEW_PATH")
    print(json.dumps(compact_database(args.database, args.backup) if args.compact else inspect_database(args.database)))
