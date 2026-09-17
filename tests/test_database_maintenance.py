import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("maintenance", Path(__file__).resolve().parents[1] / "server" / "maintain_db.py")
maintenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(maintenance)


class DatabaseMaintenanceTests(unittest.TestCase):
    def test_compaction_reclaims_space_and_preserves_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "monitor.db"
            backup = Path(directory) / "before.db"
            with sqlite3.connect(path) as conn:
                conn.executescript("CREATE TABLE reports(data BLOB); CREATE TABLE hosts(id); CREATE TABLE host_security(id);")
                conn.execute("INSERT INTO reports VALUES(zeroblob(2000000))")
                conn.commit()
                conn.execute("DELETE FROM reports")
                conn.execute("INSERT INTO hosts VALUES(42)")
            conn.close()
            result = maintenance.compact_database(path, backup)
            self.assertLess(result["after"]["database_bytes"], result["before"]["database_bytes"])
            self.assertEqual(result["after"]["auto_vacuum"], 2)
            for p in (path, backup):
                with sqlite3.connect(p) as conn:
                    self.assertEqual(conn.execute("PRAGMA quick_check").fetchone()[0], "ok")
                    self.assertEqual(conn.execute("SELECT id FROM hosts").fetchone()[0], 42)
                conn.close()
            with self.assertRaises(ValueError):
                maintenance.compact_database(path, backup)
