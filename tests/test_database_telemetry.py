import sqlite3
import tempfile
import unittest
from pathlib import Path

from server import database_telemetry as telemetry


class DatabaseTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "monitor.db")
        self.conn = sqlite3.connect(self.path)
        telemetry.initialize(self.conn)

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    def test_samples_are_hourly_idempotent_and_history_is_bounded(self):
        now = 2_000_000_000
        first = telemetry.sample_and_summarize(self.conn, self.path, now)
        second = telemetry.sample_and_summarize(self.conn, self.path, now + 1200)
        self.assertEqual(first["sampled_at"], second["sampled_at"])
        self.assertEqual(len(second["history"]), 1)
        self.assertEqual(second["retention_days"], 45)

    def test_growth_threshold_requires_both_absolute_and_relative_evidence(self):
        gib = 1024**3
        self.assertEqual(telemetry.assess_growth(1 * gib + 300 * 1024**2, 1 * gib)["status"], "warning")
        self.assertEqual(telemetry.assess_growth(1 * gib + 1_100 * 1024**2, 1 * gib)["status"], "critical")
        # A large database needs a meaningful percentage increase as well.
        self.assertEqual(telemetry.assess_growth(10 * gib + 500 * 1024**2, 10 * gib)["status"], "healthy")
        self.assertEqual(telemetry.assess_growth(500, 1000)["status"], "healthy")
        self.assertEqual(telemetry.assess_growth(500, None)["status"], "warming_up")

    def test_old_samples_are_pruned(self):
        now = 2_000_000_000
        self.conn.execute(
            "INSERT INTO database_storage_samples(ts,database_bytes,wal_bytes,reusable_bytes,total_bytes) VALUES(?,?,?,?,?)",
            (now - telemetry.HISTORY_RETENTION_SECONDS - 3600, 100, 0, 0, 100),
        )
        self.conn.commit()
        telemetry.sample_and_summarize(self.conn, self.path, now)
        count = self.conn.execute("SELECT COUNT(*) FROM database_storage_samples WHERE ts<?", (now - telemetry.HISTORY_RETENTION_SECONDS,)).fetchone()[0]
        self.assertEqual(count, 0)

if __name__ == "__main__":
    unittest.main()
