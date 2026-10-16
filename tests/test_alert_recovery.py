import unittest
from server import buyer_notifications as buyer
from tests import test_buyer_notifications as fixtures


class RecoveryTests(unittest.TestCase):
    setUp = fixtures.BuyerTests.setUp
    tearDown = fixtures.BuyerTests.tearDown
    ingest = fixtures.BuyerTests.ingest

    def item(self):
        with fixtures.server.db() as conn:
            row = conn.execute('SELECT * FROM security_alerts ORDER BY id LIMIT 1').fetchone()
            return fixtures.server._security_alert_item(conn, row)

    def test_two_fresh_samples_freeze_recovery_duration(self):
        self.ingest()
        self.ingest([], self.now+10)
        self.assertFalse(self.item()['recovery']['verified'])
        self.ingest([], self.now+20)
        recovery = self.item()['recovery']
        self.assertTrue(recovery['verified'])
        self.assertEqual(recovery['duration_seconds'], 20)
        self.assertEqual(recovery['recovered_at'], self.now+20)
        self.ingest([], self.now+1800)
        self.assertEqual(self.item()['recovery'], recovery)

    def test_recurrence_starts_new_episode(self):
        self.ingest()
        self.ingest([], self.now+10)
        self.ingest([], self.now+20)
        self.ingest(when=self.now+30)
        self.assertEqual(self.item()['recovery']['state'], 'ongoing')
        self.ingest([], self.now+40)
        self.ingest([], self.now+50)
        self.assertEqual(self.item()['recovery']['duration_seconds'], 20)
        self.assertEqual(self.item()['recovery']['recovered_at'], self.now+50)

    def test_unknown_auth_is_not_recovery(self):
        self.ingest()
        c = {**self.c, 'security': {'socks_proxy': {'detected': True, 'auth_mode': 'unknown'}}}
        self.ingest([], self.now+10, c)
        self.ingest([], self.now+20, c)
        recovery = self.item()['recovery']
        self.assertFalse(recovery['verified'])
        self.assertIsNone(recovery['duration_seconds'])
        self.assertEqual(recovery['closed_duration_seconds'], 10)

    def test_manual_close_is_not_confirmed_recovery(self):
        self.ingest()
        with fixtures.server.db() as conn:
            row = conn.execute('SELECT * FROM security_alerts').fetchone()
            conn.execute("UPDATE security_alerts SET status='resolved' WHERE id=?", (row['id'],))
            conn.execute('INSERT INTO security_alert_decisions(alert_id,fingerprint,decision,requested_by,created_at) VALUES(?,?,?,?,?)', (row['id'], row['fingerprint'], 'resolve', 'test', self.now+15))
        recovery = self.item()['recovery']
        self.assertEqual(recovery['state'], 'manual_closed')
        self.assertFalse(recovery['verified'])
        self.assertEqual(recovery['closed_duration_seconds'], 15)

    def test_legacy_verified_never_invents_timestamp(self):
        self.ingest()
        self.ingest([], self.now+10)
        self.ingest([], self.now+20)
        with fixtures.server.db() as conn:
            conn.execute('UPDATE buyer_checks SET verified_at=0')
        self.ingest([], self.now+500)
        recovery = self.item()['recovery']
        self.assertEqual(recovery['state'], 'legacy_verified')
        self.assertIsNone(recovery['recovered_at'])
        self.assertIsNone(recovery['duration_seconds'])

    def test_missing_container_is_not_recovery(self):
        self.ingest()
        with fixtures.server.db() as conn:
            fixtures.server.process_security_alerts(conn, 'host', self.now+10, [])
            buyer.observe(conn, 'host', self.now+10, [], [])
            buyer.observe(conn, 'host', self.now+20, [], [])
        self.assertFalse(self.item()['recovery']['verified'])


if __name__ == '__main__': unittest.main()
