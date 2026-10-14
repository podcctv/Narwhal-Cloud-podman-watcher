import asyncio
import copy
import hashlib
import hmac
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from server import app as server, abuse_api


def alert():
    return {'type': 'prohibited_activity', 'runtime': 'podman', 'project': '',
            'container_name': 'customer', 'instance_id': 'a'*64,
            'abuse_evidence': [{'kind': 'credential_stuffing', 'confidence': 'high', 'pid': 22,
                'start_ticks': '12345', 'source_sha256': 'b'*64,
                'features': {'corroborating_samples': 2, 'dictionary_inputs': True},
                'source': 'private-source', 'password': 'private-password'}],
            'network_quarantine': {'status': 'isolated', 'ingress_blocked': True, 'egress_blocked': True}}


def request(payload, role='admin'):
    body = json.dumps(payload).encode()
    async def receive():
        return {'type': 'http.request', 'body': body, 'more_body': False}
    return Request({'type': 'http', 'method': 'POST', 'path': '/', 'headers': [],
                    'state': {'dashboard_role': role, 'dashboard_user': 'test-reviewer'}}, receive)


class AbuseAPITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.patch = mock.patch.multiple(server, DB_PATH=str(Path(self.directory.name)/'monitor.db'), SHARED_SECRET='test-only-secret')
        self.patch.start()
        server.init_db()
        self.conn = server.db()
        self.now = int(time.time())
        self.conn.execute("INSERT INTO hosts VALUES('host',?,'test','node','{}')", (self.now,))
        self.conn.commit()
        self.sync = mock.Mock()
        app = FastAPI()
        abuse_api.attach(app, server.db, server.verify_signature, server.signed_json_response,
                         server.process_security_alerts, self.sync, server._queue_security_action_row)
        self.event = next(r.endpoint for r in app.routes if r.path == '/api/v1/abuse/events')
        self.release = next(r.endpoint for r in app.routes if r.path.endswith('/release-quarantine'))

    def tearDown(self):
        self.conn.close()
        self.patch.stop()
        self.directory.cleanup()

    def emit(self, value=None, node='node'):
        payload = {'host_id': 'host', 'node_id': node, 'alert': value or alert()}
        req = request(payload)
        body = json.dumps(payload).encode()
        timestamp = str(int(time.time()))
        signature = hmac.new(server.SHARED_SECRET.encode(), body+timestamp.encode(), hashlib.sha256).hexdigest()
        return asyncio.run(self.event(req, timestamp, signature))

    def test_signed_incremental_event_retains_unrelated_risks_and_notifies(self):
        unrelated = {'type': 'container_connection_count', 'runtime': 'podman', 'project': '',
                     'container_name': 'other', 'severity': 'critical', 'value': 2000, 'threshold': 500}
        server.process_security_alerts(self.conn, 'host', self.now, [unrelated])
        self.conn.commit()
        self.emit()
        states = {r['container_name']: r['status'] for r in self.conn.execute('SELECT * FROM security_alerts')}
        self.assertEqual(states, {'other': 'active', 'customer': 'active'})
        self.assertEqual(self.conn.execute('SELECT status FROM network_quarantines').fetchone()[0], 'isolated')
        stored = self.conn.execute("SELECT details_json FROM security_alerts WHERE alert_type='prohibited_activity'").fetchone()[0]
        self.assertNotIn('private-source', stored)
        self.assertNotIn('private-password', stored)
        self.sync.assert_called_once()

    def test_wrong_signature_and_wrong_node_cannot_create_event(self):
        with self.assertRaises(HTTPException) as caught:
            asyncio.run(self.event(request({}), str(int(time.time())), 'bad'))
        self.assertEqual(caught.exception.status_code, 401)
        with self.assertRaises(HTTPException) as caught:
            self.emit(node='different-node')
        self.assertEqual(caught.exception.status_code, 403)
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM network_quarantines').fetchone()[0], 0)

    def test_weak_partial_or_unproven_evidence_rejected(self):
        mutations = [lambda a: a['abuse_evidence'][0].update(confidence='suspected'),
                     lambda a: a['abuse_evidence'][0]['features'].update(corroborating_samples=1),
                     lambda a: a['network_quarantine'].update(egress_blocked=False),
                     lambda a: a.update(instance_id='short'),
                     lambda a: a['abuse_evidence'][0].update(start_ticks='invalid')]
        for mutate in mutations:
            value = alert(); mutate(value)
            with self.assertRaises(HTTPException):
                abuse_api.normalized_alert(value)

    def test_failure_never_claims_completed_isolation(self):
        value = alert(); value['network_quarantine']['status'] = 'failed'
        normalized = abuse_api.normalized_alert(value)
        self.assertFalse(normalized['network_quarantine']['ingress_blocked'])
        self.assertFalse(normalized['network_quarantine']['egress_blocked'])
        self.assertIn('未能完整验证', normalized['message'])
        self.assertEqual(normalized['severity'], 'critical')

    def test_repeated_event_deduplicates_but_new_instance_gets_separate_record(self):
        self.emit(); self.emit()
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM network_quarantines').fetchone()[0], 1)
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM security_alerts').fetchone()[0], 1)
        value = alert(); value['instance_id'] = 'c'*64
        self.emit(value)
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM network_quarantines').fetchone()[0], 2)
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM security_alerts').fetchone()[0], 2)

    def test_review_requires_admin_and_explicit_confirmation_and_binds_identity(self):
        self.emit()
        alert_id = self.conn.execute('SELECT alert_id FROM network_quarantines').fetchone()[0]
        for payload, role in (({'confirmed': True}, 'viewer'), ({'confirmed': False}, 'admin')):
            with self.assertRaises(HTTPException):
                asyncio.run(self.release(alert_id, request(payload, role)))
        response = asyncio.run(self.release(alert_id, request({'confirmed': True})))
        self.assertEqual(response.status_code, 202)
        row = self.conn.execute('SELECT * FROM security_actions').fetchone()
        params = json.loads(row['params_json'])
        self.assertEqual(row['action_type'], 'release_network_quarantine')
        self.assertEqual(params['instance_id'], 'a'*64)
        self.assertEqual(params['expected_node_id'], 'node')
        self.assertEqual(self.conn.execute('SELECT status FROM network_quarantines').fetchone()[0], 'isolated')

    def test_stale_node_release_refused(self):
        self.emit()
        self.conn.execute('UPDATE hosts SET last_seen=?', (self.now-1000,)); self.conn.commit()
        alert_id = self.conn.execute('SELECT alert_id FROM network_quarantines').fetchone()[0]
        with self.assertRaises(HTTPException) as caught:
            asyncio.run(self.release(alert_id, request({'confirmed': True})))
        self.assertEqual(caught.exception.status_code, 409)

    def test_missing_full_report_does_not_resolve_pending_network_review(self):
        self.emit()
        server.process_security_alerts(self.conn, 'host', self.now+10, [])
        self.conn.commit()
        row = self.conn.execute("SELECT status FROM security_alerts WHERE alert_type='prohibited_activity'").fetchone()
        self.assertEqual(row[0], 'active')

    def test_pending_review_cannot_be_purged_with_host_identity(self):
        self.emit()
        with self.assertRaises(HTTPException) as caught:
            server._purge_host(self.conn, 'host')
        self.assertEqual(caught.exception.status_code, 409)
        self.assertTrue(self.conn.execute("SELECT 1 FROM hosts WHERE host_id='host'").fetchone())

    def test_release_result_is_not_misrepresented_as_verified_recovery(self):
        self.emit()
        alert_id = self.conn.execute('SELECT alert_id FROM network_quarantines').fetchone()[0]
        row = {'action_type': 'release_network_quarantine', 'alert_id': alert_id}
        abuse_api.record_release_result(self.conn, row, {'instance_id': 'a'*64}, 'succeeded', self.now)
        self.conn.commit()
        record = self.conn.execute('SELECT * FROM security_alerts').fetchone()
        self.assertIn('不等于风险已恢复', record['message'])
        self.assertEqual(json.loads(record['details_json'])['network_quarantine']['status'], 'released')

    def test_telegram_card_reports_isolation_not_recovery_even_if_alert_archived(self):
        self.emit()
        self.conn.execute("UPDATE security_alerts SET status='resolved'"); self.conn.commit()
        row = self.conn.execute('SELECT * FROM security_alerts').fetchone()
        text, keyboard = server._telegram_alert_status_card(row, self.now)
        self.assertIn('已双向隔离', text)
        self.assertIn('连续佐证 2 次', text)
        self.assertNotIn('状态：<b>已恢复</b>', text)
        self.assertNotIn('private-source', text)
        detail, actions = server._telegram_alert_detail(row['id'], 'all', 0)
        self.assertNotIn('dismiss_once', json.dumps(actions))
        self.assertNotIn('allow_silent', json.dumps(actions))
        self.assertIn('网页管理员', detail)

    def test_generic_resolve_and_silent_allow_cannot_hide_quarantine(self):
        self.emit()
        row = self.conn.execute('SELECT * FROM security_alerts').fetchone()
        for decision in ('resolve', 'dismiss_once', 'allow_silent', 'deny'):
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(server.set_security_alert_disposition(row['id'], request({'decision': decision})))
            self.assertEqual(caught.exception.status_code, 409)


if __name__ == '__main__':
    unittest.main()

