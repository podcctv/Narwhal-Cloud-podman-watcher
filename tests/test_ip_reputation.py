import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.fernet import Fernet
from fastapi import HTTPException
from fastapi import FastAPI
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("narwhal_ip_reputation", ROOT / "server" / "ip_reputation.py")
assert SPEC and SPEC.loader
ip_reputation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ip_reputation)


class IPReputationTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ip_reputation.initialize(self.conn)
        self.fernet = Fernet(Fernet.generate_key())
        self.key = "test-abuseipdb-key-0123456789abcdef"
        self.conn.execute(
            "INSERT INTO ip_reputation_settings(id,encrypted_api_key,updated_at) VALUES(1,?,1)",
            (self.fernet.encrypt(self.key.encode()).decode(),),
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def cipher_factory(self, _db_path):
        return self.fernet

    def test_only_public_ips_are_sent_to_provider(self):
        self.assertEqual(ip_reputation.normalize_public_ip("2001:4860:4860::8888"), "2001:4860:4860::8888")
        for value in ("127.0.0.1", "10.0.0.1", "192.0.2.1", "not-an-ip"):
            with self.subTest(value=value), self.assertRaises(HTTPException):
                ip_reputation.normalize_public_ip(value)

    def test_key_is_encrypted_and_cached_lookup_does_not_repeat_provider_call(self):
        stored = self.conn.execute("SELECT encrypted_api_key FROM ip_reputation_settings WHERE id=1").fetchone()[0]
        self.assertNotIn(self.key, stored)
        self.assertEqual(self.fernet.decrypt(stored.encode()).decode(), self.key)
        expected = {
            "status": "checked", "provider": "AbuseIPDB", "ip": "8.8.8.8",
            "classification": "no_recent_reports", "abuse_confidence_score": 0,
            "total_reports": 0, "distinct_reporters": 0, "checked_at": 1000,
            "last_reported_at": "", "usage_type": "", "isp": "", "country_code": "US",
            "is_whitelisted": None, "message": "reputation is not proof of intent",
        }
        with mock.patch.object(ip_reputation, "_query_provider", return_value=expected) as query:
            first = ip_reputation.check_ip(self.conn, "8.8.8.8", lambda: "/tmp/test.db", self.cipher_factory, now=1000)
            second = ip_reputation.check_ip(self.conn, "8.8.8.8", lambda: "/tmp/test.db", self.cipher_factory, now=1100)
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(query.call_count, 1)

    def test_reputation_classification_is_not_a_benign_or_malicious_verdict(self):
        data = {
            "abuseConfidenceScore": 91,
            "totalReports": 45,
            "numDistinctUsers": 17,
            "lastReportedAt": "2026-10-18T12:00:00+00:00",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Example ISP",
            "countryCode": "US",
            "isWhitelisted": False,
        }
        result = ip_reputation._safe_result("8.8.8.8", data, 1000)
        self.assertEqual(result["classification"], "many_recent_reports")
        self.assertIn("不能单独证明", result["message"])
        self.assertNotIn("raw", json.dumps(result))

        low_confidence = ip_reputation._safe_result("8.8.8.8", {
            "abuseConfidenceScore": 0,
            "totalReports": 235,
            "numDistinctUsers": 91,
        }, 1000)
        self.assertEqual(low_confidence["classification"], "reports_low_confidence")
        self.assertEqual(low_confidence["abuse_confidence_score"], 0)
        self.assertEqual(low_confidence["total_reports"], 235)

    def test_cached_classification_is_recomputed_from_reports_and_score(self):
        stale_cache = {
            "status": "checked",
            "ip": "8.8.8.8",
            "classification": "no_recent_reports",
            "abuse_confidence_score": 0,
            "total_reports": 235,
            "distinct_reporters": 91,
        }
        self.conn.execute(
            "INSERT INTO ip_reputation_cache(ip,result_json,checked_at,expires_at) VALUES(?,?,?,?)",
            ("8.8.8.8", json.dumps(stale_cache), 999, 10000),
        )
        self.conn.commit()

        with mock.patch.object(ip_reputation, "_query_provider") as query:
            result = ip_reputation.check_ip(
                self.conn, "8.8.8.8", lambda: "/tmp/test.db", self.cipher_factory, now=1000
            )

        self.assertEqual(result["classification"], "reports_low_confidence")
        self.assertTrue(result["cached"])
        query.assert_not_called()

    def test_provider_uses_key_header_and_url_encodes_ipv6(self):
        provider_response = mock.MagicMock()
        provider_response.status = 200
        provider_response.read.return_value = json.dumps({"data": {
            "abuseConfidenceScore": 82,
            "totalReports": 14,
            "numDistinctUsers": 9,
            "countryCode": "US",
        }}).encode("utf-8")
        opener = mock.MagicMock()
        opener.open.return_value.__enter__.return_value = provider_response

        with mock.patch("urllib.request.build_opener", return_value=opener):
            result = ip_reputation._query_provider(self.key, "2001:4860:4860::8888", 1234)

        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Key"), self.key)
        self.assertEqual(request.get_header("Accept"), "application/json")
        self.assertIn("ipAddress=2001%3A4860%3A4860%3A%3A8888", request.full_url)
        self.assertNotIn("key=", request.full_url.lower())
        self.assertEqual(result["status"], "checked")
        self.assertEqual(result["abuse_confidence_score"], 82)

    def test_local_daily_guard_stops_before_provider_quota(self):
        self.conn.execute(
            "INSERT INTO ip_reputation_daily_usage(utc_day,requests) VALUES('1970-01-01',900)"
        )
        self.conn.commit()
        with mock.patch.object(ip_reputation, "_query_provider") as query:
            result = ip_reputation.check_ip(self.conn, "8.8.8.8", lambda: "/tmp/test.db", self.cipher_factory, now=1000)
        self.assertEqual(result["status"], "local_limit")
        query.assert_not_called()

    def test_settings_and_explicit_lookup_routes_keep_key_private(self):
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp) / "monitor.db")

            def database():
                connection = sqlite3.connect(path)
                connection.row_factory = sqlite3.Row
                ip_reputation.initialize(connection)
                return connection

            app = FastAPI()
            ip_reputation.attach(app, database, lambda: path, lambda _path: self.fernet)
            client = TestClient(app)
            try:
                self.assertFalse(client.get("/api/v1/ip-reputation/settings").json()["configured"])
                saved = client.post("/api/v1/ip-reputation/settings", json={"api_key": self.key})
                self.assertEqual(saved.status_code, 200)
                self.assertTrue(client.get("/api/v1/ip-reputation/settings").json()["configured"])
                with mock.patch.object(ip_reputation, "_query_provider", return_value={
                    "status": "checked", "ip": "8.8.8.8", "abuse_confidence_score": 0,
                    "classification": "no_recent_reports", "message": "safe fixture",
                }) as query:
                    checked = client.post("/api/v1/ip-reputation/check", json={"ip": "8.8.8.8"})
                self.assertEqual(checked.status_code, 200)
                self.assertEqual(checked.json()["ip"], "8.8.8.8")
                self.assertEqual(query.call_count, 1)
                connection = sqlite3.connect(path)
                stored = connection.execute("SELECT encrypted_api_key FROM ip_reputation_settings WHERE id=1").fetchone()[0]
                connection.close()
                self.assertNotIn(self.key, stored)
                self.assertEqual(client.post("/api/v1/ip-reputation/check", json={"ip": "10.0.0.1"}).status_code, 400)
            finally:
                client.close()


if __name__ == "__main__":
    unittest.main()
