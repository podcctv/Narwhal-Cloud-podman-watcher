import json
import unittest

from server import inbound_assessment


def report(ts, *, signals, listeners=(443,), service_listeners=None, conntrack=True):
    security = {
        "host_conntrack_available": conntrack,
        "listening_ports": list(listeners),
        "inbound_source_signals": signals,
    }
    if service_listeners is not None:
        security["service_listeners"] = service_listeners
    return {
        "ts": ts,
        "payload_json": json.dumps({
            "security": security,
        }),
    }


def signal(ip, *, ports, established=0, unreplied=0, pending=0, replies=0):
    return {
        "ip": ip,
        "scope": "single_conntrack_snapshot",
        "evidence_sources": ["host_conntrack"],
        "container_ports": list(ports),
        "tcp_established_flows": established,
        "tcp_unreplied_flows": unreplied,
        "tcp_handshake_pending_flows": pending,
        "reply_packets": replies,
    }


class InboundAssessmentTests(unittest.TestCase):
    def test_repeated_established_listener_transport_does_not_claim_business_or_identity(self):
        rows = [
            report(1000, signals=[signal("8.8.8.8", ports=[443], established=2, replies=5)]),
            report(1040, signals=[signal("8.8.8.8", ports=[443], established=3, replies=8)]),
        ]

        result = inbound_assessment.assess(rows, now=1050)

        self.assertEqual(result["status"], "available")
        assessment = result["assessments"][0]
        self.assertEqual(assessment["classification"], "repeated_established_listener_transport")
        self.assertEqual(assessment["service_ports"], [443])
        self.assertFalse(assessment["identity_confirmed"])
        self.assertFalse(result["customer_notice_allowed"])
        self.assertEqual(result["customer_attribution_status"], "not_verified")
        self.assertTrue(result["requires_application_auth_logs"])

    def test_repeated_incomplete_multiport_probe_is_separate_from_service_traffic(self):
        rows = [
            report(1000, signals=[signal("9.9.9.9", ports=[22, 80, 8080], unreplied=3)]),
            report(1040, signals=[signal("9.9.9.9", ports=[22, 80, 8080], unreplied=4)]),
        ]

        result = inbound_assessment.assess(rows, now=1050)

        assessment = result["assessments"][0]
        self.assertEqual(assessment["classification"], "repeated_uncompleted_multiport_probe")
        self.assertEqual(assessment["non_listener_ports"], [22, 80, 8080])
        self.assertEqual(assessment["probe_clue_samples"], 2)

    def test_service_and_probe_evidence_are_reported_as_mixed(self):
        rows = [
            report(1000, signals=[signal("1.1.1.1", ports=[443], established=1, replies=2)]),
            report(1040, signals=[signal("1.1.1.1", ports=[22, 80, 8080], unreplied=3)]),
        ]

        result = inbound_assessment.assess(rows, now=1050)

        self.assertEqual(
            result["assessments"][0]["classification"],
            "mixed_repeated_listener_transport_and_probe_clues",
        )
        self.assertEqual(result["assessments"][0]["confidence"], "moderate")

    def test_udp_only_service_listener_does_not_classify_tcp_conntrack_as_service_use(self):
        rows = [
            report(
                1000,
                listeners=(),
                service_listeners=[{"proto": "udp", "port": 443}],
                signals=[signal("8.8.8.8", ports=[443], established=1, replies=2)],
            ),
            report(
                1040,
                listeners=(),
                service_listeners=[{"proto": "udp", "port": 443}],
                signals=[signal("8.8.8.8", ports=[443], established=1, replies=2)],
            ),
        ]

        result = inbound_assessment.assess(rows, now=1050)

        self.assertEqual(result["assessments"][0]["classification"], "insufficient_evidence")
        self.assertEqual(result["assessments"][0]["service_ports"], [])

    def test_single_sample_and_missing_conntrack_remain_inconclusive(self):
        single = inbound_assessment.assess(
            [report(1040, signals=[signal("8.8.4.4", ports=[443], established=1, replies=2)])],
            now=1050,
        )
        self.assertEqual(single["status"], "insufficient_history")
        self.assertEqual(single["assessments"][0]["classification"], "insufficient_evidence")
        self.assertEqual(single["assessments"][0]["confidence"], "low")

        no_conntrack = inbound_assessment.assess(
            [
                report(1000, conntrack=False, signals=[signal("8.8.4.4", ports=[22, 80, 8080], unreplied=3)]),
                report(1040, conntrack=False, signals=[signal("8.8.4.4", ports=[22, 80, 8080], unreplied=3)]),
            ],
            now=1050,
        )
        self.assertEqual(no_conntrack["status"], "insufficient_history")
        self.assertEqual(no_conntrack["assessments"], [])

    def test_private_and_expired_source_evidence_is_excluded(self):
        rows = [
            report(100, signals=[signal("10.0.0.5", ports=[22, 80, 8080], unreplied=3)]),
            report(1040, signals=[signal("8.8.8.8", ports=[443], established=1, replies=1)]),
        ]

        result = inbound_assessment.assess(rows, now=1050)

        self.assertEqual([item["ip"] for item in result["assessments"]], ["8.8.8.8"])
        self.assertEqual(result["report_sample_count"], 1)


if __name__ == "__main__":
    unittest.main()
