"""Unit tests for client/microburst_guard.py"""

import unittest
from client import microburst_guard


class TestMicroburstGuard(unittest.TestCase):
    def setUp(self):
        microburst_guard.clear_state()

    def test_empty_container_name(self):
        res = microburst_guard.detect_microburst("runman", "", 0, 0, 0, 0)
        self.assertFalse(res["detected"])

    def test_first_sample_initializes(self):
        res = microburst_guard.detect_microburst("runman", "vm-1", 1000, 1000, 50000, 50000, now=100.0)
        self.assertFalse(res["detected"])
        self.assertEqual(res["threat_level"], "normal")

    def test_small_packet_flood_detection(self):
        # Sample 1: baseline
        microburst_guard.detect_microburst("runman", "vm-attack", 1000, 1000, 100000, 100000, now=100.0)

        # Sample 2: 1 second later, 4,000 packets sent with small bytes (40 bytes/packet, e.g. SYN flood)
        res = microburst_guard.detect_microburst(
            "runman", "vm-attack",
            rx_packets=1200, tx_packets=5000,   # delta = 4000 packets in 1s -> 4000 PPS
            rx_bytes=110000, tx_bytes=260000,   # delta = 160000 bytes -> 40 bytes/pkt
            now=101.0
        )
        self.assertTrue(res["detected"])
        self.assertEqual(res["flood_type"], "outbound_small_packet_flood")
        self.assertEqual(res["threat_level"], "high")
        self.assertEqual(res["tx_pps"], 4000.0)
        self.assertEqual(res["avg_tx_packet_size"], 40.0)

    def test_normal_traffic_not_detected(self):
        microburst_guard.detect_microburst("incus", "c-normal", 1000, 1000, 1000000, 1000000, now=100.0)
        res = microburst_guard.detect_microburst(
            "incus", "c-normal",
            rx_packets=1100, tx_packets=1100,
            rx_bytes=1100000, tx_bytes=1100000,
            now=101.0
        )
        self.assertFalse(res["detected"])
        self.assertEqual(res["threat_level"], "normal")


if __name__ == "__main__":
    unittest.main()

