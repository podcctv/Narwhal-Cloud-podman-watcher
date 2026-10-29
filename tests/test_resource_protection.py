import unittest

from client import cpu_guard, io_guard


class ResourceProtectionPressureTests(unittest.TestCase):
    def test_cpu_psi_must_confirm_contention_when_available(self):
        host = {
            "status": "ready",
            "busy_percent": 92,
            "psi": {"cpu": {"status": "ready", "some": {"avg10": 0.4}}},
        }
        confirmed, psi, basis = cpu_guard._host_cpu_pressure(host, 80, 5)
        self.assertFalse(confirmed)
        self.assertEqual(psi, 0.4)
        self.assertEqual(basis, "host_psi_below_threshold")

    def test_cpu_high_busy_and_psi_confirm_contention(self):
        host = {
            "status": "ready",
            "busy_percent": 92,
            "psi": {"cpu": {"status": "ready", "some": {"avg10": 7.5}}},
        }
        confirmed, psi, basis = cpu_guard._host_cpu_pressure(host, 80, 5)
        self.assertTrue(confirmed)
        self.assertEqual(psi, 7.5)
        self.assertEqual(basis, "host_busy_and_psi_confirmed")

    def test_cpu_busy_fallback_is_explicit_when_psi_is_missing(self):
        host = {"status": "ready", "busy_percent": 92, "psi": {"cpu": {"status": "unsupported"}}}
        confirmed, psi, basis = cpu_guard._host_cpu_pressure(host, 80, 5)
        self.assertTrue(confirmed)
        self.assertIsNone(psi)
        self.assertEqual(basis, "host_busy_psi_unavailable_fallback")

    def test_cpu_psi_does_not_override_low_host_busy(self):
        host = {
            "status": "ready",
            "busy_percent": 60,
            "psi": {"cpu": {"status": "ready", "some": {"avg10": 12}}},
        }
        confirmed, _, basis = cpu_guard._host_cpu_pressure(host, 80, 5)
        self.assertFalse(confirmed)
        self.assertEqual(basis, "host_busy_below_threshold")

    def test_io_psi_is_authoritative_when_available(self):
        self.assertEqual(io_guard._host_io_pressure(98, 1.0, 80, 5), (False, "host_io_psi"))
        self.assertEqual(io_guard._host_io_pressure(20, 8.0, 80, 5), (True, "host_io_psi"))

    def test_io_device_busy_is_compatibility_fallback_when_psi_is_missing(self):
        self.assertEqual(
            io_guard._host_io_pressure(85, None, 80, 5),
            (True, "device_busy_fallback_psi_unavailable"),
        )
        self.assertEqual(
            io_guard._host_io_pressure(55, None, 80, 5),
            (False, "device_busy_fallback_psi_unavailable"),
        )

    def test_io_psi_reader_uses_scoped_host_and_container_values(self):
        evidence = {
            "host": {"io": {"status": "ready", "some": {"avg10": 4.2}}},
            "container": {"io": {"status": "ready", "some": {"avg10": 9.1}}},
        }
        self.assertEqual(io_guard._psi_avg10(evidence, "host"), 4.2)
        self.assertEqual(io_guard._psi_avg10(evidence, "container"), 9.1)


if __name__ == "__main__":
    unittest.main()
