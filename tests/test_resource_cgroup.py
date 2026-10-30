import tempfile
import unittest
from pathlib import Path
from pathlib import PurePosixPath
from unittest.mock import patch

from client import cpu_guard, io_guard, memory_guard
from client.resource_cgroup import resolve_container_cgroup


class ContainerCgroupResolutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "cgroup"
        self.proc = Path(self.temp.name) / "proc"
        self.root.mkdir()
        self.proc.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def _process(self, pid: int, relative: str):
        self.root.joinpath(*PurePosixPath(relative).parts).mkdir(parents=True, exist_ok=True)
        process_dir = self.proc / str(pid)
        process_dir.mkdir(parents=True)
        (process_dir / "cgroup").write_text(f"0::/{relative}\n", encoding="ascii")

    def _boundary(self, relative: str) -> Path:
        boundary = self.root / relative
        boundary.mkdir(parents=True)
        (boundary / "cgroup.events").write_text("populated 1\nfrozen 0\n", encoding="ascii")
        return boundary

    def _resolve(self, pid: int, runtime: str, stable_id: str, name: str = ""):
        return resolve_container_cgroup(
            pid,
            runtime,
            stable_id,
            name,
            proc_root=self.proc,
            cgroup_root=self.root,
        )

    def test_incus_init_scope_resolves_to_uuid_owned_payload_cgroup(self):
        instance_id = "b0e9f695-2937-4c44-87f9-9b6ebad4f843"
        boundary = self._boundary(f"lxc.payload.{instance_id}")
        self._process(1234, f"lxc.payload.{instance_id}/init.scope")

        actual, error = self._resolve(1234, "incus", instance_id, "container-name")

        self.assertEqual(actual, boundary)
        self.assertEqual(error, "")

    def test_podman_short_id_resolves_full_systemd_scope_and_child(self):
        full_id = "a" * 64
        short_id = full_id[:12]
        boundary = self._boundary(f"machine.slice/libpod-{full_id}.scope")
        (boundary / "system.slice").mkdir()
        self._process(
            1235,
            f"machine.slice/libpod-{full_id}.scope/system.slice/x-ui.service",
        )

        actual, error = self._resolve(1235, "podman", short_id, "x-ui")

        self.assertEqual(actual, boundary)
        self.assertEqual(error, "")

    def test_unknown_or_host_cgroup_never_falls_back_to_process_leaf(self):
        self._boundary("system.slice")
        self._process(1236, "system.slice/some-service.scope")

        actual, error = self._resolve(1236, "incus", "b0e9f695-2937-4c44-87f9-9b6ebad4f843")

        self.assertIsNone(actual)
        self.assertIn("没有唯一匹配", error)

    def test_mismatched_runtime_id_is_rejected(self):
        self._boundary("lxc.payload.actual-id")
        self._process(1237, "lxc.payload.actual-id/init.scope")

        actual, error = self._resolve(1237, "incus", "different-id")

        self.assertIsNone(actual)
        self.assertIn("没有唯一匹配", error)

    def test_memory_guard_reads_limits_and_psi_from_runtime_boundary(self):
        boundary = self._boundary("lxc.payload.instance-id")
        (boundary / "memory.current").write_text("120000000\n", encoding="ascii")
        (boundary / "memory.max").write_text("128000000\n", encoding="ascii")
        (boundary / "memory.high").write_text("max\n", encoding="ascii")
        (boundary / "memory.pressure").write_text(
            "some avg10=12.0 avg60=10.0 avg300=8.0 total=100\nfull avg10=4.0 avg60=3.0 avg300=2.0 total=20\n",
            encoding="ascii",
        )
        container = {"pid": 1238, "runtime": "incus", "id": "instance-id", "name": "guest"}
        with patch("client.memory_guard.resolve_container_cgroup", return_value=(boundary, "")):
            actual, metrics, error = memory_guard._cgroup(container)

        self.assertEqual(actual, boundary)
        self.assertEqual(metrics["current_bytes"], 120000000)
        self.assertEqual(metrics["max_bytes"], 128000000)
        self.assertEqual(metrics["pressure"]["some"]["avg10"], 12.0)
        self.assertEqual(error, "")

    def test_io_guard_reads_attributed_devices_from_runtime_boundary(self):
        boundary = self._boundary("lxc.payload.instance-id")
        (boundary / "io.max").write_text("", encoding="ascii")
        (boundary / "io.stat").write_text(
            "254:0 rbytes=4096 wbytes=2048 rios=8 wios=4\n", encoding="ascii"
        )
        container = {"pid": 1239, "runtime": "incus", "id": "instance-id", "name": "guest"}
        with patch("client.io_guard.resolve_container_cgroup", return_value=(boundary, "")):
            actual, stats, error = io_guard._read_cgroup(container)

        self.assertEqual(actual, str(boundary))
        self.assertEqual(stats["254:0"]["rbytes"], 4096)
        self.assertEqual(error, "")

    def test_cpu_pressure_reads_runtime_boundary_not_init_scope(self):
        boundary = self._boundary("lxc.payload.instance-id")
        for resource in ("cpu", "memory", "io"):
            (boundary / f"{resource}.pressure").write_text(
                "some avg10=6.0 avg60=5.0 avg300=4.0 total=10\nfull avg10=2.0 avg60=1.0 avg300=1.0 total=4\n",
                encoding="ascii",
            )
        container = {"pid": 1240, "runtime": "incus", "id": "instance-id", "name": "guest"}
        with patch("client.cpu_guard.resolve_container_cgroup", return_value=(boundary, "")):
            actual = cpu_guard._container_psi(container)

        self.assertEqual(actual["status"], "ready")
        self.assertEqual(actual["memory"]["some"]["avg10"], 6.0)


if __name__ == "__main__":
    unittest.main()
