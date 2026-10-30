"""Resolve a runtime container's cgroup boundary from a host PID safely.

Incus and Podman put the container init process in a nested cgroup (for
example ``lxc.payload.<uuid>/init.scope``). Resource controls belong on the
runtime-owned container cgroup, not that process-only leaf.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath
from typing import Any


CGROUP_ROOT = Path(os.getenv("NARWHAL_CGROUP_ROOT", "/sys/fs/cgroup"))
_SAFE_ID = re.compile(r"[A-Za-z0-9_.:@+-]{1,256}\Z")
_PODMAN_ID = re.compile(r"[0-9a-fA-F]{12,64}\Z")


def _podman_boundary(segment: str, stable_id: str) -> bool:
    value = segment[:-6] if segment.endswith(".scope") else segment
    if not value.startswith("libpod-"):
        return False
    cgroup_id = value[len("libpod-"):]
    if not _PODMAN_ID.fullmatch(cgroup_id) or not _PODMAN_ID.fullmatch(stable_id):
        return False
    container_id = stable_id.lower()
    cgroup_id = cgroup_id.lower()
    return cgroup_id.startswith(container_id) or container_id.startswith(cgroup_id)


def resolve_container_cgroup(
    pid_value: Any,
    runtime: Any,
    stable_id: Any,
    name: Any = "",
    *,
    proc_root: str | os.PathLike[str] = "/proc",
    cgroup_root: str | os.PathLike[str] | None = None,
) -> tuple[Path | None, str]:
    """Return the ID-matched container cgroup, never a host/leaf fallback.

    ``stable_id`` is the Incus UUID or Podman ID reported by the runtime.
    Podman's normal short ID is accepted only when it has at least 12 hex
    characters and unambiguously prefixes the ID in the cgroup name.
    """
    try:
        pid = int(pid_value or 0)
    except (TypeError, ValueError, OverflowError):
        pid = 0
    if pid <= 1:
        return None, "容器宿主机 PID 不可用"

    runtime_name = str(runtime or "").strip().lower()
    if runtime_name not in {"incus", "podman"}:
        return None, "仅支持 Incus / Podman 容器资源 cgroup"

    identity = str(stable_id or "").strip()
    container_name = str(name or "").strip()
    if not identity or not _SAFE_ID.fullmatch(identity):
        return None, "运行时容器 ID 不可用，无法安全关联资源 cgroup"

    try:
        lines = (Path(proc_root) / str(pid) / "cgroup").read_text(
            encoding="ascii", errors="ignore"
        ).splitlines()
        relative = next((line[3:].strip() for line in lines if line.startswith("0::")), "")
        if not relative or relative == "/" or "(deleted)" in relative:
            return None, "未能确认容器 cgroup v2 路径"
        parts = PurePosixPath(relative.lstrip("/")).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            return None, "容器 cgroup 路径格式无效"

        root = Path(cgroup_root) if cgroup_root is not None else CGROUP_ROOT
        root = root.resolve(strict=True)
        process_cgroup = (root.joinpath(*parts)).resolve(strict=True)
        if process_cgroup == root or not process_cgroup.is_relative_to(root):
            return None, "容器 cgroup 路径越出受控目录"

        if runtime_name == "incus":
            expected = {f"lxc.payload.{identity}"}
            if container_name and _SAFE_ID.fullmatch(container_name):
                expected.add(f"lxc.payload.{container_name}")
            matches = [index for index, part in enumerate(parts) if part in expected]
        else:
            matches = [index for index, part in enumerate(parts) if _podman_boundary(part, identity)]

        if len(matches) != 1:
            return None, "PID 所在路径中没有唯一匹配该容器 ID 的资源 cgroup"
        boundary = root.joinpath(*parts[: matches[0] + 1]).resolve(strict=True)
        if boundary == root or not boundary.is_relative_to(root):
            return None, "容器资源 cgroup 路径越出受控目录"
        events_path = boundary / "cgroup.events"
        if not events_path.is_file():
            return None, "运行时容器边界缺少 cgroup.events"
        events = events_path.read_text(encoding="ascii", errors="ignore")
        if not re.search(r"(?m)^populated 1\s*$", events):
            return None, "容器资源 cgroup 当前没有活动进程"
        return boundary, ""
    except (OSError, RuntimeError, StopIteration, ValueError) as exc:
        return None, f"无法读取容器资源 cgroup 证据：{type(exc).__name__}"
