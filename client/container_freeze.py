"""Reversible, generation-bound container freeze and thaw using cgroup v2.

Safely freezes all processes inside an Incus, Podman, or Runman container
using cgroup v2's ``cgroup.freeze`` and verifies against ``cgroup.events``
without killing processes or dropping in-memory state.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    from client.resource_cgroup import resolve_container_cgroup
except ImportError:
    from resource_cgroup import resolve_container_cgroup


JOURNAL_PATH = os.getenv("NARWHAL_CONTAINER_FREEZE_JOURNAL", "/var/lib/narwhal-agent/container-freeze.json")
_SAFE_KEY = re.compile(r"^[A-Za-z0-9_.:@+-]{1,256}$")
_RUNMAN_ID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class FreezeError(RuntimeError):
    pass


def _read_journal(path: str = JOURNAL_PATH) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise FreezeError(f"无法读取冻结日志: {exc}") from None
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024 * 1024:
            raise FreezeError("冻结日志文件格式无效或过大")
        try:
            data = json.load(stream)
        except Exception:
            raise FreezeError("冻结日志 JSON 格式损坏")
    if not isinstance(data, dict) or len(data) > 1000:
        raise FreezeError("冻结日志内容格式不合规")
    return data


def _write_journal(data: dict[str, Any], path: str = JOURNAL_PATH) -> None:
    if len(data) > 1000:
        raise FreezeError("冻结日志条目超出容量限制")
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    if os.path.lexists(path) and os.path.islink(path):
        raise FreezeError("拒绝向符号链接写入冻结日志")
    fd, temp_file = tempfile.mkstemp(prefix=".freeze-journal-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.chmod(temp_file, 0o600)
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_file, path)
    except Exception as exc:
        try:
            os.unlink(temp_file)
        except OSError:
            pass
        raise FreezeError(f"持久化冻结日志失败: {exc}") from exc


def _read_start_ticks(pid: int, proc_root: str = "/proc") -> str:
    try:
        stat_text = (Path(proc_root) / str(pid) / "stat").read_text(encoding="ascii", errors="ignore")
        close_paren = stat_text.rfind(")")
        stat_fields = stat_text[close_paren + 2 :].split() if close_paren >= 0 else []
        return stat_fields[19] if len(stat_fields) > 19 else ""
    except Exception:
        return ""


def _parse_frozen_state(events_text: str) -> bool:
    for line in events_text.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[0] == "frozen":
            return parts[1] == "1"
    return False


def freeze_container(
    runtime: str,
    name: str,
    pid_value: Any,
    instance_id: str = "",
    expected_start_ticks: str = "",
    *,
    cgroup_root: str | os.PathLike[str] | None = None,
    proc_root: str = "/proc",
    timeout_sec: float = 3.0,
) -> tuple[bool, str]:
    """Freeze all processes in the container cgroup and verify readback."""
    runtime_name = str(runtime or "").strip().lower()
    container_name = str(name or "").strip()
    if runtime_name not in {"incus", "podman", "runman"}:
        return False, f"不支持的运行时: {runtime_name}"
    if not container_name or not _SAFE_KEY.fullmatch(container_name):
        return False, f"容器名称格式无效: {container_name}"

    try:
        pid = int(pid_value or 0)
    except (TypeError, ValueError):
        return False, "容器 PID 无效"
    if pid <= 1:
        return False, "容器 PID 必须大于 1"

    stable_id = instance_id.strip() if instance_id else container_name
    if runtime_name == "runman":
        if not _RUNMAN_ID.fullmatch(container_name):
            return False, "Runman 容器必须为有效 VM UUID"
        if not expected_start_ticks:
            expected_start_ticks = _read_start_ticks(pid, proc_root)
            if not expected_start_ticks:
                return False, "无法从 procfs 读取 Runman 启动代次"

    cgroup_dir, err = resolve_container_cgroup(
        pid,
        runtime_name,
        stable_id,
        container_name,
        proc_root=proc_root,
        cgroup_root=cgroup_root,
        expected_start_ticks=expected_start_ticks,
    )
    if not cgroup_dir or err:
        return False, f"无法定位安全的容器资源 cgroup: {err}"

    freeze_file = cgroup_dir / "cgroup.freeze"
    events_file = cgroup_dir / "cgroup.events"
    if not freeze_file.is_file() or not events_file.is_file():
        return False, "cgroup v2 冻结控制器 (cgroup.freeze / cgroup.events) 不可用"

    journal_key = f"{runtime_name}:{container_name}"
    journal = _read_journal()
    journal[journal_key] = {
        "status": "freezing",
        "runtime": runtime_name,
        "name": container_name,
        "instance_id": stable_id,
        "pid": pid,
        "updated_at": int(time.time()),
    }
    _write_journal(journal)

    try:
        freeze_file.write_text("1\n", encoding="ascii")
    except OSError as exc:
        journal.pop(journal_key, None)
        _write_journal(journal)
        return False, f"写入 cgroup.freeze 失败: {exc}"

    # Poll cgroup.events for frozen 1 confirmation
    deadline = time.monotonic() + timeout_sec
    confirmed = False
    while time.monotonic() < deadline:
        try:
            events = events_file.read_text(encoding="ascii", errors="ignore")
            if _parse_frozen_state(events):
                confirmed = True
                break
        except OSError:
            pass
        time.sleep(0.05)

    if not confirmed:
        # Revert on timeout to avoid ambiguous state
        try:
            freeze_file.write_text("0\n", encoding="ascii")
        except OSError:
            pass
        journal.pop(journal_key, None)
        _write_journal(journal)
        return False, "超时：未能确认容器进入完全冻结状态 (cgroup.events frozen 1)"

    journal[journal_key] = {
        "status": "frozen",
        "runtime": runtime_name,
        "name": container_name,
        "instance_id": stable_id,
        "pid": pid,
        "frozen_at": int(time.time()),
    }
    _write_journal(journal)
    return True, f"容器 {container_name} 已成功挂起冻结，内存现场完好保留"


def unfreeze_container(
    runtime: str,
    name: str,
    pid_value: Any,
    instance_id: str = "",
    expected_start_ticks: str = "",
    *,
    cgroup_root: str | os.PathLike[str] | None = None,
    proc_root: str = "/proc",
    timeout_sec: float = 3.0,
) -> tuple[bool, str]:
    """Unfreeze all processes in the container cgroup and verify readback."""
    runtime_name = str(runtime or "").strip().lower()
    container_name = str(name or "").strip()
    if runtime_name not in {"incus", "podman", "runman"}:
        return False, f"不支持的运行时: {runtime_name}"
    if not container_name or not _SAFE_KEY.fullmatch(container_name):
        return False, f"容器名称格式无效: {container_name}"

    try:
        pid = int(pid_value or 0)
    except (TypeError, ValueError):
        return False, "容器 PID 无效"
    if pid <= 1:
        return False, "容器 PID 必须大于 1"

    stable_id = instance_id.strip() if instance_id else container_name
    if runtime_name == "runman":
        if not _RUNMAN_ID.fullmatch(container_name):
            return False, "Runman 容器必须为有效 VM UUID"
        if not expected_start_ticks:
            expected_start_ticks = _read_start_ticks(pid, proc_root)

    cgroup_dir, err = resolve_container_cgroup(
        pid,
        runtime_name,
        stable_id,
        container_name,
        proc_root=proc_root,
        cgroup_root=cgroup_root,
        expected_start_ticks=expected_start_ticks,
    )
    if not cgroup_dir or err:
        return False, f"无法定位安全的容器资源 cgroup: {err}"

    freeze_file = cgroup_dir / "cgroup.freeze"
    events_file = cgroup_dir / "cgroup.events"
    if not freeze_file.is_file() or not events_file.is_file():
        return False, "cgroup v2 冻结控制器 (cgroup.freeze / cgroup.events) 不可用"

    try:
        freeze_file.write_text("0\n", encoding="ascii")
    except OSError as exc:
        return False, f"写入 cgroup.freeze 解冻失败: {exc}"

    deadline = time.monotonic() + timeout_sec
    confirmed = False
    while time.monotonic() < deadline:
        try:
            events = events_file.read_text(encoding="ascii", errors="ignore")
            if not _parse_frozen_state(events):
                confirmed = True
                break
        except OSError:
            pass
        time.sleep(0.05)

    if not confirmed:
        return False, "超时：未能确认容器解除冻结 (cgroup.events frozen 0)"

    journal_key = f"{runtime_name}:{container_name}"
    journal = _read_journal()
    journal.pop(journal_key, None)
    _write_journal(journal)
    return True, f"容器 {container_name} 已成功解冻恢复运行"


def get_freeze_status(
    runtime: str,
    name: str,
    pid_value: Any,
    instance_id: str = "",
    expected_start_ticks: str = "",
    *,
    cgroup_root: str | os.PathLike[str] | None = None,
    proc_root: str = "/proc",
) -> dict[str, Any]:
    """Read verified cgroup freeze status and journal entry."""
    runtime_name = str(runtime or "").strip().lower()
    container_name = str(name or "").strip()
    if runtime_name not in {"incus", "podman", "runman"} or not container_name:
        return {"supported": False, "reason": "unsupported runtime or name"}

    try:
        pid = int(pid_value or 0)
    except (TypeError, ValueError):
        pid = 0
    if pid <= 1:
        return {"supported": False, "reason": "invalid pid"}

    stable_id = instance_id.strip() if instance_id else container_name
    if runtime_name == "runman" and not expected_start_ticks:
        expected_start_ticks = _read_start_ticks(pid, proc_root)

    cgroup_dir, err = resolve_container_cgroup(
        pid,
        runtime_name,
        stable_id,
        container_name,
        proc_root=proc_root,
        cgroup_root=cgroup_root,
        expected_start_ticks=expected_start_ticks,
    )
    if not cgroup_dir or err:
        return {"supported": False, "reason": err or "cgroup unavailable"}

    freeze_file = cgroup_dir / "cgroup.freeze"
    events_file = cgroup_dir / "cgroup.events"
    if not freeze_file.is_file() or not events_file.is_file():
        return {"supported": False, "reason": "cgroup.freeze not present"}

    try:
        events = events_file.read_text(encoding="ascii", errors="ignore")
        is_frozen = _parse_frozen_state(events)
        journal = _read_journal()
        entry = journal.get(f"{runtime_name}:{container_name}")
        return {
            "supported": True,
            "frozen": is_frozen,
            "journaled": entry is not None,
            "frozen_at": entry.get("frozen_at") if isinstance(entry, dict) else None,
        }
    except Exception as exc:
        return {"supported": False, "reason": str(exc)}

