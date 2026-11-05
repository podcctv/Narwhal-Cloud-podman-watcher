"""Conservative, targeted Egress UDP Blackhole guard for containers.

Applies a precision egress UDP blackhole in the container's network namespace,
dropping outbound UDP floods and amplification attacks while preserving:
- Loopback (lo) traffic
- Inbound traffic and active TCP/SSH connections
- Outbound DNS resolution (UDP port 53, optional)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable

JOURNAL_PATH = os.getenv("NARWHAL_UDP_BLACKHOLE_JOURNAL", "/var/lib/narwhal-agent/udp-blackhole.json")
_SAFE_KEY = re.compile(r"^[A-Za-z0-9_.:@+-]{1,256}$")
NFT_TABLE = "narwhal_udp_guard"


class UdpGuardError(RuntimeError):
    pass


def _read_journal(path: str = JOURNAL_PATH) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise UdpGuardError(f"无法读取 UDP 阻断日志: {exc}") from None
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024 * 1024:
            raise UdpGuardError("UDP 阻断日志格式无效")
        try:
            data = json.load(stream)
        except Exception:
            raise UdpGuardError("UDP 阻断日志 JSON 格式损坏")
    if not isinstance(data, dict) or len(data) > 1000:
        raise UdpGuardError("UDP 阻断日志内容格式不合规")
    return data


def _write_journal(data: dict[str, Any], path: str = JOURNAL_PATH) -> None:
    if len(data) > 1000:
        raise UdpGuardError("UDP 阻断日志超出容量限制")
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    if os.path.lexists(path) and os.path.islink(path):
        raise UdpGuardError("拒绝向符号链接写入日志")
    fd, temp_file = tempfile.mkstemp(prefix=".udp-blackhole-", dir=directory)
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
        raise UdpGuardError(f"持久化日志失败: {exc}") from exc


def _build_nft_rules(allow_dns: bool = True) -> str:
    dns_rule = "        udp dport 53 accept\n" if allow_dns else ""
    return (
        f"table inet {NFT_TABLE} {{\n"
        "    chain output {\n"
        "        type filter hook output priority 0; policy accept;\n"
        "        oif \"lo\" accept\n"
        "        ct state established,related accept\n"
        f"{dns_rule}"
        "        ip protocol udp drop\n"
        "        ip6 nexthdr udp drop\n"
        "    }\n"
        "}\n"
    )


def apply_udp_blackhole(
    runtime: str,
    name: str,
    pid: int = 0,
    instance_id: str = "",
    allow_dns: bool = True,
    project: str = "default",
    *,
    runner: Callable[[list[str]], tuple[bool, str]] | None = None,
    nsenter_bin: str | None = None,
    nft_bin: str | None = None,
    iptables_bin: str | None = None,
) -> tuple[bool, str]:
    """Apply targeted egress UDP drop inside the container network namespace."""
    runtime_name = str(runtime or "").strip().lower()
    container_name = str(name or "").strip()
    if runtime_name not in {"incus", "podman", "runman"}:
        return False, f"不支持的运行时: {runtime_name}"
    if not container_name or not _SAFE_KEY.fullmatch(container_name):
        return False, f"容器名称格式无效: {container_name}"
    if pid <= 1:
        return False, "容器 PID 无效，无法进入 network namespace"

    nsenter = nsenter_bin or shutil.which("nsenter")
    nft = nft_bin or shutil.which("nft")
    iptables = iptables_bin or shutil.which("iptables")

    if not nsenter:
        return False, "宿主机缺少 nsenter 命令"

    def default_runner(cmd: list[str]) -> tuple[bool, str]:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return res.returncode == 0, res.stdout + res.stderr
        except Exception as e:
            return False, str(e)

    run_cmd = runner or default_runner
    rules_applied = False

    # Try nftables first
    if nft:
        nft_content = _build_nft_rules(allow_dns)
        cmd = [nsenter, "-t", str(pid), "-n", "--", nft, "-f", "-"]
        try:
            if runner is None:
                proc = subprocess.run(cmd, input=nft_content, capture_output=True, text=True, timeout=5)
                if proc.returncode == 0:
                    rules_applied = True
            else:
                ok, _ = run_cmd([nsenter, "-t", str(pid), "-n", "--", nft, f"table inet {NFT_TABLE}"])
                rules_applied = ok
        except Exception:
            rules_applied = False

    # Fallback to iptables / ip6tables if nftables failed
    if not rules_applied and iptables:
        dns_part = (
            f"iptables -C OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -p udp --dport 53 -j ACCEPT; "
            f"ip6tables -C OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 1 -p udp --dport 53 -j ACCEPT; "
        ) if allow_dns else ""
        script = (
            f"iptables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -o lo -j ACCEPT; "
            f"iptables -C OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I OUTPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT; "
            f"{dns_part}"
            f"iptables -C OUTPUT -p udp -j DROP 2>/dev/null || iptables -A OUTPUT -p udp -j DROP; "
            f"ip6tables -C OUTPUT -o lo -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 1 -o lo -j ACCEPT; "
            f"ip6tables -C OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT; "
            f"ip6tables -C OUTPUT -p udp -j DROP 2>/dev/null || ip6tables -A OUTPUT -p udp -j DROP"
        )
        ok, msg = run_cmd([nsenter, "-t", str(pid), "-n", "sh", "-c", script])
        rules_applied = ok

    if not rules_applied:
        return False, "应用出站 UDP 黑洞规则失败 (nftables 和 iptables 均无法执行)"

    journal_key = f"{runtime_name}:{container_name}"
    journal = _read_journal()
    journal[journal_key] = {
        "status": "blackholed",
        "runtime": runtime_name,
        "name": container_name,
        "instance_id": instance_id,
        "pid": pid,
        "allow_dns": allow_dns,
        "applied_at": int(time.time()),
    }
    _write_journal(journal)
    dns_note = " (放行 53 端口 DNS 解析)" if allow_dns else " (完全阻断全部 UDP)"
    return True, f"已对容器 {container_name} 实施出站 UDP 专项阻断{dns_note}"


def release_udp_blackhole(
    runtime: str,
    name: str,
    pid: int = 0,
    instance_id: str = "",
    project: str = "default",
    *,
    runner: Callable[[list[str]], tuple[bool, str]] | None = None,
    nsenter_bin: str | None = None,
    nft_bin: str | None = None,
    iptables_bin: str | None = None,
) -> tuple[bool, str]:
    """Release egress UDP blackhole rules and restore full UDP line rate."""
    runtime_name = str(runtime or "").strip().lower()
    container_name = str(name or "").strip()
    if runtime_name not in {"incus", "podman", "runman"} or not container_name:
        return False, "无效的运行时或容器名称"

    journal_key = f"{runtime_name}:{container_name}"
    journal = _read_journal()

    if pid > 1:
        nsenter = nsenter_bin or shutil.which("nsenter")
        nft = nft_bin or shutil.which("nft")
        iptables = iptables_bin or shutil.which("iptables")

        def default_runner(cmd: list[str]) -> tuple[bool, str]:
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return res.returncode == 0, res.stdout + res.stderr
            except Exception as e:
                return False, str(e)

        run_cmd = runner or default_runner
        if nsenter and nft:
            run_cmd([nsenter, "-t", str(pid), "-n", "--", nft, "delete", "table", "inet", NFT_TABLE])

        if nsenter and iptables:
            script = (
                "iptables -D OUTPUT -p udp -j DROP 2>/dev/null || true; "
                "iptables -D OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true; "
                "ip6tables -D OUTPUT -p udp -j DROP 2>/dev/null || true; "
                "ip6tables -D OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true"
            )
            run_cmd([nsenter, "-t", str(pid), "-n", "sh", "-c", script])

    journal.pop(journal_key, None)
    _write_journal(journal)
    return True, f"已解除容器 {container_name} 的出站 UDP 阻断"


def get_udp_blackhole_status(
    runtime: str,
    name: str,
    pid: int = 0,
    *,
    runner: Callable[[list[str]], tuple[bool, str]] | None = None,
    nsenter_bin: str | None = None,
    nft_bin: str | None = None,
) -> dict[str, Any]:
    """Inspect whether egress UDP blackhole is currently active."""
    runtime_name = str(runtime or "").strip().lower()
    container_name = str(name or "").strip()
    journal = _read_journal()
    entry = journal.get(f"{runtime_name}:{container_name}")

    is_active = entry is not None and entry.get("status") == "blackholed"
    if pid > 1 and is_active:
        nsenter = nsenter_bin or shutil.which("nsenter")
        nft = nft_bin or shutil.which("nft")
        if nsenter and nft:
            def default_runner(cmd: list[str]) -> tuple[bool, str]:
                try:
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                    return res.returncode == 0, res.stdout
                except Exception as e:
                    return False, str(e)

            run_cmd = runner or default_runner
            ok, out = run_cmd([nsenter, "-t", str(pid), "-n", "--", nft, "list", "table", "inet", NFT_TABLE])
            if ok and "table inet " + NFT_TABLE in out:
                is_active = True

    return {
        "active": is_active,
        "allow_dns": entry.get("allow_dns", True) if isinstance(entry, dict) else True,
        "applied_at": entry.get("applied_at") if isinstance(entry, dict) else None,
    }

