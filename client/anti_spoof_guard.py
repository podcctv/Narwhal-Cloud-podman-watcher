"""Host-side Veth Anti-IP Spoofing guard for container interfaces.

Enforces source address validation on the host veth interface of Runman,
Incus, and Podman containers via host nftables and strict kernel rp_filter.
Prevents containers from generating raw spoofed packets or forging external IPs.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable

JOURNAL_PATH = os.getenv("NARWHAL_ANTI_SPOOF_JOURNAL", "/var/lib/narwhal-agent/anti-spoof.json")
_SAFE_VETH = re.compile(r"^[A-Za-z0-9_.-]{1,16}$")
_SAFE_KEY = re.compile(r"^[A-Za-z0-9_.:@+-]{1,256}$")
NFT_TABLE = "narwhal_antispoof"


class AntiSpoofError(RuntimeError):
    pass


def _read_journal(path: str = JOURNAL_PATH) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise AntiSpoofError(f"无法读取反欺骗日志: {exc}") from None
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024 * 1024:
            raise AntiSpoofError("反欺骗日志格式无效")
        try:
            data = json.load(stream)
        except Exception:
            raise AntiSpoofError("反欺骗日志 JSON 损坏")
    if not isinstance(data, dict) or len(data) > 1000:
        raise AntiSpoofError("反欺骗日志结构不合规")
    return data


def _write_journal(data: dict[str, Any], path: str = JOURNAL_PATH) -> None:
    if len(data) > 1000:
        raise AntiSpoofError("反欺骗日志超出容量")
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    if os.path.lexists(path) and os.path.islink(path):
        raise AntiSpoofError("拒绝向符号链接写入日志")
    fd, temp_file = tempfile.mkstemp(prefix=".anti-spoof-", dir=directory)
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
        raise AntiSpoofError(f"持久化日志失败: {exc}") from exc


def _parse_valid_ips(raw_ips: list[str]) -> tuple[list[str], list[str]]:
    v4: list[str] = []
    v6: list[str] = []
    for item in raw_ips:
        if not isinstance(item, str):
            continue
        item = item.strip()
        if not item:
            continue
        try:
            addr = ipaddress.ip_address(item)
            if addr.is_loopback:
                continue
            if addr.version == 4:
                v4.append(str(addr))
            else:
                v6.append(str(addr))
        except ValueError:
            continue
    return sorted(set(v4)), sorted(set(v6))


def apply_anti_spoof(
    veth_name: str,
    allocated_ips: list[str],
    runtime: str = "runman",
    name: str = "",
    *,
    runner: Callable[[list[str]], tuple[bool, str]] | None = None,
    nft_bin: str | None = None,
) -> tuple[bool, str]:
    """Apply host-side source IP filtering and strict rp_filter on container veth."""
    veth = str(veth_name or "").strip()
    if not veth or not _SAFE_VETH.fullmatch(veth):
        return False, f"无效的网卡接口名: {veth}"

    v4_ips, v6_ips = _parse_valid_ips(allocated_ips)
    if not v4_ips and not v6_ips:
        return False, "未提供已分配的有效 IPv4 / IPv6 列表，无法构建白名单"

    nft = nft_bin or shutil.which("nft")
    def default_runner(cmd: list[str]) -> tuple[bool, str]:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return res.returncode == 0, res.stdout + res.stderr
        except Exception as e:
            return False, str(e)

    run_cmd = runner or default_runner

    # 1. Enable strict kernel reverse-path filtering
    run_cmd(["sysctl", "-w", f"net.ipv4.conf.{veth}.rp_filter=1"])

    # 2. Add nftables anti-spoof rules if nft is available
    if nft:
        init_table = f"table inet {NFT_TABLE} {{\n    chain forward {{\n        type filter hook forward priority -10; policy accept;\n    }}\n}}\n"
        try:
            if runner is None:
                subprocess.run([nft, "-f", "-"], input=init_table, text=True, timeout=5)
            else:
                run_cmd([nft, f"table inet {NFT_TABLE}"])
        except Exception:
            pass

        # Build veth rules
        rules: list[str] = []
        if v4_ips:
            v4_set = ", ".join(v4_ips)
            rules.append(f"add rule inet {NFT_TABLE} forward iifname \"{veth}\" ip saddr != {{ {v4_set} }} drop")
        if v6_ips:
            v6_set = ", ".join(v6_ips)
            rules.append(f"add rule inet {NFT_TABLE} forward iifname \"{veth}\" ip6 saddr != {{ {v6_set} }} drop")
        else:
            rules.append(f"add rule inet {NFT_TABLE} forward iifname \"{veth}\" ip6 drop")

        for rule in rules:
            run_cmd([nft] + rule.split()[1:])

    journal = _read_journal()
    journal[veth] = {
        "status": "active",
        "runtime": runtime,
        "name": name,
        "veth": veth,
        "v4_ips": v4_ips,
        "v6_ips": v6_ips,
        "applied_at": int(time.time()),
    }
    _write_journal(journal)
    return True, f"已在接口 {veth} 启用源地址防伪造保护 (允许 v4: {len(v4_ips)}个, v6: {len(v6_ips)}个)"


def release_anti_spoof(
    veth_name: str,
    runtime: str = "runman",
    name: str = "",
    *,
    runner: Callable[[list[str]], tuple[bool, str]] | None = None,
    nft_bin: str | None = None,
) -> tuple[bool, str]:
    """Release anti-spoofing filter and restore default rp_filter."""
    veth = str(veth_name or "").strip()
    if not veth or not _SAFE_VETH.fullmatch(veth):
        return False, f"无效的网卡接口名: {veth}"

    def default_runner(cmd: list[str]) -> tuple[bool, str]:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return res.returncode == 0, res.stdout + res.stderr
        except Exception as e:
            return False, str(e)

    run_cmd = runner or default_runner
    run_cmd(["sysctl", "-w", f"net.ipv4.conf.{veth}.rp_filter=2"])

    nft = nft_bin or shutil.which("nft")
    if nft:
        # Flush rules associated with this veth
        run_cmd([nft, "delete", "table", "inet", NFT_TABLE])

    journal = _read_journal()
    journal.pop(veth, None)
    _write_journal(journal)
    return True, f"已在接口 {veth} 解除源地址防伪造过滤"


def get_anti_spoof_status(veth_name: str) -> dict[str, Any]:
    """Inspect whether anti-spoofing is currently active on this veth."""
    veth = str(veth_name or "").strip()
    journal = _read_journal()
    entry = journal.get(veth)
    return {
        "active": entry is not None and entry.get("status") == "active",
        "v4_ips": entry.get("v4_ips", []) if isinstance(entry, dict) else [],
        "v6_ips": entry.get("v6_ips", []) if isinstance(entry, dict) else [],
        "applied_at": entry.get("applied_at") if isinstance(entry, dict) else None,
    }


def get_anti_spoof_status_for_container(runtime: str, name: str, veth_name: str = "") -> dict[str, Any]:
    """Lookup anti-spoof status by container identity or veth name."""
    runtime_name = str(runtime or "").strip().lower()
    container_name = str(name or "").strip()
    journal = _read_journal()
    if veth_name and veth_name in journal:
        entry = journal[veth_name]
        return {
            "active": entry.get("status") == "active",
            "veth": veth_name,
            "v4_ips": entry.get("v4_ips", []),
            "v6_ips": entry.get("v6_ips", []),
            "applied_at": entry.get("applied_at"),
        }
    for veth, entry in journal.items():
        if isinstance(entry, dict) and entry.get("runtime") == runtime_name and entry.get("name") == container_name:
            return {
                "active": entry.get("status") == "active",
                "veth": veth,
                "v4_ips": entry.get("v4_ips", []),
                "v6_ips": entry.get("v6_ips", []),
                "applied_at": entry.get("applied_at"),
            }
    return {"active": False, "veth": "", "v4_ips": [], "v6_ips": [], "applied_at": None}
