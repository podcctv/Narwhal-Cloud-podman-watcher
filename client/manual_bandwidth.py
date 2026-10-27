"""Safe, opt-in bandwidth policing for a host interface or one container netns.

This deliberately uses only an agent-owned ``clsact`` filter. It never replaces
the interface root qdisc and never removes filters it cannot prove it owns.
Rates are policers (excess packets are dropped), not queue-based shaping.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import time
import uuid
from typing import Any, Callable


STATE_PATH = os.getenv(
    "NARWHAL_MANUAL_BANDWIDTH_STATE",
    "/var/lib/narwhal-monitor/manual-bandwidth-limits.json",
)
PREFS = {"download": 49150, "upload": 49151}
TC_DIRECTIONS = {"download": "ingress", "upload": "egress"}
MAX_POLICIES = 256
MAX_RATE_MBPS = 100_000
AUTO_THRESHOLD_PERCENT = 80
AUTO_TRIGGER_SECONDS = 300
AUTO_TIER_PERCENTAGES = (50, 25, 5)
AUTO_MINIMUM_MBPS = 1
AUTO_RECOVERY_PERCENT = 50
AUTO_RECOVERY_SECONDS = 600


class BandwidthPolicyError(ValueError):
    pass


def _runner(args: list[str], timeout: float = 8) -> tuple[int, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return 127, "command unavailable or timed out"
    return result.returncode, (result.stdout or result.stderr or "").strip()[:2000]


def _valid_int(value: Any, minimum: int = 0, maximum: int = MAX_RATE_MBPS) -> int:
    if type(value) is not int:
        raise BandwidthPolicyError("invalid rate")
    number = value
    if number < minimum or number > maximum:
        raise BandwidthPolicyError("rate is outside the supported range")
    return number


def validate_policy(policy: Any, host_id: str, node_id: str) -> dict[str, Any]:
    if not isinstance(policy, dict) or policy.get("schema") != 1:
        raise BandwidthPolicyError("unsupported bandwidth policy")
    if policy.get("host_id") != host_id or policy.get("expected_node_id") != node_id:
        raise BandwidthPolicyError("bandwidth policy host identity mismatch")
    limits = policy.get("limits")
    if not isinstance(limits, list) or len(limits) > MAX_POLICIES:
        raise BandwidthPolicyError("invalid bandwidth policy list")
    normalized: list[dict[str, Any]] = []
    identities: set[str] = set()
    host_limits = 0
    for item in limits:
        if not isinstance(item, dict):
            raise BandwidthPolicyError("invalid bandwidth policy item")
        scope = item.get("scope")
        upload = _valid_int(item.get("upload_mbps", 0))
        download = _valid_int(item.get("download_mbps", 0))
        if upload == 0 and download == 0:
            raise BandwidthPolicyError("at least one direction needs a non-zero rate")
        if scope == "host":
            interface = str(item.get("interface") or "")
            if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,15}", interface):
                raise BandwidthPolicyError("invalid host interface")
            entry = {"scope": "host", "interface": interface}
            key = f"host:{interface}"
            host_limits += 1
        elif scope == "container":
            runtime = str(item.get("runtime") or "")
            project = str(item.get("project") or "")
            name = str(item.get("container_name") or "")
            container_id = str(item.get("container_id") or "")
            if runtime not in {"incus", "podman"}:
                raise BandwidthPolicyError("only Incus and Podman containers can be limited")
            if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,200}", name):
                raise BandwidthPolicyError("invalid container name")
            if project and not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", project):
                raise BandwidthPolicyError("invalid Incus project")
            if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,256}", container_id):
                raise BandwidthPolicyError("container ID is required")
            entry = {
                "scope": "container", "runtime": runtime, "project": project,
                "container_name": name, "container_id": container_id,
            }
            key = "container:" + "\0".join((runtime, project, name, container_id))
        else:
            raise BandwidthPolicyError("scope must be host or container")
        if key in identities:
            raise BandwidthPolicyError("duplicate bandwidth target")
        identities.add(key)
        normalized.append({**entry, "upload_mbps": upload, "download_mbps": download})
    if host_limits > 1:
        raise BandwidthPolicyError("only one host interface can be configured")
    auto_policy = policy.get("auto_throttle")
    if auto_policy is None:
        auto_enabled = host_limits == 1
    elif isinstance(auto_policy, dict) and type(auto_policy.get("enabled")) is bool:
        auto_enabled = bool(auto_policy["enabled"])
    else:
        raise BandwidthPolicyError("invalid automatic bandwidth protection setting")
    if auto_enabled and host_limits != 1:
        raise BandwidthPolicyError("automatic container limiting requires one host bandwidth interface")
    return {
        "schema": 1, "host_id": host_id, "expected_node_id": node_id,
        "revision": _valid_int(policy.get("revision", 0), 0, 2**31 - 1),
        "limits": normalized, "auto_throttle": {"enabled": auto_enabled},
    }


def _read_state(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, ValueError, TypeError):
        return {"schema": 1, "host_id": "", "expected_node_id": "", "entries": {}}
    if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("entries"), dict):
        return {"schema": 1, "host_id": "", "expected_node_id": "", "entries": {}}
    return value


def _write_state(path: str, state: dict[str, Any]) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd = -1
    temp_path = ""
    for _ in range(8):
        temp_path = os.path.join(directory, f".manual-bandwidth-{os.getpid()}-{uuid.uuid4().hex}.tmp")
        try:
            fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            continue
    if fd < 0:
        raise OSError("unable to create a unique bandwidth state temporary file")
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            os.chmod(temp_path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, ensure_ascii=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass


def _container_target(
    item: dict[str, Any], containers: list[dict[str, Any]],
) -> tuple[list[str], int, str, str]:
    match = next((c for c in containers if
        c.get("runtime") == item["runtime"]
        and str(c.get("project") or "") == item["project"]
        and c.get("name") == item["container_name"]
        and str(c.get("id") or "") == item["container_id"]), None)
    if not match:
        raise BandwidthPolicyError("container identity is not present in the current runtime inventory")
    pid = _container_process_pid(item, match)
    if pid <= 1:
        raise BandwidthPolicyError("container is not running or its init PID is unavailable")
    try:
        namespace_inode = str(os.stat(f"/proc/{pid}/ns/net").st_ino)
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as stream:
            start_ticks = _proc_start_ticks(stream.read())
    except (OSError, IndexError, ValueError):
        raise BandwidthPolicyError("container process identity could not be verified") from None
    prefix = ["nsenter", "--target", str(pid), "--net"]
    code, output = _runner(prefix + ["ip", "-j", "route", "show", "default"])
    if code != 0:
        raise BandwidthPolicyError("container default network interface is unavailable")
    try:
        routes = json.loads(output)
    except (TypeError, ValueError):
        routes = []
    interfaces = [r.get("dev") for r in routes if isinstance(r, dict)]
    interface = next((name for name in interfaces if isinstance(name, str)
                      and re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,15}", name)), "")
    if not interface:
        raise BandwidthPolicyError("container has no verified default route interface")
    return prefix, pid, namespace_inode, start_ticks + ":" + interface


def _container_process_pid(item: dict[str, Any], match: dict[str, Any]) -> int:
    pid = int(match.get("pid") or 0)
    if item["runtime"] == "podman" and pid <= 1:
        runtime_bin = str(match.get("runtime_bin") or "podman")
        if not re.fullmatch(r"[A-Za-z0-9_./+-]{1,240}", runtime_bin):
            raise BandwidthPolicyError("Podman runtime executable could not be verified")
        code, output = _runner([runtime_bin, "inspect", "--format", "{{.Id}}|{{.State.Pid}}", item["container_name"]])
        fields = output.split("|", 1)
        if code != 0 or len(fields) != 2 or not fields[0].startswith(item["container_id"]):
            raise BandwidthPolicyError("Podman container ID or state could not be verified")
        try:
            pid = int(fields[1])
        except ValueError:
            pid = 0
    if pid <= 1:
        raise BandwidthPolicyError("container is not running or its init PID is unavailable")
    return pid


def _proc_start_ticks(raw: str) -> str:
    # /proc/PID/stat field 2 is parenthesized and may contain spaces. Split
    # after its final ')' so field 22 (starttime) remains at offset 19.
    close = raw.rfind(")")
    if close < 0:
        raise ValueError("malformed proc stat")
    fields_after_comm = raw[close + 1:].split()
    value = fields_after_comm[19]
    if not value.isdigit():
        raise ValueError("invalid proc start time")
    return value


def _call(prefix: list[str], args: list[str]) -> tuple[int, str]:
    return _runner(prefix + args)


def _ensure_clsact(prefix: list[str], interface: str) -> None:
    code, listing = _call(prefix, ["tc", "qdisc", "show", "dev", interface])
    if code == 0 and re.search(r"\bclsact\b", listing):
        return
    add_code, message = _call(prefix, ["tc", "qdisc", "add", "dev", interface, "clsact"])
    if add_code != 0:
        code, listing = _call(prefix, ["tc", "qdisc", "show", "dev", interface])
        if code != 0 or not re.search(r"\bclsact\b", listing):
            raise BandwidthPolicyError("cannot add an agent-managed clsact qdisc: " + (message or "tc failed")[:240])


def _handle(owner_key: str, direction: str) -> str:
    digest = hashlib.sha256((owner_key + "\0" + direction).encode()).hexdigest()[:7]
    return "0x6" + digest


def _filter_listing(prefix: list[str], interface: str, direction: str) -> str:
    tc_direction = TC_DIRECTIONS.get(direction)
    if not tc_direction:
        raise BandwidthPolicyError("invalid bandwidth direction")
    code, listing = _call(prefix, ["tc", "filter", "show", "dev", interface, tc_direction])
    if code != 0:
        raise BandwidthPolicyError("cannot verify existing filters on interface")
    return listing


def _filter_present(listing: str, handle: str, pref: int) -> bool:
    for block in re.split(r"(?=filter protocol )", listing):
        if re.search(rf"\bhandle\s+{re.escape(handle)}\b", block) and re.search(rf"\bpref\s+{pref}\b", block):
            return True
    return False


def _filter_has_police_action(
    listing: str, handle: str, pref: int, rate_mbps: int | None = None,
) -> bool:
    for block in re.split(r"(?=filter protocol )", listing):
        if not (re.search(rf"\bhandle\s+{re.escape(handle)}\b", block)
                and re.search(rf"\bpref\s+{pref}\b", block)
                and "police" in block):
            continue
        if rate_mbps is None:
            return True
        match = re.search(
            r"\brate\s+([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?bit(?:/s)?|[kmgt]?bps)\b",
            block, re.IGNORECASE,
        )
        if not match:
            continue
        unit = match.group(2).casefold().replace("/s", "")
        multipliers = {
            "bit": 1, "bps": 1,
            "kbit": 1_000, "kbps": 1_000,
            "mbit": 1_000_000, "mbps": 1_000_000,
            "gbit": 1_000_000_000, "gbps": 1_000_000_000,
            "tbit": 1_000_000_000_000, "tbps": 1_000_000_000_000,
        }
        actual_mbps = float(match.group(1)) * multipliers.get(unit, 0) / 1_000_000
        if abs(actual_mbps - rate_mbps) <= max(0.001, rate_mbps * 0.001):
            return True
    return False


def _filter_preference(listing: str, handle: str) -> int | None:
    for block in re.split(r"(?=filter protocol )", listing):
        if not re.search(rf"\bhandle\s+{re.escape(handle)}\b", block):
            continue
        match = re.search(r"\bpref\s+(\d+)\b", block)
        if match:
            preference = int(match.group(1))
            if 1 <= preference <= 65535:
                return preference
    return None


def _occupied_preferences(listing: str) -> set[int]:
    return {int(value) for value in re.findall(r"\bpref\s+(\d+)\b", listing)
            if 1 <= int(value) <= 65535}


def _next_free_preference(listing: str, direction: str, preferred: int | None = None) -> int:
    occupied = _occupied_preferences(listing)
    first = preferred if type(preferred) is int and 49150 <= preferred < 65535 else PREFS[direction]
    # Keep Narwhal filters in the high-priority-number range. This avoids
    # displacing existing filters and lets tc evaluate pre-existing rules first.
    candidates = [first, *(value for value in range(49150, 65535) if value != first)]
    return next((value for value in candidates if value not in occupied), 0)


def _apply_filter(
    prefix: list[str], interface: str, owner_key: str, direction: str,
    rate_mbps: int, previously_owned: bool, preferred_pref: int | None = None,
) -> int:
    handle = _handle(owner_key, direction)
    tc_direction = TC_DIRECTIONS.get(direction)
    if not tc_direction:
        raise BandwidthPolicyError("invalid bandwidth direction")
    _ensure_clsact(prefix, interface)
    listing = _filter_listing(prefix, interface, direction)
    owned_pref = _filter_preference(listing, handle)
    if owned_pref is not None and not previously_owned:
        raise BandwidthPolicyError("reserved filter identity already exists; left unchanged")
    pref = owned_pref if owned_pref is not None else _next_free_preference(
        listing, direction, preferred_pref if preferred_pref is not None else PREFS[direction],
    )
    if not pref:
        raise BandwidthPolicyError("no free tc filter priority is available on this interface")
    # Existing owned filters are changed in place. `replace` can return EEXIST
    # on kernels with a competing filter at the same priority even when this
    # handle is ours; `change` targets the verified filter identity without
    # creating or replacing a foreign filter. New filters retry free priorities.
    for _attempt in range(5):
        replacing_owned = previously_owned and owned_pref == pref
        verb = "change" if replacing_owned else "add"
        code, message = _call(prefix, [
            "tc", "filter", verb, "dev", interface, tc_direction,
            "protocol", "all", "pref", str(pref), "handle", handle,
            "matchall", "action", "police", "rate", f"{rate_mbps}mbit",
            "burst", "256k", "conform-exceed", "drop",
        ])
        if code == 0:
            verified = _filter_listing(prefix, interface, direction)
            if not _filter_has_police_action(verified, handle, pref, rate_mbps):
                raise BandwidthPolicyError(
                    f"bandwidth policer readback did not confirm {rate_mbps} Mbps at priority {pref}"
                )
            return pref
        if replacing_owned and "file exists" in message.casefold():
            verified = _filter_listing(prefix, interface, direction)
            if _filter_has_police_action(verified, handle, pref, rate_mbps):
                # Netlink may report an already-applied identical change as
                # EEXIST. Trust only an exact owned-handle rate readback.
                return pref
            raise BandwidthPolicyError(
                f"owned bandwidth filter change failed at priority {pref}; "
                f"readback did not confirm {rate_mbps} Mbps: {(message or 'tc failed')[:180]}"
            )
        if verb == "add" and "file exists" in message.casefold():
            listing = _filter_listing(prefix, interface, direction)
            if _filter_preference(listing, handle) is not None:
                raise BandwidthPolicyError("filter identity appeared during apply; left unchanged")
            pref = _next_free_preference(listing, direction, pref + 1 if pref < 65535 else None)
            if pref:
                continue
            raise BandwidthPolicyError("no free tc filter priority is available on this interface")
        raise BandwidthPolicyError(
            f"bandwidth policer was not confirmed (tc filter {verb}, priority {pref}, {direction}): "
            + (message or "tc failed")[:200]
        )
    raise BandwidthPolicyError("tc filter priorities kept colliding; no foreign filter was changed")


def _remove_filter(
    prefix: list[str], interface: str, owner_key: str, direction: str,
    preferred_pref: int | None = None,
) -> bool:
    handle = _handle(owner_key, direction)
    tc_direction = TC_DIRECTIONS.get(direction)
    if not tc_direction:
        raise BandwidthPolicyError("invalid bandwidth direction")
    listing = _filter_listing(prefix, interface, direction)
    # Search for the deterministic owned handle, not only the current
    # preferred priority. This also cleans up rules created by older agents.
    pref = preferred_pref if type(preferred_pref) is int and _filter_present(listing, handle, preferred_pref) else _filter_preference(listing, handle)
    if pref is None:
        return False
    code, message = _call(prefix, [
        "tc", "filter", "del", "dev", interface, tc_direction,
        "protocol", "all", "pref", str(pref), "handle", handle,
    ])
    if code != 0:
        raise BandwidthPolicyError("owned bandwidth filter could not be removed: " + (message or "tc failed")[:240])
    if _filter_present(_filter_listing(prefix, interface, direction), handle, pref):
        raise BandwidthPolicyError("owned bandwidth filter remains after removal")
    return True


def _resolve_entry(
    host_id: str, item: dict[str, Any], containers: list[dict[str, Any]],
) -> dict[str, Any]:
    if item["scope"] == "host":
        interface = item["interface"]
        try:
            interface_index = socket.if_nametoindex(interface)
        except OSError:
            raise BandwidthPolicyError("selected host interface no longer exists") from None
        return {
            "key": f"host:{interface}", "owner_key": f"{host_id}:host:{interface}",
            "scope": "host", "prefix": [], "interface": interface,
            "interface_index": interface_index, "namespace_inode": "host",
        }
    identity = "\0".join((item["runtime"], item["project"], item["container_name"], item["container_id"]))
    key = "container:" + identity
    prefix, pid, namespace_inode, generation = _container_target(item, containers)
    interface = generation.split(":", 1)[1]
    code, output = _call(prefix, ["ip", "-j", "link", "show", "dev", interface])
    if code != 0:
        raise BandwidthPolicyError("container interface disappeared during verification")
    try:
        links = json.loads(output)
        interface_index = int(links[0]["ifindex"]) if links and isinstance(links[0], dict) else 0
        peer_index = int(links[0].get("link_index") or links[0].get("iflink") or 0) if links and isinstance(links[0], dict) else 0
    except (TypeError, ValueError, KeyError, IndexError):
        interface_index = 0
        peer_index = 0
    if interface_index <= 0:
        raise BandwidthPolicyError("container interface index could not be verified")
    return {
        "key": key, "owner_key": f"{host_id}:{key}", "scope": "container",
        "runtime": item["runtime"], "project": item["project"],
        "container_name": item["container_name"], "container_id": item["container_id"],
        "prefix": prefix, "pid": pid, "process_generation": generation.split(":", 1)[0],
        "interface": interface, "interface_index": interface_index, "peer_index": peer_index,
        "namespace_inode": namespace_inode,
    }


def _remove_entry(entry: dict[str, Any], expected_host: str, actual_host: str, actual_node: str) -> list[str]:
    # Policies are bound to an enrollment. A replacement node with the same
    # display name must never remove or inherit the former machine's filters.
    if expected_host != actual_host or entry.get("expected_node_id") != actual_node:
        return []
    interface = str(entry.get("interface") or "")
    if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,15}", interface):
        return []
    prefix = entry.get("prefix") if isinstance(entry.get("prefix"), list) else []
    if entry.get("scope") == "host":
        try:
            if socket.if_nametoindex(interface) != int(entry.get("interface_index") or 0):
                return []
        except (OSError, TypeError, ValueError):
            return []
    else:
        try:
            if os.stat(f"/proc/{int(entry.get('pid') or 0)}/ns/net").st_ino != int(entry.get("namespace_inode") or 0):
                return []
            code, output = _call(prefix, ["ip", "-j", "link", "show", "dev", interface])
            links = json.loads(output) if code == 0 else []
            current_index = int(links[0]["ifindex"]) if links and isinstance(links[0], dict) else 0
            if current_index != int(entry.get("interface_index") or 0):
                return []
        except (OSError, TypeError, ValueError):
            # The old container namespace no longer exists; its tc rules died
            # with it, so forgetting the local record is safe.
            return []
    removed = []
    preferences = entry.get("filter_prefs") if isinstance(entry.get("filter_prefs"), dict) else {}
    for direction in ("download", "upload"):
        if _remove_filter(prefix, interface, str(entry.get("owner_key") or ""), direction,
                          preferences.get(direction)):
            removed.append(direction)
    return removed


def _identity(item: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(item.get("runtime") or ""), str(item.get("project") or ""),
        str(item.get("name") or item.get("container_name") or ""),
        str(item.get("id") or item.get("container_id") or ""),
    )


def _container_identity_key(identity: tuple[str, str, str, str]) -> str:
    return "\0".join(identity)


def _finite_rate(value: Any) -> float | None:
    try:
        rate = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return rate if rate >= 0 and rate < 1e15 else None


def _auto_tier_rates(base_mbps: int) -> list[int]:
    """Return descending per-container caps, ending at 1 Mbps where possible."""
    rates: list[int] = []
    for percentage in AUTO_TIER_PERCENTAGES:
        rate = max(AUTO_MINIMUM_MBPS, int(base_mbps * percentage / 100))
        if rate < base_mbps and (not rates or rate < rates[-1]):
            rates.append(rate)
    if base_mbps > AUTO_MINIMUM_MBPS and (not rates or rates[-1] > AUTO_MINIMUM_MBPS):
        rates.append(AUTO_MINIMUM_MBPS)
    return rates


def _sysfs_host_links() -> tuple[dict[int, dict[str, Any]], str]:
    """Read host veth peer/master metadata without depending on iproute2 JSON support."""
    root = "/sys/class/net"
    try:
        names = os.listdir(root)
    except OSError as exc:
        return {}, f"cannot read {root}: {exc}"
    links: dict[int, dict[str, Any]] = {}
    for name in names[:512]:
        if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,15}", name):
            continue
        base = os.path.join(root, name)
        try:
            with open(os.path.join(base, "ifindex"), "r", encoding="ascii") as handle:
                index = int(handle.read().strip())
        except (OSError, ValueError):
            continue
        try:
            with open(os.path.join(base, "iflink"), "r", encoding="ascii") as handle:
                peer_index = int(handle.read().strip())
        except (OSError, ValueError):
            peer_index = index
        try:
            master = os.path.basename(os.readlink(os.path.join(base, "master")))
        except OSError:
            master = ""
        if index > 0:
            links[index] = {
                "ifname": name, "ifindex": index, "link_index": peer_index,
                "iflink": peer_index, "master": master,
            }
    return links, "" if links else f"{root} contained no readable interfaces"


def _proc_default_routes() -> set[str]:
    """Fallback route inventory for minimal iproute2 builds."""
    result: set[str] = set()
    try:
        with open("/proc/net/route", "r", encoding="ascii") as handle:
            for line in handle.read().splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 4 and fields[1] == "00000000":
                    try:
                        is_up = bool(int(fields[3], 16) & 0x1)
                    except ValueError:
                        is_up = False
                    if is_up and re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,15}", fields[0]):
                        result.add(fields[0])
    except OSError:
        pass
    try:
        with open("/proc/net/ipv6_route", "r", encoding="ascii") as handle:
            for line in handle.read().splitlines():
                fields = line.split()
                if (len(fields) >= 10 and not fields[0].strip("0") and fields[1] == "00"
                        and re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,15}", fields[9])):
                    result.add(fields[9])
    except OSError:
        pass
    return result


def _host_link_snapshot() -> tuple[dict[int, dict[str, Any]], set[str], str]:
    code, output = _runner(["ip", "-j", "link", "show"])
    link_error = f"ip -j link show failed ({code}): {output}" if code != 0 else ""
    try:
        raw_links = json.loads(output)
    except (TypeError, ValueError):
        raw_links = None
        link_error = "ip -j link show returned invalid JSON"
    # Some minimal iproute2 builds expose the same link fields only through
    # `address show`; try that read-only source before disabling auto mapping.
    if not isinstance(raw_links, list) or not raw_links:
        fallback_code, fallback_output = _runner(["ip", "-j", "address", "show"])
        try:
            fallback_links = json.loads(fallback_output)
        except (TypeError, ValueError):
            fallback_links = None
        if fallback_code == 0 and isinstance(fallback_links, list):
            raw_links = fallback_links
            link_error = ""
        else:
            link_error += f"; ip -j address show failed ({fallback_code}): {fallback_output}"
    if not isinstance(raw_links, list) or not raw_links:
        sysfs_links, sysfs_error = _sysfs_host_links()
        if sysfs_links:
            return_links = sysfs_links
            link_error = ""
        else:
            return {}, set(), (link_error + "; " + sysfs_error)[:500]
    else:
        return_links = {}
    if not return_links:
        for item in raw_links[:512]:
            if not isinstance(item, dict):
                continue
            try:
                index = int(item.get("ifindex") or 0)
            except (TypeError, ValueError):
                continue
            name = str(item.get("ifname") or "")
            if index > 0 and re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,15}", name):
                return_links[index] = item
    if not return_links:
        sysfs_links, sysfs_error = _sysfs_host_links()
        if not sysfs_links:
            return {}, set(), (link_error or "link inventory contained no valid interfaces") + "; " + sysfs_error
        return_links = sysfs_links
        link_error = ""
    code, output = _runner(["ip", "-j", "route", "show", "default"])
    defaults: set[str] = set()
    if code == 0:
        try:
            routes = json.loads(output)
        except (TypeError, ValueError):
            routes = []
        for route in routes if isinstance(routes, list) else []:
            if isinstance(route, dict):
                name = str(route.get("dev") or "")
                if re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,15}", name):
                    defaults.add(name)
    route_error = f"ip -j route show default failed ({code}): {output}" if code != 0 else ""
    if not defaults:
        defaults.update(_proc_default_routes())
        if defaults:
            route_error = ""
    return return_links, defaults, route_error[:500]


def _uses_selected_host_interface(
    selected: str, target: dict[str, Any], host_links: dict[int, dict[str, Any]],
    default_routes: set[str], bridge_inventory: list[dict[str, Any]],
) -> bool:
    try:
        peer_index = int(target.get("peer_index") or 0)
    except (TypeError, ValueError):
        peer_index = 0
    peer = host_links.get(peer_index)
    if not peer:
        return False
    peer_name = str(peer.get("ifname") or "")
    master = peer.get("master")
    if isinstance(master, int):
        master_link = host_links.get(master) or {}
        master = master_link.get("ifname")
    master_name = str(master or "")
    if peer_name == selected or master_name == selected:
        return True
    if selected not in default_routes:
        return False
    runtime_bridges = {
        str(item.get("name") or "")
        for item in bridge_inventory
        if isinstance(item, dict) and item.get("kind") == "bridge"
        and isinstance(item.get("runtimes"), list)
        and any(runtime in {"incus", "podman"} for runtime in item.get("runtimes", []))
    }
    # A selected default-route NIC also covers containers attached to a
    # runtime-owned bridge, whose external route is forwarded by the host.
    return bool(master_name and master_name in runtime_bridges)


def _auto_sample_map(samples: list[dict[str, Any]]) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    result: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        identity = _identity(sample)
        if identity[0] in {"incus", "podman"} and identity[2] and identity[3]:
            result[identity] = sample
    return result


def _advance_direction(
    record: dict[str, Any], base_mbps: int, usage_mbps: float,
    sample_at: int, sample_window_seconds: int,
) -> None:
    tiers = _auto_tier_rates(base_mbps)
    if record.get("base_mbps") is not None and int(record.get("base_mbps") or 0) != base_mbps:
        record.update(stage=0, high_seconds=0, low_seconds=0)
    record["base_mbps"] = base_mbps
    if not tiers:
        record.update(stage=0, high_seconds=0, low_seconds=0, last_sample_at=sample_at)
        return
    stage = max(0, min(int(record.get("stage") or 0), len(tiers)))
    window = max(1, min(86_400, int(sample_window_seconds or 1)))
    current_limit = tiers[stage - 1] if stage else base_mbps
    high_threshold = current_limit * AUTO_THRESHOLD_PERCENT / 100.0
    recovery_threshold = current_limit * AUTO_RECOVERY_PERCENT / 100.0
    if stage < len(tiers) and usage_mbps >= high_threshold:
        high_seconds = max(0, int(record.get("high_seconds") or 0)) + window
        record["low_seconds"] = 0
        if high_seconds >= AUTO_TRIGGER_SECONDS:
            record["stage"] = stage + 1
            record["high_seconds"] = 0
            record["low_seconds"] = 0
        else:
            record["high_seconds"] = high_seconds
    elif stage > 0 and usage_mbps < recovery_threshold:
        low_seconds = max(0, int(record.get("low_seconds") or 0)) + window
        record["high_seconds"] = 0
        if low_seconds >= AUTO_RECOVERY_SECONDS:
            record["stage"] = stage - 1
            record["low_seconds"] = 0
        else:
            record["low_seconds"] = low_seconds
    else:
        record.update(high_seconds=0, low_seconds=0)
    record["last_sample_at"] = sample_at
    record["last_usage_mbps"] = round(usage_mbps, 3)


def _automatic_limits(
    auto_policy: dict[str, Any], host_limit: dict[str, Any] | None,
    host_id: str, node_id: str, containers: list[dict[str, Any]],
    traffic_samples: list[dict[str, Any]], sample_at: int,
    sample_interval_seconds: int, bridge_inventory: list[dict[str, Any]],
    state: dict[str, Any], resolve: Callable[..., dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    enabled = bool(auto_policy.get("enabled")) and isinstance(host_limit, dict)
    interface = str(host_limit.get("interface") or "") if enabled else ""
    auto_state = state.get("auto_throttle_state")
    if not isinstance(auto_state, dict) or auto_state.get("interface") != interface:
        auto_state = {"interface": interface, "last_sample_at": 0, "containers": {}}
    tracked = auto_state.get("containers")
    if not isinstance(tracked, dict):
        tracked = {}
    if not enabled:
        auto_state = {"interface": "", "last_sample_at": sample_at,
                      "containers": {}, "status": "disabled"}
        state["auto_throttle_state"] = auto_state
        return [], {
            "enabled": False, "state": "disabled", "interface": "",
            "threshold_percent": AUTO_THRESHOLD_PERCENT,
            "trigger_seconds": AUTO_TRIGGER_SECONDS,
            "tier_percentages": list(AUTO_TIER_PERCENTAGES),
            "minimum_mbps": AUTO_MINIMUM_MBPS,
            "recovery_percent": AUTO_RECOVERY_PERCENT,
            "recovery_seconds": AUTO_RECOVERY_SECONDS,
            "items": [],
        }

    candidates = {
        _identity(item): item for item in containers if isinstance(item, dict)
        and _identity(item)[0] in {"incus", "podman"}
        and _identity(item)[2] and _identity(item)[3]
    }
    current_sample = max(0, int(sample_at or 0))
    previous_sample = int(auto_state.get("last_sample_at") or 0)
    new_sample = current_sample > previous_sample
    if new_sample:
        samples = _auto_sample_map(traffic_samples)
        host_links, default_routes, host_network_error = _host_link_snapshot()
        mapping_reason = "host_link_inventory_unavailable" if not host_links else ""
        if host_network_error and not mapping_reason:
            mapping_reason = "host_route_inventory_unavailable"
        mapped_identities: set[tuple[str, str, str, str]] = set()
        unmapped_identities: set[tuple[str, str, str, str]] = set()
        unavailable_samples = 0
        namespace_owners: dict[str, list[tuple[str, str, str, str]]] = {}
        try:
            host_namespace_inode = str(os.stat("/proc/1/ns/net").st_ino)
        except OSError:
            host_namespace_inode = ""
            mapping_reason = "host_namespace_unavailable"
        for identity, candidate in candidates.items():
            item = {
                "scope": "container", "runtime": identity[0], "project": identity[1],
                "container_name": identity[2], "container_id": identity[3],
                "upload_mbps": 1, "download_mbps": 1,
            }
            key = _container_identity_key(identity)
            previous = tracked.get(key) if isinstance(tracked.get(key), dict) else {}
            try:
                target = resolve(host_id, item, containers)
            except (BandwidthPolicyError, OSError, ValueError) as exc:
                unmapped_identities.add(identity)
                if previous:
                    previous["sampling_state"] = "target_unavailable"
                    previous["message"] = str(exc)[:180]
                    tracked[key] = previous
                continue
            namespace_inode = str(target.get("namespace_inode") or "")
            if not namespace_inode or not host_namespace_inode or namespace_inode == host_namespace_inode:
                unmapped_identities.add(identity)
                if previous:
                    previous.update(state="unmapped", sampling_state="unsafe_shared_namespace",
                                    upload_stage=0, download_stage=0,
                                    directions={"upload": {}, "download": {}})
                    if not host_namespace_inode:
                        previous["sampling_state"] = "host_namespace_unavailable"
                    tracked[key] = previous
                continue
            shared_with = namespace_owners.setdefault(namespace_inode, [])
            if shared_with:
                shared_identities = [*shared_with, identity]
                for shared_identity in shared_identities:
                    mapped_identities.discard(shared_identity)
                    unmapped_identities.add(shared_identity)
                    shared_key = _container_identity_key(shared_identity)
                    shared_record = tracked.get(shared_key)
                    if isinstance(shared_record, dict):
                        shared_record.update(state="unmapped", sampling_state="shared_network_namespace",
                                             directions={"upload": {}, "download": {}})
                        tracked[shared_key] = shared_record
                shared_with.append(identity)
                continue
            shared_with.append(identity)
            if not _uses_selected_host_interface(interface, target, host_links, default_routes, bridge_inventory):
                unmapped_identities.add(identity)
                if previous:
                    previous.update(state="unmapped", sampling_state="interface_unmapped",
                                    upload_stage=0, download_stage=0,
                                    directions={"upload": {}, "download": {}})
                    tracked[key] = previous
                continue
            mapped_identities.add(identity)
            sample = samples.get(identity)
            sample_rates = sample.get("traffic_counters") if isinstance(sample, dict) and isinstance(sample.get("traffic_counters"), dict) else {}
            if sample_rates.get("available") is not True:
                unavailable_samples += 1
                if previous:
                    previous["sampling_state"] = "unavailable"
                    tracked[key] = previous
                continue
            generation = str(target.get("process_generation") or "")
            interface_index = int(target.get("interface_index") or 0)
            same_process = bool(previous and previous.get("process_generation") == generation
                                and previous.get("namespace_inode") == namespace_inode
                                and previous.get("interface_index") == interface_index)
            record = previous if same_process else {
                "identity": list(identity), "process_generation": generation,
                "namespace_inode": namespace_inode, "interface_index": interface_index,
                "network_interface": target.get("interface"),
                "directions": {"upload": {}, "download": {}},
            }
            for direction, rate_key, base_key in (
                ("upload", "net_tx_bps", "upload_mbps"),
                ("download", "net_rx_bps", "download_mbps"),
            ):
                base = int(host_limit.get(base_key) or 0)
                rate = _finite_rate(sample.get(rate_key))
                if base <= 0 or rate is None:
                    record.setdefault("directions", {}).pop(direction, None)
                    continue
                direction_state = record.setdefault("directions", {}).setdefault(direction, {})
                if int(direction_state.get("last_sample_at") or 0) >= current_sample:
                    continue
                _advance_direction(
                    direction_state, base, rate * 8 / 1_000_000,
                    current_sample, sample_interval_seconds,
                )
            record.update(
                identity=list(identity), process_generation=generation,
                namespace_inode=namespace_inode, interface_index=interface_index,
                network_interface=target.get("interface"), state="limited" if any(
                    int(value.get("stage") or 0) > 0
                    for value in record.get("directions", {}).values() if isinstance(value, dict)
                ) else "monitoring", sampling_state="healthy", last_sample_at=current_sample,
            )
            tracked[key] = record
        auto_state["last_sample_at"] = current_sample
        auto_state["status"] = "monitoring"
        auto_state["mapped_containers"] = len(mapped_identities)
        auto_state["unmapped_containers"] = len(unmapped_identities)
        auto_state["unavailable_samples"] = unavailable_samples
        auto_state["mapping_reason"] = mapping_reason
        auto_state["mapping_error"] = host_network_error[:500] if mapping_reason and host_network_error else ""
    # Prune long-departed identities, but keep recent ones so a transient runtime
    # inventory failure cannot remove a limiter that is already protecting a container.
    for key, record in list(tracked.items()):
        if not isinstance(record, dict):
            tracked.pop(key, None)
            continue
        last_sample = int(record.get("last_sample_at") or 0)
        if current_sample and last_sample and current_sample - last_sample > 86_400:
            tracked.pop(key, None)
    auto_state["containers"] = tracked
    state["auto_throttle_state"] = auto_state

    auto_limits: list[dict[str, Any]] = []
    status_items: list[dict[str, Any]] = []
    for key, record in tracked.items():
        identity_value = record.get("identity")
        if not isinstance(identity_value, list) or len(identity_value) != 4:
            continue
        identity = tuple(str(value) for value in identity_value)
        directions = record.get("directions") if isinstance(record.get("directions"), dict) else {}
        rates: dict[str, int] = {}
        base_rates = {"upload": int(host_limit.get("upload_mbps") or 0),
                      "download": int(host_limit.get("download_mbps") or 0)}
        for direction in ("upload", "download"):
            direction_state = directions.get(direction) if isinstance(directions.get(direction), dict) else {}
            stage = int(direction_state.get("stage") or 0)
            tiers = _auto_tier_rates(base_rates[direction])
            if 1 <= stage <= len(tiers):
                rates[direction] = tiers[stage - 1]
        if rates and identity[0] in {"incus", "podman"}:
            auto_limits.append({
                "scope": "container", "runtime": identity[0], "project": identity[1],
                "container_name": identity[2], "container_id": identity[3],
                "upload_mbps": rates.get("upload", 0),
                "download_mbps": rates.get("download", 0),
            })
        if identity[0] in {"incus", "podman"}:
            upload_state = directions.get("upload") if isinstance(directions.get("upload"), dict) else {}
            download_state = directions.get("download") if isinstance(directions.get("download"), dict) else {}
            status_items.append({
                "runtime": identity[0], "project": identity[1],
                "container_name": identity[2], "container_id": identity[3],
                "state": str(record.get("state") or "monitoring"),
                "sampling_state": str(record.get("sampling_state") or "unknown"),
                "network_interface": str(record.get("network_interface") or ""),
                "upload_mbps": rates.get("upload", 0),
                "download_mbps": rates.get("download", 0),
                "upload_current_mbps": float(upload_state.get("last_usage_mbps") or 0),
                "download_current_mbps": float(download_state.get("last_usage_mbps") or 0),
                "upload_baseline_mbps": base_rates["upload"],
                "download_baseline_mbps": base_rates["download"],
                "upload_high_seconds": max(0, int(upload_state.get("high_seconds") or 0)),
                "download_high_seconds": max(0, int(download_state.get("high_seconds") or 0)),
                "upload_low_seconds": max(0, int(upload_state.get("low_seconds") or 0)),
                "download_low_seconds": max(0, int(download_state.get("low_seconds") or 0)),
            })
    status_state = "limited" if auto_limits else "monitoring"
    if auto_state.get("mapping_reason"):
        status_state = "verification_unavailable"
    elif not auto_limits and int(auto_state.get("mapped_containers") or 0) == 0:
        status_state = "no_mapped_containers"
    elif not auto_limits and int(auto_state.get("unavailable_samples") or 0) > 0:
        status_state = "sampling_unavailable"
    status = {
        "enabled": True, "state": status_state, "interface": interface,
        "threshold_percent": AUTO_THRESHOLD_PERCENT,
        "trigger_seconds": AUTO_TRIGGER_SECONDS,
        "tier_percentages": list(AUTO_TIER_PERCENTAGES),
        "minimum_mbps": AUTO_MINIMUM_MBPS,
        "recovery_percent": AUTO_RECOVERY_PERCENT,
        "recovery_seconds": AUTO_RECOVERY_SECONDS,
        "mapped_containers": int(auto_state.get("mapped_containers") or 0),
        "unmapped_containers": int(auto_state.get("unmapped_containers") or 0),
        "unavailable_samples": int(auto_state.get("unavailable_samples") or 0),
        "items": status_items[:500],
    }
    if auto_state.get("mapping_reason") == "host_namespace_unavailable":
        status["message"] = "宿主机网络命名空间不可读，已跳过自动限速路径核验"
    elif auto_state.get("mapping_reason") == "host_link_inventory_unavailable":
        detail = str(auto_state.get("mapping_error") or "")
        status["message"] = "宿主机网卡清单不可读，已跳过自动限速路径核验" + (f"：{detail}" if detail else "")
    elif auto_state.get("mapping_reason") == "host_route_inventory_unavailable":
        detail = str(auto_state.get("mapping_error") or "")
        status["message"] = "宿主机路由清单不可读，无法确认容器是否经过所选网卡，已跳过自动限速路径核验" + (f"：{detail}" if detail else "")
    return auto_limits, status


def _merge_automatic_limits(
    manual_limits: list[dict[str, Any]], automatic_limits: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged = [dict(item) for item in manual_limits]
    by_identity = {
        (item.get("runtime"), str(item.get("project") or ""), item.get("container_name"), item.get("container_id")): index
        for index, item in enumerate(merged) if item.get("scope") == "container"
    }
    for automatic in automatic_limits:
        identity = (automatic.get("runtime"), str(automatic.get("project") or ""),
                    automatic.get("container_name"), automatic.get("container_id"))
        index = by_identity.get(identity)
        if index is None:
            by_identity[identity] = len(merged)
            merged.append(dict(automatic))
            continue
        current = merged[index]
        for direction in ("upload", "download"):
            auto_rate = int(automatic.get(f"{direction}_mbps") or 0)
            if not auto_rate:
                continue
            manual_rate = int(current.get(f"{direction}_mbps") or 0)
            current[f"{direction}_mbps"] = min(manual_rate, auto_rate) if manual_rate else auto_rate
    return merged


def _active_bandwidth_limits(entries: dict[str, Any], previous_status: Any) -> list[dict[str, Any]]:
    """Return last-readback rates for filters whose ownership is still recorded."""
    legacy_rates: dict[tuple[str, str], dict[str, int]] = {}
    legacy_full_rates: dict[tuple[str, str, str, str], dict[str, int]] = {}
    previous_items = previous_status.get("items", []) if isinstance(previous_status, dict) else []
    for item in previous_items if isinstance(previous_items, list) else []:
        if not isinstance(item, dict) or item.get("state") not in {"applied", "partial"}:
            continue
        scope = str(item.get("scope") or "")
        target = str(item.get("target") or item.get("container_name") or item.get("interface") or "")
        if not scope or not target:
            continue
        rates: dict[str, int] = {}
        direction = item.get("direction")
        if direction in {"upload", "download"}:
            try:
                rate = int(item.get("rate_mbps") or 0)
            except (TypeError, ValueError):
                rate = 0
            if rate > 0:
                rates[direction] = rate
        else:
            for name in ("upload", "download"):
                try:
                    rate = int(item.get(f"{name}_mbps") or 0)
                except (TypeError, ValueError):
                    rate = 0
                if rate > 0:
                    rates[name] = rate
        if not rates:
            continue
        legacy_rates[(scope, target)] = {**legacy_rates.get((scope, target), {}), **rates}
        runtime = str(item.get("runtime") or "")
        project = str(item.get("project") or "")
        container_id = str(item.get("container_id") or "")
        if scope == "container" and runtime and container_id:
            key = (scope, runtime, project, container_id)
            legacy_full_rates[key] = {**legacy_full_rates.get(key, {}), **rates}

    active: list[dict[str, Any]] = []
    for entry in entries.values():
        if not isinstance(entry, dict):
            continue
        scope = str(entry.get("scope") or "")
        target = str(entry.get("container_name") or entry.get("interface") or "")
        if scope not in {"host", "container"} or not target:
            continue
        rates = entry.get("rates_mbps") if isinstance(entry.get("rates_mbps"), dict) else {}
        normalized_rates: dict[str, int] = {}
        for direction in ("upload", "download"):
            try:
                rate = int(rates.get(direction) or 0)
            except (TypeError, ValueError):
                rate = 0
            if rate > 0:
                normalized_rates[direction] = rate
        if not normalized_rates:
            if scope == "container":
                full_key = (scope, str(entry.get("runtime") or ""),
                            str(entry.get("project") or ""), str(entry.get("container_id") or ""))
                normalized_rates = dict(legacy_full_rates.get(full_key)
                                        or legacy_rates.get((scope, target), {}))
            else:
                normalized_rates = dict(legacy_rates.get((scope, target), {}))
        if not normalized_rates:
            continue
        active.append({
            "scope": scope, "target": target,
            "interface": str(entry.get("interface") or ""),
            "runtime": str(entry.get("runtime") or ""),
            "project": str(entry.get("project") or ""),
            "container_name": str(entry.get("container_name") or ""),
            "container_id": str(entry.get("container_id") or ""),
            "upload_mbps": normalized_rates.get("upload", 0),
            "download_mbps": normalized_rates.get("download", 0),
            "last_confirmed_at": int(entry.get("last_confirmed_at") or 0),
        })
    return sorted(active, key=lambda item: (item["scope"], item["runtime"], item["container_name"], item["interface"]))


def reconcile(
    policy: Any,
    host_id: str,
    node_id: str,
    containers: list[dict[str, Any]],
    *,
    state_path: str = STATE_PATH,
    resolve: Callable[..., dict[str, Any]] = _resolve_entry,
    traffic_samples: list[dict[str, Any]] | None = None,
    sample_at: int | float = 0,
    sample_interval_seconds: int = 300,
    bridge_inventory: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Apply the current server policy and remove only filters recorded as ours."""
    state = _read_state(state_path)
    if state.get("host_id") not in ("", host_id) or state.get("expected_node_id") not in ("", node_id):
        state = {"schema": 1, "host_id": host_id, "expected_node_id": node_id, "entries": {}}
    state.update(host_id=host_id, expected_node_id=node_id)
    entries = state["entries"]
    previous_status = state.get("status")
    status: dict[str, Any] = {"revision": 0, "state": "unconfigured", "items": []}
    try:
        normalized = validate_policy(policy, host_id, node_id)
    except BandwidthPolicyError as exc:
        status.update(state="rejected", message=str(exc))
        return status
    status["revision"] = normalized["revision"]
    host_limit = next((item for item in normalized["limits"] if item.get("scope") == "host"), None)
    automatic_limits, automatic_status = _automatic_limits(
        normalized.get("auto_throttle") or {}, host_limit, host_id, node_id,
        containers if isinstance(containers, list) else [],
        traffic_samples if isinstance(traffic_samples, list) else [],
        int(sample_at or 0), max(1, int(round(float(sample_interval_seconds or 1)))),
        bridge_inventory if isinstance(bridge_inventory, list) else [], state, resolve,
    )
    effective_limits = _merge_automatic_limits(normalized["limits"], automatic_limits)
    status["auto_throttle"] = automatic_status
    desired: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    requested_keys = set()
    failures = False
    for item in effective_limits:
        if item["scope"] == "host":
            requested_keys.add(f"host:{item['interface']}")
        else:
            requested_keys.add("container:" + "\0".join((item["runtime"], item["project"], item["container_name"], item["container_id"])))
        try:
            target = resolve(host_id, item, containers)
            target["expected_node_id"] = node_id
            desired[target["key"]] = (item, target)
        except (BandwidthPolicyError, OSError, ValueError) as exc:
            failures = True
            status["items"].append({"scope": item["scope"], "target": item.get("container_name", item.get("interface")),
                                    "state": "failed", "message": str(exc)[:240]})

    newly_installed: list[tuple[dict[str, Any], str]] = []
    for key, old in list(entries.items()):
        # A temporarily unavailable target must not silently lose a previously
        # applied limit. Keep the old owned filter until its target can be
        # resolved again or the administrator removes it from policy.
        if key in requested_keys and key not in desired:
            continue
        new = desired.get(key)
        same_netns = bool(new and old.get("namespace_inode") == new[1].get("namespace_inode")
                          and old.get("interface") == new[1].get("interface")
                          and old.get("interface_index") == new[1].get("interface_index"))
        if new and same_netns:
            continue
        try:
            _remove_entry(old, host_id, host_id, node_id)
            entries.pop(key, None)
        except BandwidthPolicyError as exc:
            failures = True
            status["items"].append({"scope": old.get("scope"), "target": old.get("container_name", old.get("interface")),
                                    "state": "cleanup_failed", "message": str(exc)[:240]})

    for key, (item, target) in desired.items():
        old = entries.get(key) if isinstance(entries.get(key), dict) else None
        target = {**target, "expected_node_id": node_id}
        same_target = bool(old and old.get("namespace_inode") == target.get("namespace_inode")
                           and old.get("interface") == target.get("interface")
                           and old.get("interface_index") == target.get("interface_index"))
        try:
            _ensure_clsact(target["prefix"], target["interface"])
        except (BandwidthPolicyError, OSError, ValueError) as exc:
            failures = True
            status["items"].append({"scope": item["scope"], "target": item.get("container_name", item.get("interface")),
                                    "interface": target["interface"], "runtime": item.get("runtime", ""),
                                    "project": item.get("project", ""), "container_name": item.get("container_name", ""),
                                    "container_id": item.get("container_id", ""), "state": "failed",
                                    "message": str(exc)[:240]})
            continue

        old_directions = set(old.get("directions", [])) if same_target and old else set()
        old_rates = dict(old.get("rates_mbps", {})) if same_target and old and isinstance(old.get("rates_mbps"), dict) else {}
        old_prefs = dict(old.get("filter_prefs", {})) if same_target and old and isinstance(old.get("filter_prefs"), dict) else {}
        rates = {direction: int(old_rates[direction]) for direction in old_directions
                 if direction in old_rates and str(old_rates[direction]).isdigit()}
        filter_prefs = {direction: int(old_prefs[direction]) for direction in old_directions
                        if direction in old_prefs and str(old_prefs[direction]).isdigit()}
        confirmed_at = dict(old.get("confirmed_at", {})) if same_target and old and isinstance(old.get("confirmed_at"), dict) else {}
        installed = set(old_directions)
        report_identity = {
            "scope": item["scope"], "target": item.get("container_name", item.get("interface")),
            "interface": target["interface"], "runtime": item.get("runtime", ""),
            "project": item.get("project", ""), "container_name": item.get("container_name", ""),
            "container_id": item.get("container_id", ""),
        }
        for direction in ("download", "upload"):
            rate = int(item[f"{direction}_mbps"])
            owned = direction in old_directions
            try:
                if rate:
                    applied_pref = _apply_filter(
                        target["prefix"], target["interface"], target["owner_key"], direction,
                        rate, owned, filter_prefs.get(direction),
                    )
                    # Keep persisted state JSON-safe if an older integration
                    # wrapper reports success without returning the selected
                    # preference. The production implementation always
                    # returns an integer after kernel readback.
                    if type(applied_pref) is not int or not 49150 <= applied_pref < 65535:
                        previous_pref = filter_prefs.get(direction)
                        applied_pref = previous_pref if type(previous_pref) is int and 49150 <= previous_pref < 65535 else PREFS[direction]
                    installed.add(direction)
                    rates[direction] = rate
                    filter_prefs[direction] = applied_pref
                    confirmed_at[direction] = int(time.time())
                    if not owned:
                        newly_installed.append((target, direction))
                    status["items"].append({**report_identity, "direction": direction,
                                            "rate_mbps": rate, "state": "applied"})
                elif owned:
                    _remove_filter(target["prefix"], target["interface"], target["owner_key"],
                                   direction, filter_prefs.get(direction))
                    installed.discard(direction)
                    rates.pop(direction, None)
                    filter_prefs.pop(direction, None)
                    confirmed_at.pop(direction, None)
                    status["items"].append({**report_identity, "direction": direction,
                                            "rate_mbps": 0, "state": "removed"})
            except (BandwidthPolicyError, OSError, ValueError) as exc:
                failures = True
                # If this direction was owned already, retain its last confirmed
                # readback so the UI never implies that a failed update removed it.
                status["items"].append({**report_identity, "direction": direction,
                                        "rate_mbps": rate, "state": "failed",
                                        "message": str(exc)[:240]})
        if installed:
            entry = {**target, "directions": sorted(installed), "rates_mbps": rates,
                     "filter_prefs": filter_prefs, "confirmed_at": confirmed_at}
            entry["last_confirmed_at"] = max(confirmed_at.values(), default=0)
            entries[key] = entry
        else:
            entries.pop(key, None)
    status["state"] = "failed" if failures else "applied" if desired else "unconfigured"
    status["updated_at"] = int(time.time())
    status["active_limits"] = _active_bandwidth_limits(entries, previous_status)
    state["revision"] = normalized["revision"]
    state["status"] = status
    try:
        _write_state(state_path, state)
    except OSError:
        # If this was a new policy, remove only filters added in this pass.
        # Existing filters remain represented by the previously persisted state.
        rollback_failed = False
        for target, direction in reversed(newly_installed):
            try:
                _remove_filter(target["prefix"], target["interface"], target["owner_key"], direction)
            except BandwidthPolicyError:
                rollback_failed = True
        persisted = _read_state(state_path)
        persisted_entries = persisted.get("entries") if isinstance(persisted.get("entries"), dict) else {}
        status["active_limits"] = _active_bandwidth_limits(persisted_entries, persisted.get("status"))
        status.update(
            state="failed",
            message="local ownership state could not be saved; " + ("rollback was not confirmed" if rollback_failed else "new filters were rolled back"),
        )
    return status


def last_status(state_path: str = STATE_PATH) -> dict[str, Any]:
    state = _read_state(state_path)
    status = state.get("status")
    return status if isinstance(status, dict) else {"revision": 0, "state": "unconfigured", "items": []}
