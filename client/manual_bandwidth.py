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
import uuid
from typing import Any, Callable


STATE_PATH = os.getenv(
    "NARWHAL_MANUAL_BANDWIDTH_STATE",
    "/var/lib/narwhal-monitor/manual-bandwidth-limits.json",
)
PREFS = {"download": 49150, "upload": 49151}
MAX_POLICIES = 256
MAX_RATE_MBPS = 100_000


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
    return {
        "schema": 1, "host_id": host_id, "expected_node_id": node_id,
        "revision": _valid_int(policy.get("revision", 0), 0, 2**31 - 1),
        "limits": normalized,
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
    code, listing = _call(prefix, ["tc", "filter", "show", "dev", interface, direction])
    if code != 0:
        raise BandwidthPolicyError("cannot verify existing filters on interface")
    return listing


def _filter_present(listing: str, handle: str, pref: int) -> bool:
    for block in re.split(r"(?=filter protocol )", listing):
        if re.search(rf"\bhandle\s+{re.escape(handle)}\b", block) and re.search(rf"\bpref\s+{pref}\b", block):
            return True
    return False


def _apply_filter(
    prefix: list[str], interface: str, owner_key: str, direction: str,
    rate_mbps: int, previously_owned: bool,
) -> None:
    handle = _handle(owner_key, direction)
    pref = PREFS[direction]
    listing = _filter_listing(prefix, interface, direction)
    exists = _filter_present(listing, handle, pref)
    if exists and not previously_owned:
        raise BandwidthPolicyError("reserved filter identity already exists; left unchanged")
    _ensure_clsact(prefix, interface)
    verb = "replace" if exists and previously_owned else "add"
    code, message = _call(prefix, [
        "tc", "filter", verb, "dev", interface, direction,
        "protocol", "all", "pref", str(pref), "handle", handle,
        "matchall", "action", "police", "rate", f"{rate_mbps}mbit",
        "burst", "256k", "conform-exceed", "drop",
    ])
    if code != 0:
        raise BandwidthPolicyError("bandwidth policer was not confirmed: " + (message or "tc failed")[:240])
    verified = _filter_listing(prefix, interface, direction)
    if not _filter_present(verified, handle, pref) or "police" not in verified:
        raise BandwidthPolicyError("bandwidth policer readback did not confirm the filter")


def _remove_filter(prefix: list[str], interface: str, owner_key: str, direction: str) -> bool:
    handle = _handle(owner_key, direction)
    pref = PREFS[direction]
    listing = _filter_listing(prefix, interface, direction)
    if not _filter_present(listing, handle, pref):
        return False
    code, message = _call(prefix, [
        "tc", "filter", "del", "dev", interface, direction,
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
    except (TypeError, ValueError, KeyError, IndexError):
        interface_index = 0
    if interface_index <= 0:
        raise BandwidthPolicyError("container interface index could not be verified")
    return {
        "key": key, "owner_key": f"{host_id}:{key}", "scope": "container",
        "runtime": item["runtime"], "project": item["project"],
        "container_name": item["container_name"], "container_id": item["container_id"],
        "prefix": prefix, "pid": pid, "process_generation": generation.split(":", 1)[0],
        "interface": interface, "interface_index": interface_index,
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
    for direction in ("download", "upload"):
        if _remove_filter(prefix, interface, str(entry.get("owner_key") or ""), direction):
            removed.append(direction)
    return removed


def reconcile(
    policy: Any,
    host_id: str,
    node_id: str,
    containers: list[dict[str, Any]],
    *,
    state_path: str = STATE_PATH,
    resolve: Callable[..., dict[str, Any]] = _resolve_entry,
) -> dict[str, Any]:
    """Apply the current server policy and remove only filters recorded as ours."""
    state = _read_state(state_path)
    if state.get("host_id") not in ("", host_id) or state.get("expected_node_id") not in ("", node_id):
        state = {"schema": 1, "host_id": host_id, "expected_node_id": node_id, "entries": {}}
    state.update(host_id=host_id, expected_node_id=node_id)
    entries = state["entries"]
    status: dict[str, Any] = {"revision": 0, "state": "unconfigured", "items": []}
    try:
        normalized = validate_policy(policy, host_id, node_id)
    except BandwidthPolicyError as exc:
        status.update(state="rejected", message=str(exc))
        return status
    status["revision"] = normalized["revision"]
    desired: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    requested_keys = set()
    failures = False
    for item in normalized["limits"]:
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
            installed = []
            for direction in ("download", "upload"):
                rate = int(item[f"{direction}_mbps"])
                owned = bool(same_target and old and direction in old.get("directions", []))
                if rate:
                    _apply_filter(target["prefix"], target["interface"], target["owner_key"], direction, rate, owned)
                    installed.append(direction)
                    if not owned:
                        newly_installed.append((target, direction))
                elif owned:
                    _remove_filter(target["prefix"], target["interface"], target["owner_key"], direction)
            entries[key] = {**target, "directions": installed}
            status["items"].append({"scope": item["scope"], "target": item.get("container_name", item.get("interface")),
                                    "interface": target["interface"], "download_mbps": item["download_mbps"],
                                    "upload_mbps": item["upload_mbps"], "state": "applied"})
        except (BandwidthPolicyError, OSError, ValueError) as exc:
            failures = True
            status["items"].append({"scope": item["scope"], "target": item.get("container_name", item.get("interface")),
                                    "state": "failed", "message": str(exc)[:240]})
    status["state"] = "failed" if failures else "applied" if desired else "unconfigured"
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
        status.update(
            state="failed",
            message="local ownership state could not be saved; " + ("rollback was not confirmed" if rollback_failed else "new filters were rolled back"),
        )
    return status


def last_status(state_path: str = STATE_PATH) -> dict[str, Any]:
    state = _read_state(state_path)
    status = state.get("status")
    return status if isinstance(status, dict) else {"revision": 0, "state": "unconfigured", "items": []}
