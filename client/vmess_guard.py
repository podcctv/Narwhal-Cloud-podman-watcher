"""Conservative, namespace-local VMess inbound port guard for Incus/Podman.

Only a VMess endpoint that is present in a completely parsed live process
configuration and matched to the same PID/transport/port listener is eligible.
The guard drops that transport/port in the container's own network namespace;
it never signals or restarts a process or container.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess

try:
    from client import socks_detector
except ImportError:
    import socks_detector


SUPPORTED_RUNTIMES = {"incus", "podman"}
SUPPORTED_ENGINES = {"xray", "v2ray", "sing-box"}
MAX_ENDPOINTS = 32


def _integer(value, minimum=1, maximum=65535):
    if isinstance(value, bool):
        return 0
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return number if minimum <= number <= maximum else 0


def _publicly_reachable_listener(listener, network_exposure):
    local = str(listener.get("local") or "")
    host, port = socks_detector.endpoint(local)
    if not host or not port:
        return False
    if not socks_detector.loopback(host):
        return True
    return socks_detector.exposed({"local": local}, network_exposure) is True


def plan(runtime, configured_protocols, listeners, network_exposure=None, scan_state="unavailable",
         process_scan_states=None, listener_inventory_complete=None):
    """Build only unambiguous VMess targets from config+live listener evidence."""
    runtime = str(runtime or "").strip().lower()
    configured_protocols = configured_protocols if isinstance(configured_protocols, list) else []
    listeners = listeners if isinstance(listeners, list) else []
    network_exposure = network_exposure if isinstance(network_exposure, list) else []
    vmess = []
    for item in configured_protocols[:100]:
        if not isinstance(item, dict) or str(item.get("protocol") or "").lower() != "vmess":
            continue
        pid = _integer(item.get("pid"), 2, 4194304)
        port = _integer(item.get("port"))
        process = str(item.get("process") or "").lower()
        if pid and port and process in SUPPORTED_ENGINES:
            vmess.append({"pid": pid, "process": process, "port": port, "listen": str(item.get("listen") or "*")})
    detected = bool(vmess)
    result = {
        "detected": detected,
        "state": "not_detected",
        "blocked_endpoints": [],
        "pending_endpoints": [],
        "release_eligible": False,
    }
    has_scoped_scan_states = isinstance(process_scan_states, list)
    listener_snapshot_complete = (
        listener_inventory_complete is True
        if has_scoped_scan_states
        else listener_inventory_complete is not False
    )
    if not detected:
        if scan_state == "complete" and listener_snapshot_complete:
            result["release_eligible"] = runtime in SUPPORTED_RUNTIMES
            return result
        result.update(state="unverified", reason="configuration_scan_incomplete")
        return result
    if runtime not in SUPPORTED_RUNTIMES:
        result.update(state="unverified", reason="runtime_not_supported")
        return result
    if not listener_snapshot_complete:
        result.update(state="unverified", reason="listener_inventory_incomplete")
        result["pending_endpoints"] = [{"port": item["port"], "process": item["process"], "reason": "listener_inventory_incomplete"} for item in vmess[:20]]
        return result

    process_states = None
    if has_scoped_scan_states:
        process_states = {
            (_integer(item.get("pid"), 2, 4194304), str(item.get("process") or "").lower()):
                str(item.get("state") or "partial").lower()
            for item in process_scan_states if isinstance(item, dict)
        }
    if process_states is None and scan_state != "complete":
        # Compatibility for callers that only provide the historical aggregate
        # scan state. The Agent now supplies process-scoped evidence below.
        result.update(state="unverified", reason="configuration_scan_incomplete")
        result["pending_endpoints"] = [{"port": item["port"], "process": item["process"], "reason": "configuration_scan_incomplete"} for item in vmess[:20]]
        return result

    desired = {}
    pending = []
    saw_loopback_only = False
    for configured in vmess:
        pid, process, port = configured["pid"], configured["process"], configured["port"]
        if process_states is not None and process_states.get((pid, process)) != "complete":
            pending.append({"port": port, "process": process, "reason": "configuration_scan_incomplete"})
            continue
        configured_transports = None
        for item in configured_protocols:
            if not isinstance(item, dict):
                continue
            if (
                _integer(item.get("pid"), 2, 4194304) == pid
                and str(item.get("process") or "").lower() == process
                and _integer(item.get("port")) == port
                and str(item.get("protocol") or "").lower() == "vmess"
            ):
                transports = item.get("transports")
                configured_transports = set(transports) if isinstance(transports, list) and all(x in {"tcp", "udp"} for x in transports) else None
                break

        matches = [item for item in listeners if isinstance(item, dict)
                   and _integer(item.get("pid"), 2, 4194304) == pid
                   and str(item.get("process") or "").lower() == process
                   and _integer(item.get("port")) == port
                   and str(item.get("proto") or "").lower() in {"tcp", "udp"}
                   and (configured_transports is None or str(item.get("proto") or "").lower() in configured_transports)]
        if not matches:
            pending.append({"port": port, "process": process, "reason": "live_listener_not_confirmed"})
            continue

        for listener in matches:
            transport = str(listener.get("proto") or "").lower()
            protocols = listener.get("application_protocols")
            protocols = {str(value).lower() for value in protocols} if isinstance(protocols, list) else set()
            if listener.get("application_protocol_evidence") != "config_matches_live_pid_and_port" or protocols != {"vmess"}:
                pending.append({"port": port, "process": process, "reason": "listener_protocol_or_owner_ambiguous"})
                continue

            config_collision = False
            for item in configured_protocols:
                if not isinstance(item, dict):
                    continue
                if (_integer(item.get("pid"), 2, 4194304) != pid
                        or str(item.get("process") or "").lower() != process
                        or _integer(item.get("port")) != port
                        or str(item.get("protocol") or "").lower() == "vmess"):
                    continue
                transports = item.get("transports")
                if not isinstance(transports, list) or transport in transports:
                    config_collision = True
                    break
            if config_collision:
                pending.append({"port": port, "proto": transport, "process": process, "reason": "shared_configured_port"})
                continue

            co_listeners = [item for item in listeners if isinstance(item, dict)
                            and str(item.get("proto") or "").lower() == transport
                            and _integer(item.get("port")) == port]
            if any(
                _integer(item.get("pid"), 2, 4194304) != pid
                or str(item.get("process") or "").lower() != process
                or item.get("application_protocol_evidence") != "config_matches_live_pid_and_port"
                or not isinstance(item.get("application_protocols"), list)
                or {str(value).lower() for value in item["application_protocols"]} != {"vmess"}
                for item in co_listeners
            ):
                pending.append({"port": port, "proto": transport, "process": process, "reason": "shared_live_listener"})
                continue

            if not _publicly_reachable_listener(listener, network_exposure):
                saw_loopback_only = True
                continue
            key = (transport, port)
            desired[key] = {"proto": transport, "port": port, "pid": pid, "process": process}

    blocked = [desired[key] for key in sorted(desired)]
    result["blocked_endpoints"] = blocked
    result["pending_endpoints"] = pending[:20]
    if blocked and pending:
        result.update(state="partial", reason="some_endpoints_are_ambiguous")
    elif blocked:
        result["state"] = "candidate"
    elif saw_loopback_only and not pending:
        result.update(state="internal_only", reason="loopback_only_listener")
    elif pending:
        result.update(state="unverified", reason=pending[0]["reason"])
    else:
        result["state"] = "not_detected"
    return result


def _pid_epoch(pid):
    try:
        namespace = os.readlink(f"/proc/{pid}/ns/net")
        if namespace == os.readlink("/proc/1/ns/net"):
            return ""
        with open("/proc/sys/kernel/random/boot_id", encoding="utf-8") as handle:
            boot = handle.read().strip()
        with open(f"/proc/{pid}/stat", encoding="utf-8") as handle:
            start = handle.read().rsplit(")", 1)[1].split()[19]
        return f"{boot}:{namespace}:{pid}:{start}"
    except (OSError, ValueError, IndexError):
        return ""


def _open_namespace_fd(pid, expected_epoch):
    """Pin the verified network namespace so PID reuse cannot redirect nft."""
    if _pid_epoch(pid) != expected_epoch:
        return None
    try:
        namespace_fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    except OSError:
        return None
    if _pid_epoch(pid) != expected_epoch:
        os.close(namespace_fd)
        return None
    return namespace_fd


def _owned_endpoints(readback, marker):
    """Extract only protocol/port tuples from this guard's owned nft comments."""
    pattern = re.compile(re.escape(marker) + r'-(tcp|udp)-([0-9]{1,5})(?=[^0-9]|$)')
    endpoints = set()
    for transport, raw_port in pattern.findall(str(readback or "")):
        port = _integer(raw_port)
        if port:
            endpoints.add((transport, port))
    return endpoints


def _firewall_failure_reason(completed, fallback):
    """Map nft errors to safe diagnostic codes; never return command output."""
    if completed is None:
        return fallback
    diagnostic = " ".join(
        str(getattr(completed, field, "") or "") for field in ("stdout", "stderr")
    ).lower()
    if any(token in diagnostic for token in ("operation not permitted", "permission denied", "not permitted")):
        return "firewall_permission_denied"
    if any(token in diagnostic for token in ("operation not supported", "not supported by kernel", "protocol not supported")):
        return "firewall_kernel_unsupported"
    if any(token in diagnostic for token in ("file exists", "resource busy", "device or resource busy")):
        return "firewall_state_conflict"
    if any(token in diagnostic for token in ("syntax error", "unexpected", "invalid argument", "unknown keyword")):
        return "firewall_rule_validation_failed"
    return fallback


def _reconcile_owned_table(prefix, table, marker, endpoint_map, pid, expected_epoch, runner, namespace_fd,
                           *, release_if_absent=False, live_listeners=None, preserve_existing=False):
    result = {"state": "unverified", "blocked_endpoints": [], "reason": "firewall_apply_failed"}

    def call(args, data=None):
        try:
            return runner(args, input=data, capture_output=True, text=True, timeout=5,
                          check=False, pass_fds=(namespace_fd,))
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return None

    current = call(prefix + ["-a", "list", "table", "inet", table])
    exists = current is not None and current.returncode == 0
    if exists and marker not in (current.stdout or ""):
        result["reason"] = "firewall_table_not_owned"
        return result
    if not exists:
        tables = call(prefix + ["-j", "list", "tables"])
        if tables is None or tables.returncode != 0:
            result["reason"] = "firewall_readback_unavailable"
            return result
        try:
            parsed = json.loads(tables.stdout or "{}")
            names = {str(item.get("table", {}).get("name") or "") for item in parsed.get("nftables", []) if isinstance(item, dict)}
        except (TypeError, ValueError):
            result["reason"] = "firewall_readback_invalid"
            return result
        if table in names:
            result["reason"] = "firewall_table_ownership_unverified"
            return result

    existing_endpoints = _owned_endpoints(current.stdout, marker) if exists else set()
    requested_endpoints = set(endpoint_map)
    live = {
        (str(item.get("proto") or "").lower(), _integer(item.get("port")))
        for item in live_listeners if isinstance(item, dict)
    } if isinstance(live_listeners, list) else set()
    if preserve_existing and exists:
        for transport, port in existing_endpoints - requested_endpoints:
            if not isinstance(live_listeners, list) or (transport, port) in live:
                endpoint_map[(transport, port)] = {"proto": transport, "port": port}

    if not endpoint_map:
        if exists and release_if_absent:
            if not isinstance(live_listeners, list):
                result["reason"] = "release_evidence_unavailable"
                return result
            remaining = sorted(existing_endpoints & live)
            if remaining:
                result.update(
                    state="release_pending",
                    reason="guarded_port_still_has_listener",
                    pending_removal_endpoints=[{"proto": proto, "port": port} for proto, port in remaining],
                )
                return result
        if exists:
            removed = call(prefix + ["delete", "table", "inet", table])
            tables = call(prefix + ["-j", "list", "tables"])
            if tables is None or tables.returncode != 0:
                result["reason"] = "firewall_remove_readback_failed"
                return result
            try:
                parsed = json.loads(tables.stdout or "{}")
                names = {str(item.get("table", {}).get("name") or "") for item in parsed.get("nftables", []) if isinstance(item, dict)}
            except (TypeError, ValueError):
                result["reason"] = "firewall_remove_readback_invalid"
                return result
            if table in names:
                result.update(
                    state="release_pending" if release_if_absent else "unverified",
                    reason="firewall_remove_failed" if removed is None or removed.returncode != 0 else "firewall_remove_readback_failed",
                    pending_removal_endpoints=[{"proto": proto, "port": port} for proto, port in sorted(existing_endpoints)],
                )
                return result
        if _pid_epoch(pid) != expected_epoch:
            result["reason"] = "container_namespace_changed"
            return result
        return {"state": "cleared", "blocked_endpoints": [], "reason": ""}

    if len(endpoint_map) > MAX_ENDPOINTS:
        result["reason"] = "endpoint_limit_exceeded"
        return result

    lines = []
    if exists:
        lines.append(f"delete table inet {table}")
    lines.append(f"add table inet {table}")
    lines.append(f"add chain inet {table} input {{ type filter hook input priority -20; policy accept; }}")
    for transport, port in sorted(endpoint_map):
        lines.append(
            f'add rule inet {table} input meta l4proto {transport} {transport} dport {port} drop comment "{marker}-{transport}-{port}"'
        )
    script = "\n".join(lines) + "\n"
    checked = call(prefix + ["--check", "-f", "-"], script)
    if checked is None or checked.returncode != 0:
        result["reason"] = _firewall_failure_reason(checked, "firewall_rule_validation_failed")
        return result
    applied = call(prefix + ["-f", "-"], script)
    if applied is None or applied.returncode != 0:
        result["reason"] = _firewall_failure_reason(applied, "firewall_apply_failed")
        return result
    readback = call(prefix + ["-a", "list", "table", "inet", table])
    if readback is None or readback.returncode != 0 or marker not in (readback.stdout or ""):
        result["reason"] = _firewall_failure_reason(readback, "firewall_readback_failed")
        return result
    for transport, port in endpoint_map:
        if f"{marker}-{transport}-{port}" not in (readback.stdout or ""):
            result["reason"] = "firewall_rule_readback_incomplete"
            return result
    if _pid_epoch(pid) != expected_epoch:
        # The descriptor pins the namespace, so cleanup cannot touch a newly
        # reused PID's network. A fresh collection can re-apply if still valid.
        removed = call(prefix + ["delete", "table", "inet", table])
        result["reason"] = "container_namespace_changed" if removed is not None and removed.returncode == 0 else "container_namespace_changed_cleanup_failed"
        return result
    return {"state": "blocked", "blocked_endpoints": [endpoint_map[key] for key in sorted(endpoint_map)], "reason": ""}


def reconcile(pid, identity, expected_epoch, endpoints, *, host_network=False, runner=None, nsenter_path=None,
              nft_path=None, release_if_absent=False, live_listeners=None, preserve_existing=False):
    """Atomically reconcile an owned nft table in one isolated network namespace."""
    result = {"state": "unverified", "blocked_endpoints": [], "reason": "firewall_apply_failed"}
    if type(pid) is not int or pid <= 1 or not isinstance(identity, str) or not identity:
        result["reason"] = "container_identity_unavailable"
        return result
    if host_network:
        result["reason"] = "shared_network_namespace"
        return result
    if not expected_epoch or _pid_epoch(pid) != expected_epoch:
        result["reason"] = "container_namespace_changed_or_shared"
        return result
    nsenter_path = nsenter_path or shutil.which("nsenter")
    nft_path = nft_path or shutil.which("nft")
    if not nsenter_path or not nft_path:
        result["reason"] = "firewall_dependency_unavailable"
        return result
    endpoint_map = {}
    for item in endpoints if isinstance(endpoints, list) else []:
        if not isinstance(item, dict):
            continue
        transport = str(item.get("proto") or "").lower()
        port = _integer(item.get("port"))
        if transport in {"tcp", "udp"} and port:
            endpoint_map[(transport, port)] = {"proto": transport, "port": port}
    if len(endpoint_map) > MAX_ENDPOINTS:
        result["reason"] = "endpoint_limit_exceeded"
        return result

    digest = hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()[:12]
    table = f"narwhal_vmess_{digest}"
    marker = f"narwhal-vmess-guard-v1-{digest}"
    namespace_fd = _open_namespace_fd(pid, expected_epoch)
    if namespace_fd is None:
        result["reason"] = "container_namespace_changed_or_unavailable"
        return result
    try:
        prefix = [nsenter_path, f"--net=/proc/self/fd/{namespace_fd}", "--", nft_path]
        return _reconcile_owned_table(
            prefix, table, marker, endpoint_map, pid, expected_epoch,
            runner or subprocess.run, namespace_fd, release_if_absent=release_if_absent,
            live_listeners=live_listeners, preserve_existing=preserve_existing,
        )
    finally:
        try:
            os.close(namespace_fd)
        except OSError:
            pass
