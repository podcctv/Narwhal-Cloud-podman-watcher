"""Conservative, namespace-local VMess inbound port guard for Incus/Podman.

Only a VMess endpoint that is present in a completely parsed live process
configuration and matched to the same PID/transport/port listener is eligible.
The guard drops that transport/port in the container's own network namespace;
it never signals or restarts a process or container.
"""
import hashlib
import json
import os
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


def plan(runtime, configured_protocols, listeners, network_exposure=None, scan_state="unavailable"):
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
    result = {"detected": detected, "state": "not_detected", "blocked_endpoints": [], "pending_endpoints": []}
    if not detected:
        if scan_state == "complete":
            return result
        result.update(state="unverified", reason="configuration_scan_incomplete")
        return result
    if runtime not in SUPPORTED_RUNTIMES:
        result.update(state="unverified", reason="runtime_not_supported")
        return result
    if scan_state != "complete":
        result.update(state="unverified", reason="configuration_scan_incomplete")
        result["pending_endpoints"] = [{"port": item["port"], "process": item["process"], "reason": "configuration_scan_incomplete"} for item in vmess[:20]]
        return result

    desired = {}
    pending = []
    saw_loopback_only = False
    for configured in vmess:
        pid, process, port = configured["pid"], configured["process"], configured["port"]
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


def _reconcile_owned_table(prefix, table, marker, endpoint_map, pid, expected_epoch, runner, namespace_fd):
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

    if not endpoint_map:
        if exists:
            removed = call(prefix + ["delete", "table", "inet", table])
            if removed is None or removed.returncode != 0:
                result["reason"] = "firewall_remove_failed"
                return result
        if _pid_epoch(pid) != expected_epoch:
            result["reason"] = "container_namespace_changed"
            return result
        return {"state": "cleared", "blocked_endpoints": [], "reason": ""}

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
        result["reason"] = "firewall_rule_validation_failed"
        return result
    applied = call(prefix + ["-f", "-"], script)
    if applied is None or applied.returncode != 0:
        result["reason"] = "firewall_apply_failed"
        return result
    readback = call(prefix + ["-a", "list", "table", "inet", table])
    if readback is None or readback.returncode != 0 or marker not in (readback.stdout or ""):
        result["reason"] = "firewall_readback_failed"
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


def reconcile(pid, identity, expected_epoch, endpoints, *, host_network=False, runner=None, nsenter_path=None, nft_path=None):
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
            runner or subprocess.run, namespace_fd,
        )
    finally:
        try:
            os.close(namespace_fd)
        except OSError:
            pass
