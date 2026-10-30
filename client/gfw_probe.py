"""Small, bounded TCP reachability worker for signed GFW correlation jobs."""
import hashlib
import ipaddress
import json
import os
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_lock = threading.Lock()
_JOB_ID = re.compile(r"[0-9a-f-]{36}")
_LEASE = re.compile(r"[A-Za-z0-9_-]{32,64}")
_ERRORS = {"", "timeout", "refused", "network_error"}
_FAILURE_CODES = {
    "probe_source_identity_mismatch", "invalid_probe_identity", "invalid_probe_lease",
    "invalid_probe_deadline", "invalid_target_count", "invalid_target_fields",
    "invalid_target_endpoint", "invalid_target_identity", "invalid_targets_hash",
    "incomplete_probe_results", "probe_runtime_unavailable", "probe_worker_busy", "probe_worker_error",
}


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _safe_ip(value):
    try:
        address = ipaddress.ip_address(value)
        return address.is_global and not address.is_multicast
    except (TypeError, ValueError):
        return False


def _safe_identity_text(value, limit):
    if not isinstance(value, str) or not 1 <= len(value) <= limit:
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def available():
    return os.name == "posix" and Path("/proc/self/ns/net").exists() and not Path("/.dockerenv").exists() and not Path("/run/.containerenv").exists()


def _validate(job, host_id, node_id):
    if not isinstance(job, dict) or job.get("source_host_id") != host_id or job.get("source_node_id") != node_id:
        raise ValueError("probe_source_identity_mismatch")
    for key in ("id", "cycle_id"):
        if not isinstance(job.get(key), str) or not _JOB_ID.fullmatch(job[key]):
            raise ValueError("invalid_probe_identity")
    # Host IDs are user-facing machine names, and node IDs are stable agent
    # identifiers. Neither is guaranteed to be a UUID (for example, a host
    # name may contain spaces/Unicode and node IDs may be 32 hex characters).
    if (not _safe_identity_text(job.get("target_host_id"), 200)
            or not _safe_identity_text(job.get("target_node_id"), 128)):
        raise ValueError("invalid_probe_identity")
    if job.get("role") not in {"mainland", "overseas"} or not isinstance(job.get("lease"), str) or not _LEASE.fullmatch(job["lease"]):
        raise ValueError("invalid_probe_lease")
    # The server leases queued jobs with a 10-minute deadline. They may spend
    # part of that window waiting behind earlier jobs for the same probe node.
    if type(job.get("deadline_at")) is not int or not 0 < job["deadline_at"] - time.time() <= 660:
        raise ValueError("invalid_probe_deadline")
    targets = job.get("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 8:
        raise ValueError("invalid_target_count")
    ids = set()
    for target in targets:
        if not isinstance(target, dict) or set(target) != {"id", "ip", "port", "interface"}:
            raise ValueError("invalid_target_fields")
        if not isinstance(target["interface"], str) or len(target["interface"]) > 32 or type(target["port"]) is not int or not 1 <= target["port"] <= 65535 or not _safe_ip(target["ip"]):
            raise ValueError("invalid_target_endpoint")
        expected = _digest({"host_id": job["target_host_id"], "ip": target["ip"], "port": target["port"], "interface": target["interface"]})[:24]
        if target["id"] != expected or target["id"] in ids:
            raise ValueError("invalid_target_identity")
        ids.add(target["id"])
    if job.get("targets_hash") != _digest(targets):
        raise ValueError("invalid_targets_hash")


def _failure_report(job, host_id, node_id, failure_code):
    if not isinstance(job, dict) or job.get("source_host_id") != host_id or job.get("source_node_id") != node_id:
        return None
    values = {
        "job_id": job.get("id"),
        "cycle_id": job.get("cycle_id"),
        "source_host_id": host_id,
        "source_node_id": node_id,
        "lease": job.get("lease"),
        "targets_hash": job.get("targets_hash"),
    }
    if any(not _safe_identity_text(value, 256) for value in values.values()):
        return None
    return {**values, "failure_code": failure_code}


def _probe(target):
    attempts, latencies, last_error = 0, [], "timeout"
    address = ipaddress.ip_address(target["ip"])
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    socket_address = (str(address), target["port"], 0, 0) if address.version == 6 else (str(address), target["port"])
    for _ in range(2):
        attempts += 1
        start = time.perf_counter()
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect(socket_address)
            latencies.append((time.perf_counter() - start) * 1000)
            break
        except TimeoutError:
            last_error = "timeout"
        except ConnectionRefusedError:
            last_error = "refused"
        except OSError:
            last_error = "network_error"
        if attempts < 2:
            time.sleep(.1)
    success = bool(latencies)
    return {"target_id": target["id"], "success": success,
            "latency_ms": round(latencies[0], 2) if success else None,
            "error": "" if success else last_error, "attempts": attempts}


def handle(config, host_id, node_id, post):
    if not isinstance(config, dict):
        return
    job = config.get("job")
    if not isinstance(job, dict):
        return
    if not _lock.acquire(blocking=False):
        failure = _failure_report(job, host_id, node_id, "probe_worker_busy")
        if failure:
            try:
                post("/api/v1/gfw-probe/failure", failure)
            except Exception:
                print("domestic reachability probe failure report could not be delivered", flush=True)
        return
    try:
        _validate(job, host_id, node_id)
        if not available():
            raise ValueError("probe_runtime_unavailable")
        results = []
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="gfw-probe") as pool:
            futures = {pool.submit(_probe, target): target for target in job["targets"]}
            for future in as_completed(futures, timeout=max(1, min(20, job["deadline_at"] - time.time()))):
                results.append(future.result())
        if len(results) != len(job["targets"]):
            raise ValueError("incomplete_probe_results")
        results.sort(key=lambda result: result["target_id"])
        payload = {"job_id": job["id"], "cycle_id": job["cycle_id"], "source_host_id": host_id,
                   "source_node_id": node_id, "lease": job["lease"], "targets_hash": job["targets_hash"], "results": results}
        post("/api/v1/gfw-probe/report", payload)
    except Exception as error:
        failure_code = error.args[0] if isinstance(error, ValueError) and error.args and error.args[0] in _FAILURE_CODES else "probe_worker_error"
        print("domestic reachability probe could not be completed: " + failure_code, flush=True)
        failure = _failure_report(job, host_id, node_id, failure_code)
        if failure:
            try:
                post("/api/v1/gfw-probe/failure", failure)
            except Exception:
                print("domestic reachability probe failure report could not be delivered", flush=True)
    finally:
        _lock.release()
