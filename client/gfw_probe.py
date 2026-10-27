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


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _safe_ip(value):
    try:
        address = ipaddress.ip_address(value)
        return address.version == 4 and address.is_global and not address.is_multicast
    except (TypeError, ValueError):
        return False


def available():
    return os.name == "posix" and Path("/proc/self/ns/net").exists() and not Path("/.dockerenv").exists() and not Path("/run/.containerenv").exists()


def _validate(job, host_id, node_id):
    if not isinstance(job, dict) or job.get("source_host_id") != host_id or job.get("source_node_id") != node_id:
        raise ValueError("probe source identity mismatch")
    for key in ("id", "cycle_id", "target_host_id", "target_node_id"):
        if not isinstance(job.get(key), str) or not _JOB_ID.fullmatch(job[key]):
            raise ValueError("invalid probe identity")
    if job.get("role") not in {"mainland", "overseas"} or not isinstance(job.get("lease"), str) or not _LEASE.fullmatch(job["lease"]):
        raise ValueError("invalid probe lease")
    # The server leases queued jobs with a 10-minute deadline. They may spend
    # part of that window waiting behind earlier jobs for the same probe node.
    if type(job.get("deadline_at")) is not int or not 0 < job["deadline_at"] - time.time() <= 660:
        raise ValueError("invalid probe deadline")
    targets = job.get("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 8:
        raise ValueError("invalid target count")
    ids = set()
    for target in targets:
        if not isinstance(target, dict) or set(target) != {"id", "ip", "port", "interface"}:
            raise ValueError("invalid target fields")
        if not isinstance(target["interface"], str) or len(target["interface"]) > 32 or type(target["port"]) is not int or not 1 <= target["port"] <= 65535 or not _safe_ip(target["ip"]):
            raise ValueError("invalid target endpoint")
        expected = _digest({"host_id": job["target_host_id"], "ip": target["ip"], "port": target["port"], "interface": target["interface"]})[:24]
        if target["id"] != expected or target["id"] in ids:
            raise ValueError("invalid target identity")
        ids.add(target["id"])
    if job.get("targets_hash") != _digest(targets):
        raise ValueError("invalid targets hash")


def _probe(target):
    attempts, latencies, last_error = 0, [], "timeout"
    for _ in range(2):
        attempts += 1
        start = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect((target["ip"], target["port"]))
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
    if not available() or not isinstance(config, dict):
        return
    job = config.get("job")
    if not isinstance(job, dict):
        return
    if not _lock.acquire(blocking=False):
        return
    try:
        _validate(job, host_id, node_id)
        results = []
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="gfw-probe") as pool:
            futures = {pool.submit(_probe, target): target for target in job["targets"]}
            for future in as_completed(futures, timeout=max(1, min(20, job["deadline_at"] - time.time()))):
                results.append(future.result())
        if len(results) != len(job["targets"]):
            raise ValueError("incomplete probe results")
        results.sort(key=lambda result: result["target_id"])
        payload = {"job_id": job["id"], "cycle_id": job["cycle_id"], "source_host_id": host_id,
                   "source_node_id": node_id, "lease": job["lease"], "targets_hash": job["targets_hash"], "results": results}
        post("/api/v1/gfw-probe/report", payload)
    except Exception as error:
        print("domestic reachability probe could not be completed: " + type(error).__name__, flush=True)
    finally:
        _lock.release()
