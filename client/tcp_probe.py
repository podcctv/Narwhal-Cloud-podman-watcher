"""Bounded host-VPS TCP worker. The subprocess never receives Agent credentials."""
import hashlib
import ipaddress
import json
import os
import re
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_mutex = threading.Lock()
_running = {}
_DOMAIN = re.compile(r"[a-z0-9-]{1,120}-v4\.ip\.zstaticcdn\.com")
_CUSTOM_HOST = "hinet.428048.xyz"
_CUSTOM_PORT = 36901


def allowed_host(host):
    return isinstance(host, str) and (bool(_DOMAIN.fullmatch(host)) or host == _CUSTOM_HOST)


def available():
    return os.name == "posix" and Path("/proc/self/ns/net").exists() and not Path("/.dockerenv").exists() and not Path("/run/.containerenv").exists()


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def safe_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4 and ip.is_global and not ip.is_multicast
    except ValueError:
        return False


def validate_targets(targets):
    if not isinstance(targets, list) or not 1 <= len(targets) <= 400:
        raise ValueError("invalid target count")
    ids = set()
    for t in targets:
        if not isinstance(t, dict) or set(t) != {"id", "host", "port", "province", "city", "carrier", "kind"}:
            raise ValueError("invalid target fields")
        custom = t["host"] == _CUSTOM_HOST and t["port"] == _CUSTOM_PORT and t["province"] == "台湾" and t["carrier"] == "custom" and t["kind"] == "province" and t["city"] == ""
        standard = isinstance(t["host"], str) and bool(_DOMAIN.fullmatch(t["host"])) and t["port"] in (80, 443)
        if type(t["port"]) is not int or not (custom or standard):
            raise ValueError("invalid target endpoint")
        if any(not isinstance(t[k], str) or len(t[k]) > 40 for k in ("province", "city", "carrier", "kind")):
            raise ValueError("invalid target metadata")
        if t["id"] != digest({k: v for k, v in t.items() if k != "id"})[:20] or t["id"] in ids:
            raise ValueError("invalid target identity")
        ids.add(t["id"])


def resolve(host):
    """A killable DNS subprocess; no uninterruptible resolver threads accumulate."""
    if not allowed_host(host):
        return [], "blocked_dns"
    try:
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "resolve", host],
                                capture_output=True, timeout=2.5, check=True)
        if len(result.stdout) > 16384:
            return [], "dns_error"
        ips = json.loads(result.stdout)
        if not isinstance(ips, list) or not 1 <= len(ips) <= 32 or any(not isinstance(ip, str) or not safe_ip(ip) for ip in ips):
            return [], "blocked_dns"
        return ips, ""
    except (OSError, ValueError, subprocess.SubprocessError):
        return [], "dns_error"


def probe(target, samples):
    ips, error = resolve(target["host"])
    result = {"target_id": target["id"], "ip": ips[0] if ips else "", "samples_ms": [], "error": error}
    if not ips:
        return result
    ip = ips[0]
    for attempt in range(samples):
        if not safe_ip(ip):
            raise ValueError("address changed unexpectedly")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.5)
                start = time.perf_counter()
                sock.connect((ip, target["port"]))
                elapsed = (time.perf_counter() - start)*1000
            result["samples_ms"].append(round(elapsed, 2))
        except TimeoutError:
            result["samples_ms"].append(None)
            result["error"] = "timeout"
        except ConnectionRefusedError:
            result["samples_ms"].append(None)
            result["error"] = "refused"
        except OSError:
            result["samples_ms"].append(None)
            result["error"] = "network_error"
        if attempt + 1 < samples:
            time.sleep(.15)
    return result


def worker(payload):
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (256*1024**2, 256*1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    os.nice(10)
    targets, samples = payload["targets"], payload["samples"]
    validate_targets(targets)
    if type(samples) is not int or not 1 <= samples <= 3:
        raise ValueError("invalid sample count")
    # Four simultaneous DNS children OR TCP sockets, never a process per sample.
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(probe, target, samples) for target in targets]
        for future in as_completed(futures):
            print(json.dumps(future.result(), separators=(",", ":")), flush=True)


def kill_worker(process):
    if process and process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def claim(job_id):
    import fcntl
    folder = Path(os.getenv("NARWHAL_TCP_STATE", "/var/lib/narwhal-monitor/tcp-probe"))
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(folder / "worker.lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = folder / "recent.json"
        if path.is_symlink():
            raise ValueError("invalid local state")
        if path.exists():
            if path.stat().st_size > 16384:
                raise ValueError("oversized local state")
            saved = json.loads(path.read_text())
        else:
            saved = {"last_started": 0, "jobs": []}
        now = time.time()
        if job_id in saved["jobs"] or now - saved["last_started"] < 900:
            os.close(fd)
            return None
        saved = {"last_started": now, "jobs": (saved["jobs"] + [job_id])[-32:]}
        tmp = folder / ("state-" + uuid.uuid4().hex + ".tmp")
        out = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(out, "w") as f:
            json.dump(saved, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return fd
    except Exception:
        os.close(fd)
        raise


def run_job(job, host_id, node_id, post, lock_fd):
    process, timer, pending, sequence, count, outcome = None, None, [], 0, 0, "worker_error"
    def send(rows, done=False, final=""):
        nonlocal sequence
        payload = {"job_id": job["id"], "node_id": node_id, "host_id": host_id, "lease": job["lease"],
                   "generation": job["generation"], "target_hash": job["target_hash"], "sequence": sequence,
                   "rows": rows, "done": done, "outcome": final}
        try:
            post("/api/v1/tcp-probe/report", payload)
        except Exception:
            # Exactly the same sequence/content: the server checks its digest.
            post("/api/v1/tcp-probe/report", payload)
        sequence += 1
    try:
        send([])
        seconds = min(180, job["deadline_at"] - time.time() - 15)
        if seconds <= 0:
            outcome = "deadline"
            return
        process = subprocess.Popen([sys.executable, "-u", str(Path(__file__).resolve()), "worker"],
                                   # Worker stderr contains only code errors and public targets,
                                   # never Agent credentials. Keep it in the service journal.
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None,
                                   start_new_session=True, pass_fds=(lock_fd,),
                                   # glibc's per-thread arenas can reserve more than the
                                   # entire 256 MiB address-space budget on ARM64.
                                   # Set this before interpreter/allocator startup;
                                   # keep the resource limit and four-worker bound.
                                   env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "MALLOC_ARENA_MAX": "2"})
        with _mutex:
            _running["process"] = process
            if _running.get("cancelled"):
                kill_worker(process)
        timer = threading.Timer(seconds, kill_worker, [process])
        timer.daemon = True
        timer.start()
        process.stdin.write(json.dumps({"targets": job["targets"], "samples": job["samples"]}).encode())
        process.stdin.close()
        deadline = time.monotonic() + seconds
        allowed = {t["id"] for t in job["targets"]}
        seen = set()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if not selector.select(.25):
                    if process.poll() is not None:
                        break
                    continue
                line = process.stdout.readline(4097)
                if not line:
                    break
                if len(line) > 4096:
                    raise ValueError("oversized worker output")
                row = json.loads(line)
                if row.get("target_id") not in allowed or row["target_id"] in seen:
                    raise ValueError("unexpected worker result")
                seen.add(row["target_id"])
                pending.append(row)
                count += 1
                if len(pending) >= 32:
                    send(pending)
                    pending = []
        if process.poll() is None:
            process.wait(timeout=max(.1, min(1, deadline - time.monotonic())))
        outcome = "complete" if process.returncode == 0 and count == len(allowed) else "deadline" if time.monotonic() >= deadline else "worker_error"
    except Exception as error:
        print("public TCP worker error: " + type(error).__name__, flush=True)
        outcome = "worker_error"
    finally:
        kill_worker(process)
        if process:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
            if process.stdout:
                process.stdout.close()
            if process.stdin and not process.stdin.closed:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            if outcome != "complete":
                print("public TCP worker exited: code=" + str(process.returncode) + " rows=" + str(count) + " outcome=" + outcome, flush=True)
        if timer:
            timer.cancel()
        try:
            send(pending, True, outcome)
        except Exception:
            pass  # The server expires unconfirmed tasks; never starts them again.
        os.close(lock_fd)
        with _mutex:
            _running.clear()


def handle(config, host_id, node_id, post):
    if not isinstance(config, dict) or not available():
        return
    with _mutex:
        if _running.get("id") in config.get("cancelled", []):
            _running["cancelled"] = True
            kill_worker(_running.get("process"))
        if _running:
            return
        job = config.get("job")
        if not isinstance(job, dict):
            return
        try:
            uuid.UUID(job["id"])
            if not node_id or job["node_id"] != node_id or not isinstance(job["lease"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", job["lease"]):
                raise ValueError("invalid job binding")
            if type(job["samples"]) is not int or not 1 <= job["samples"] <= 3 or type(job["deadline_at"]) is not int or not 0 < job["deadline_at"] - time.time() <= 220:
                raise ValueError("invalid job budget")
            validate_targets(job["targets"])
            if job["target_hash"] != digest(job["targets"]):
                raise ValueError("target digest mismatch")
            lock_fd = claim(job["id"])
            if lock_fd is None:
                return
        except (ValueError, TypeError, KeyError, OSError):
            return
        _running["id"] = job["id"]
        thread = threading.Thread(target=run_job, args=(job, host_id, node_id, post, lock_fd), daemon=True, name="public-tcp-probe")
        try:
            thread.start()
        except Exception:
            _running.clear()
            os.close(lock_fd)
            raise


if __name__ == "__main__":
    if sys.argv[1:] and sys.argv[1] == "resolve":
        host = sys.argv[2]
        if not allowed_host(host):
            raise SystemExit(2)
        print(json.dumps(sorted({r[4][0] for r in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)})))
    elif sys.argv[1:] == ["worker"]:
        data = sys.stdin.buffer.read(131073)
        if len(data) > 131072:
            raise SystemExit(2)
        worker(json.loads(data))
    else:
        raise SystemExit(2)
