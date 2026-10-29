"""Service-specific speed-test restrictions for isolated Incus/Podman containers.

Outbound target names are blocked through a managed /etc/hosts section. Inbound
service ports are blocked only after process, configuration/image, and live
listener evidence identify the same endpoint. No process or container is stopped.
"""
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import tempfile
import threading
import time
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

try:
    from client import vmess_guard
except ImportError:
    import vmess_guard


SUPPORTED_RUNTIMES = {"incus", "podman"}
SUPPORTED_SERVICES = {
    "ookla", "cloudflare", "fast", "tcpquality",
    "iperf3_server", "librespeed", "openspeedtest", "ookla_server",
}
INBOUND_SERVICES = {"iperf3_server", "librespeed", "openspeedtest", "ookla_server"}
SERVICE_TITLES = {
    "ookla": "Ookla Speedtest",
    "cloudflare": "Cloudflare Speed Test",
    "fast": "FAST.com",
    "tcpquality": "TcpQuality / Lisaweb 测速脚本",
    "iperf3_server": "容器内 iPerf3 服务端",
    "librespeed": "LibreSpeed 自建测速服务",
    "openspeedtest": "OpenSpeedTest 自建测速服务",
    "ookla_server": "Ookla 自建测速服务",
}

# Exact hostnames only. Do not turn these into broad provider/CDN IP blocks.
SERVICE_DOMAINS = {
    "ookla": ("speedtest.net",),
    "cloudflare": ("speed.cloudflare.com",),
    # FAST.com hostnames only. Netflix OCA domains are intentionally excluded:
    # they also carry ordinary Netflix content.
    "fast": ("fast.com", "www.fast.com"),
    "tcpquality": ("tcpquality.ibsgss.uk",),
}

POLICY_FILE = os.getenv(
    "NARWHAL_SPEEDTEST_POLICY_FILE",
    "/var/lib/narwhal-agent/speedtest-service-policy.json",
)
HOSTS_BEGIN = "# >>> NARWHAL SPEEDTEST TARGETS BEGIN >>>"
HOSTS_END = "# <<< NARWHAL SPEEDTEST TARGETS END <<<"
TARGET_CACHE_FILE = os.getenv(
    "NARWHAL_SPEEDTEST_TARGET_CACHE_FILE",
    "/var/lib/narwhal-agent/speedtest-target-cache.json",
)
TARGET_CACHE_TTL_SECONDS = 6 * 60 * 60
TARGET_RETRY_SECONDS = 10 * 60
MAX_TARGET_BYTES = 2 * 1024 * 1024
MAX_TARGET_IPS = 128
MAX_TARGET_DOMAINS = 64
GET_NODES_URL = "https://tcpquality.ibsgss.uk/getNodes?format=tsv&scope=tos"
TCPQUALITY_CORE_URL = "https://raw.githubusercontent.com/ibsgss/TcpQuality/main/runTcpQuality-core.sh"
# Last-known hostnames from the official script are useful for a visibly
# partial bootstrap block. IP addresses are never hard-coded: destination IPs
# must come from the current script/API or a previously verified cache.
FALLBACK_LEASEWEB_DOMAINS = (
    "speedtest.hkg12.hk.leaseweb.net", "speedtest.tyo11.jp.leaseweb.net",
    "speedtest.sin1.sg.leaseweb.net", "speedtest.lax12.us.leaseweb.net",
    "speedtest.dal13.us.leaseweb.net", "speedtest.chi11.us.leaseweb.net",
    "speedtest.mtl2.ca.leaseweb.net", "speedtest.mia11.us.leaseweb.net",
    "speedtest.fra1.de.leaseweb.net", "speedtest.lon1.uk.leaseweb.net",
    "speedtest.ams1.nl.leaseweb.net", "speedtest.syd12.au.leaseweb.net",
)
_hosts_cache = {}
_cleanup_cache = set()
_guard_cleanup_cache = set()
_target_lock = threading.Lock()
_target_cache_memory = None
_target_retry_after = 0


def _valid_leaseweb_domain(value):
    value = str(value or "").strip().lower().rstrip(".")
    return value if re.fullmatch(r"speedtest(?:\.[a-z0-9-]+)+\.leaseweb\.net", value) else ""


def _public_ips(values):
    result = set()
    for value in values if isinstance(values, (list, tuple, set)) else []:
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        if address.is_global:
            result.add(str(address))
        if len(result) >= MAX_TARGET_IPS:
            break
    return sorted(result, key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item))))


def _fetch_https(url, allowed_host):
    request = Request(url, headers={"User-Agent": "Narwhal-Speedtest-Policy/1"})
    with urlopen(request, timeout=5, context=ssl.create_default_context()) as response:
        final = urlsplit(response.geturl())
        if final.scheme != "https" or (final.hostname or "").lower() != allowed_host:
            raise ValueError("upstream_redirect_rejected")
        data = response.read(MAX_TARGET_BYTES + 1)
        if len(data) > MAX_TARGET_BYTES:
            raise ValueError("upstream_response_too_large")
        return data.decode("utf-8-sig", errors="strict")


def _parse_tcpquality_script(source):
    if not isinstance(source, str) or len(source) > MAX_TARGET_BYTES or "INTERNATIONAL_IPERF_TARGETS" not in source:
        return [], []
    block_match = re.search(r"(?ms)^INTERNATIONAL_IPERF_TARGETS\s*=\s*\((.*?)^\)", source)
    domains = set()
    if block_match:
        for row in re.findall(r"'([^'\r\n]{1,1024})'", block_match.group(1)):
            fields = row.split("|")
            # The upstream table stores primary and fallback hostnames at 3, 6 and 8.
            for index in (3, 6, 8):
                if index < len(fields):
                    domain = _valid_leaseweb_domain(fields[index])
                    if domain:
                        domains.add(domain)
    fallback_ips = []
    for carrier in ("CT", "CU", "CM"):
        match = re.search(
            rf"(?m)^SPEEDTEST_TOS_{carrier}_IP\s*=.*?([0-9]{{1,3}}(?:\.[0-9]{{1,3}}){{3}})",
            source,
        )
        if match:
            fallback_ips.append(match.group(1))
    return sorted(domains)[:MAX_TARGET_DOMAINS], _public_ips(fallback_ips)


def _parse_tcpquality_nodes(source):
    ips = set()
    regions = set()
    carriers = {"电信", "ct", "chinatelecom", "china telecom", "联通", "cu", "chinaunicom", "china unicom", "移动", "cm", "chinamobile", "china mobile"}
    allowed_regions = ("cn-beijing", "cn-shanghai", "cn-guangzhou")
    for line in str(source or "").splitlines()[:10000]:
        fields = line.rstrip("\r").split("\t")
        if len(fields) < 7:
            fields = line.rstrip("\r").split("|")
        if len(fields) < 7 or fields[0].strip().lower() == "type":
            continue
        kind, family = fields[0].strip().lower(), fields[1].strip()
        if kind not in {"tos", "tosutil", "speedtest"} or family != "4":
            continue
        if fields[3].strip().lower() not in carriers:
            continue
        target = fields[7].strip().lower() if len(fields) > 7 else ""
        # TcpQuality defaults an omitted target to Beijing and selects the
        # primary IP field for its domestic single-thread checks. Do not add
        # backup_ip: the current script does not use that field for these TOS
        # checks, so blocking it would exceed the observed destination set.
        region = next((item for item in allowed_regions if item in target), "cn-beijing" if not target else "")
        if region and len(fields) > 5:
            row_ips = _public_ips([fields[5].strip()])
            if row_ips:
                ips.update(row_ips)
                regions.add(region)
    return {"target_ips": _public_ips(ips), "regions": sorted(regions)}


def _resolve_target_domains(domains):
    addresses = set()
    for domain in domains[:MAX_TARGET_DOMAINS]:
        try:
            rows = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except (OSError, OverflowError, ValueError):
            continue
        for row in rows:
            address = _public_ips([row[4][0]])
            addresses.update(address)
            if len(addresses) >= MAX_TARGET_IPS:
                break
    return _public_ips(addresses)


def _read_target_cache():
    try:
        with open(TARGET_CACHE_FILE, "r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(value, dict) or value.get("schema") != 1:
        return None
    try:
        refreshed_at = int(value.get("refreshed_at") or 0)
    except (TypeError, ValueError, OverflowError):
        return None
    domains = sorted({domain for item in value.get("domains", []) if (domain := _valid_leaseweb_domain(item))})[:MAX_TARGET_DOMAINS]
    ips = _public_ips(value.get("target_ips", []))
    if not refreshed_at or not domains or not ips:
        return None
    return {
        "schema": 1,
        "refreshed_at": refreshed_at,
        "source": str(value.get("source") or "cache")[:80],
        "script_sha256": str(value.get("script_sha256") or "")[:64],
        "domains": domains,
        "target_ips": ips,
        "state": "stale",
    }


def _write_target_cache(value):
    parent = os.path.dirname(os.path.abspath(TARGET_CACHE_FILE))
    temp_path = ""
    try:
        os.makedirs(parent, mode=0o700, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".speedtest-targets-", dir=parent, text=True)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, TARGET_CACHE_FILE)
        temp_path = ""
        try:
            os.chmod(TARGET_CACHE_FILE, 0o600)
        except OSError:
            pass
        return True
    except OSError:
        return False
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def tcpquality_target_inventory(now=None, force_refresh=False):
    """Return a bounded cached inventory of exact TcpQuality test destinations."""
    global _target_cache_memory, _target_retry_after
    now = int(now or time.time())
    with _target_lock:
        cached = _target_cache_memory or _read_target_cache()
        _target_cache_memory = cached
        if cached and now - cached["refreshed_at"] < TARGET_CACHE_TTL_SECONDS:
            # Partial bootstrap data is never promoted to fresh merely because
            # it remains in memory. Only a complete script + three-city target
            # inventory may satisfy the enforcement/readback freshness check.
            if cached.get("state") == "partial":
                return {
                    **cached,
                    "state": "partial",
                    "reason": str(cached.get("reason") or "upstream_inventory_incomplete"),
                }
            return {**cached, "state": "fresh", "reason": ""}
        if not force_refresh and now < _target_retry_after:
            if cached:
                return {**cached, "state": "stale", "reason": "refresh_backoff"}
            if isinstance(_target_cache_memory, dict):
                return {**_target_cache_memory, "state": "partial", "reason": "refresh_backoff"}
        _target_retry_after = now + TARGET_RETRY_SECONDS

        source_text = ""
        nodes_text = ""
        try:
            source_text = _fetch_https(TCPQUALITY_CORE_URL, "raw.githubusercontent.com")
        except (OSError, ValueError, UnicodeError, TimeoutError):
            pass
        try:
            nodes_text = _fetch_https(GET_NODES_URL, "tcpquality.ibsgss.uk")
        except (OSError, ValueError, UnicodeError, TimeoutError):
            pass

        domains, script_fallback_ips = _parse_tcpquality_script(source_text)
        script_targets_valid = bool(source_text and domains)
        nodes_inventory = _parse_tcpquality_nodes(nodes_text)
        nodes_ips = nodes_inventory["target_ips"]
        if not domains and source_text:
            # A changed upstream script must not silently erase previously installed
            # LeaseWeb targets when its node table format is not recognized.
            domains = []
        if not domains and not source_text:
            domains = list(FALLBACK_LEASEWEB_DOMAINS)
        tos_ips = _public_ips([*nodes_ips, *script_fallback_ips])
        if not domains:
            domains = list(FALLBACK_LEASEWEB_DOMAINS)
        domains = sorted({domain for item in domains if (domain := _valid_leaseweb_domain(item))})[:MAX_TARGET_DOMAINS]
        leaseweb_ips = _resolve_target_domains(domains)
        new_ips = _public_ips([*tos_ips, *leaseweb_ips])
        complete = bool(
            script_targets_valid
            and nodes_text
            and nodes_ips
            and set(nodes_inventory["regions"]) == {"cn-beijing", "cn-shanghai", "cn-guangzhou"}
            and leaseweb_ips
        )
        if cached and not complete:
            return {**cached, "state": "stale", "reason": "upstream_inventory_incomplete"}
        if not new_ips:
            if cached:
                return {**cached, "state": "stale", "reason": "target_resolution_failed"}
            fallback = {
                "schema": 1, "refreshed_at": now, "source": "fallback", "script_sha256": "",
                "domains": ["tcpquality.ibsgss.uk", *FALLBACK_LEASEWEB_DOMAINS],
                "target_ips": [], "state": "partial", "reason": "upstream_unavailable",
            }
            _target_cache_memory = fallback
            return fallback
        value = {
            "schema": 1,
            "refreshed_at": now,
            "source": "tcpquality_script+getNodes" if complete else "tcpquality_partial_fallback",
            "script_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest() if source_text else "",
            "domains": domains,
            "target_ips": new_ips,
        }
        if complete:
            _write_target_cache(value)
            _target_cache_memory = value
            return {**value, "state": "fresh", "reason": ""}
        if cached:
            return {**cached, "state": "stale", "reason": "upstream_inventory_incomplete"}
        value["domains"] = ["tcpquality.ibsgss.uk", *domains]
        value["state"] = "partial"
        value["reason"] = "upstream_inventory_incomplete"
        _target_cache_memory = value
        return value


def normalize_policy(value):
    value = value if isinstance(value, dict) else {}
    revision = value.get("revision")
    revision = revision if type(revision) is int and 0 <= revision <= 2**63 - 1 else 0
    services = value.get("services") if isinstance(value.get("services"), list) else []
    runtimes = value.get("runtimes") if isinstance(value.get("runtimes"), list) else []
    return {
        "revision": revision,
        "services": sorted({str(item).strip().lower() for item in services if str(item).strip().lower() in SUPPORTED_SERVICES}),
        "runtimes": sorted({str(item).strip().lower() for item in runtimes if str(item).strip().lower() in SUPPORTED_RUNTIMES}),
    }


def load_policy(path=None):
    try:
        with open(path or POLICY_FILE, "r", encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError):
        return {"revision": 0, "services": [], "runtimes": [], "invalid": True}
    policy = normalize_policy(value)
    raw_services = value.get("services") if isinstance(value, dict) else None
    raw_runtimes = value.get("runtimes") if isinstance(value, dict) else None
    safe_services = raw_services if isinstance(raw_services, list) else []
    safe_runtimes = raw_runtimes if isinstance(raw_runtimes, list) else []
    invalid = (
        not isinstance(value, dict)
        or type(value.get("revision")) is not int
        or not isinstance(raw_services, list)
        or not isinstance(raw_runtimes, list)
        or any(str(item).strip().lower() not in SUPPORTED_SERVICES for item in safe_services)
        or any(str(item).strip().lower() not in SUPPORTED_RUNTIMES for item in safe_runtimes)
        or (bool(policy["services"]) and not policy["runtimes"])
    )
    if invalid:
        policy["invalid"] = True
    return policy


def save_policy(value, path=None):
    """Atomically persist a host-scoped policy without exposing file contents."""
    path = path or POLICY_FILE
    policy = normalize_policy(value)
    if not isinstance(value, dict) or type(value.get("revision")) is not int or value["revision"] < 1:
        return False, "speed-test policy revision is missing or invalid"
    raw_services = value.get("services", [])
    raw_runtimes = value.get("runtimes", [])
    if not isinstance(raw_services, list) or not isinstance(raw_runtimes, list):
        return False, "speed-test service or runtime selection is invalid"
    if any(str(item).strip().lower() not in SUPPORTED_SERVICES for item in raw_services):
        return False, "unsupported speed-test service selection"
    if any(str(item).strip().lower() not in SUPPORTED_RUNTIMES for item in raw_runtimes):
        return False, "unsupported container runtime selection"
    if policy["services"] and not policy["runtimes"]:
        return False, "select Incus and/or Podman before applying speed-test restrictions"
    parent = os.path.dirname(os.path.abspath(path))
    temp_path = ""
    try:
        os.makedirs(parent, mode=0o700, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".speedtest-policy-", dir=parent, text=True)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(policy, handle, ensure_ascii=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        temp_path = ""
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return True, "speed-test service policy saved"
    except OSError:
        return False, "speed-test service policy could not be persisted"
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def domains_for_services(services):
    selected = {str(item).strip().lower() for item in services if str(item).strip().lower() in SUPPORTED_SERVICES}
    result = []
    for service in sorted(selected):
        for domain in SERVICE_DOMAINS.get(service, ()):
            if domain not in result:
                result.append(domain)
    return result


def _hosts_script(domains):
    domains = [domain for domain in domains if re.fullmatch(r"[a-z0-9.-]{1,253}", domain)]
    block = "\n".join(
        [HOSTS_BEGIN]
        + [line for domain in domains for line in (f"0.0.0.0 {domain}", f":: {domain}")]
        + [HOSTS_END]
    )
    expected = block if domains else ""
    lines = [
        "set -eu",
        "f=/etc/hosts",
        '[ -f "$f" ] && [ ! -L "$f" ] || { echo hosts_file_unavailable; exit 21; }',
        f"begin='{HOSTS_BEGIN}'",
        f"end='{HOSTS_END}'",
        'bc=$(grep -Fxc "$begin" "$f" || true)',
        'ec=$(grep -Fxc "$end" "$f" || true)',
        '[ "$bc:$ec" = 0:0 ] || [ "$bc:$ec" = 1:1 ] || { echo hosts_marker_invalid; exit 22; }',
        f"current=$(sed -n '/^{HOSTS_BEGIN}$/,/^{HOSTS_END}$/p' \"$f\")",
        "expected=$(cat <<'NARWHAL_EXPECTED'",
        expected,
        "NARWHAL_EXPECTED",
        ")",
        'if [ "$current" = "$expected" ]; then echo hosts_policy_readback_ok; exit 0; fi',
        "tmp=$(mktemp /etc/hosts.narwhal.XXXXXX) || { echo hosts_tempfile_failed; exit 23; }",
        "if ! awk -v begin=\"$begin\" -v end=\"$end\" '",
        "  $0 == begin { if (skip) exit 31; skip=1; next }",
        "  $0 == end { if (!skip) exit 32; skip=0; next }",
        "  !skip { print }",
        "  END { if (skip) exit 33 }",
        "' \"$f\" > \"$tmp\"; then rm -f \"$tmp\"; echo hosts_marker_invalid; exit 22; fi",
    ]
    if domains:
        lines.extend(["cat >> \"$tmp\" <<'NARWHAL_BLOCK'", block, "NARWHAL_BLOCK"])
    lines.extend([
        'chmod --reference="$f" "$tmp" 2>/dev/null || chmod 0644 "$tmp"',
        'mv -f "$tmp" "$f" || { rm -f "$tmp"; echo hosts_replace_failed; exit 24; }',
    ])
    if domains:
        lines.extend([
            'grep -Fqx "$begin" "$f" && grep -Fqx "$end" "$f" || { echo hosts_readback_failed; exit 25; }',
        ])
        for domain in domains:
            lines.append(f"grep -Fqx '0.0.0.0 {domain}' \"$f\" && grep -Fqx ':: {domain}' \"$f\" || {{ echo hosts_readback_failed; exit 25; }}")
    lines.append("echo hosts_policy_readback_ok")
    return "\n".join(lines) + "\n"


def _run(runner, command):
    try:
        value = runner(command)
    except Exception:
        return False, ""
    if isinstance(value, tuple) and len(value) >= 2:
        return bool(value[0]), str(value[1] or "")[:4000]
    return False, ""


def _service_config_markers(runner):
    script = r"""set -eu
found=0
for f in /config/www/index.html /var/www/html/index.html /var/www/html/openspeedtest/index.html /app/index.html /app/public/index.html /usr/share/nginx/html/index.html /usr/share/nginx/html/openspeedtest/index.html /usr/share/caddy/index.html /usr/share/openspeedtest/index.html /opt/openspeedtest/index.html; do
  [ -f "$f" ] || continue
  if grep -Eiq 'LibreSpeed|librespeed' "$f" 2>/dev/null; then printf 'librespeed:%s\n' "$f"; found=1; fi
  if grep -Eiq 'OpenSpeedTest|openspeedtest' "$f" 2>/dev/null; then printf 'openspeedtest:%s\n' "$f"; found=1; fi
done
[ "$found" -eq 1 ] || exit 1
"""
    ok, output = _run(runner, script)
    markers = []
    services = set()
    for line in output.splitlines():
        service, sep, path = line.partition(":")
        if sep and service in {"librespeed", "openspeedtest"} and path.startswith("/"):
            services.add(service)
            markers.append(path[:180])
    return services, markers[:8], bool(ok and markers)


def _iperf_mode(runner, pid):
    pid = int(pid or 0)
    if pid <= 1 or pid > 4194304:
        return "unverified"
    script = """set -eu
p='""" + str(pid) + """'
[ -r "/proc/$p/comm" ] && [ -r "/proc/$p/cmdline" ] || exit 31
comm=$(cat "/proc/$p/comm" 2>/dev/null || true)
case "$comm" in iperf3|iperf) ;; *) echo changed; exit 32 ;; esac
args=$(tr '\\000' ' ' < "/proc/$p/cmdline" 2>/dev/null || true)
case " $args " in
  *' --server '*|*' -s '*|*' -sD '*|*' --server=*) echo server ;;
  *' --client '*|*' -c '*|*' --client=*) echo client ;;
  *) echo other ;;
esac
"""
    ok, output = _run(runner, script)
    if not ok:
        return "unverified"
    result = output.strip().splitlines()[-1:] or [""]
    return result[0] if result[0] in {"server", "client", "other", "changed"} else "unverified"


def _ookla_server_mode(runner, pid):
    pid = int(pid or 0)
    if pid <= 1 or pid > 4194304:
        return "unverified"
    script = """set -eu
p='""" + str(pid) + """'
[ -r "/proc/$p/comm" ] && [ -r "/proc/$p/cmdline" ] && [ -e "/proc/$p/exe" ] || exit 31
comm=$(cat "/proc/$p/comm" 2>/dev/null || true)
exe=$(readlink "/proc/$p/exe" 2>/dev/null || true)
args=$(tr '\\000' ' ' < "/proc/$p/cmdline" 2>/dev/null || true)
value=$(printf '%s %s %s' "$comm" "$exe" "$args" | tr '[:upper:]' '[:lower:]')
case "$value" in *ooklaserver*|*ookla-server*) echo server ;; *) echo other ;; esac
"""
    ok, output = _run(runner, script)
    if not ok:
        return "unverified"
    result = output.strip().splitlines()[-1:] or [""]
    return result[0] if result[0] in {"server", "other"} else "unverified"


def _image_services(image):
    value = str(image or "").strip().lower()
    services = set()
    if "librespeed" in value:
        services.add("librespeed")
    if "openspeedtest" in value or "open-speedtest" in value:
        services.add("openspeedtest")
    return services


def _safe_listeners(listeners):
    result = []
    for item in listeners if isinstance(listeners, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            pid = int(item.get("pid") or 0)
            port = int(item.get("port") or 0)
        except (TypeError, ValueError, OverflowError):
            continue
        proto = str(item.get("proto") or "").lower()
        process = str(item.get("process") or "").lower()[:120]
        if proto not in {"tcp", "udp"} or not 0 < port <= 65535 or pid < 0 or pid > 4194304:
            continue
        result.append({"pid": pid, "port": port, "proto": proto, "process": process, "local": str(item.get("local") or "")[:128]})
    return result


def reconcile_container(*, runtime, name, project="", identity="", pid=0, namespace_epoch="",
                        network_shared=False, image="", listeners=None, listener_inventory_complete=False,
                        policy=None, runner=None, observed_at=None):
    """Reconcile one selected container; all output is bounded and secret-free."""
    now = int(observed_at or time.time())
    runtime = str(runtime or "").strip().lower()
    name = str(name or "")[:200]
    identity = str(identity or name)[:240]
    if isinstance(policy, dict) and policy.get("invalid") is True:
        return {"state": "unverified", "reason": "policy_invalid", "observed_at": now,
                "services": [], "detected_services": [], "blocked_domains": [], "blocked_endpoints": [],
                "blocked_destination_ips": [], "hosts_state": "unverified",
                "destination_state": "unverified", "listener_inventory_complete": False}
    policy = normalize_policy(policy)
    if runtime not in SUPPORTED_RUNTIMES or not name:
        return {"state": "unsupported", "reason": "runtime_not_supported", "observed_at": now,
                "services": [], "detected_services": [], "blocked_domains": [], "blocked_endpoints": []}
    selected = policy["services"] if runtime in policy["runtimes"] else []
    selected_domains = domains_for_services(selected)
    target_inventory = None
    requested_destination_ips = []
    if "tcpquality" in selected:
        target_inventory = tcpquality_target_inventory(now=now)
        for domain in target_inventory.get("domains", []):
            if domain not in selected_domains:
                selected_domains.append(domain)
        if target_inventory.get("state") in {"fresh", "stale", "partial"}:
            requested_destination_ips = _public_ips(target_inventory.get("target_ips", []))
    listener_rows = _safe_listeners(listeners)
    endpoint_targets = {}
    detected = set()
    pending = False
    complete = listener_inventory_complete is True
    config_paths = []
    web_processes = {"nginx", "httpd", "apache2", "lighttpd", "caddy", "openresty"}

    if selected and complete and callable(runner):
        image_services = _image_services(image)
        candidate_web = bool(image_services) or any(item["process"] in web_processes for item in listener_rows)
        config_services, config_paths, config_complete = (
            _service_config_markers(runner)
            if candidate_web and any(s in selected for s in {"librespeed", "openspeedtest"})
            else (set(), [], True)
        )
        if candidate_web and not config_complete and any(s in selected for s in {"librespeed", "openspeedtest"}):
            pending = True
        confirmed_web_services = image_services.intersection(config_services).intersection(selected)
        # Require image + product marker + a web process owning the exact socket.
        for item in listener_rows:
            if item["process"] not in web_processes or item["pid"] <= 1:
                continue
            for service in confirmed_web_services:
                detected.add(service)
                key = (item["proto"], item["port"])
                endpoint_targets.setdefault(key, set()).add(item["pid"])
        if "iperf3_server" in selected:
            for item in listener_rows:
                if item["process"] not in {"iperf3", "iperf"} or item["pid"] <= 1:
                    continue
                mode = _iperf_mode(runner, item["pid"])
                if mode == "server":
                    detected.add("iperf3_server")
                    key = (item["proto"], item["port"])
                    endpoint_targets.setdefault(key, set()).add(item["pid"])
                elif mode == "unverified":
                    pending = True
        if "ookla_server" in selected:
            for item in listener_rows:
                if item["process"] not in {"ooklaserver", "ookla_server"} or item["pid"] <= 1:
                    continue
                mode = _ookla_server_mode(runner, item["pid"])
                if mode == "server":
                    detected.add("ookla_server")
                    key = (item["proto"], item["port"])
                    endpoint_targets.setdefault(key, set()).add(item["pid"])
                elif mode == "unverified":
                    pending = True
    elif set(selected).intersection(INBOUND_SERVICES):
        pending = True

    # Unknown or shared owners remain unconfirmed, causing the owned-table
    # reconciler's exclusive-owner check to fail closed.
    live_listeners = []
    for item in listener_rows:
        key = (item["proto"], item["port"])
        is_service_owner = item["pid"] > 1 and item["pid"] in endpoint_targets.get(key, set())
        live_listeners.append({
            **item,
            "application_protocols": ["speedtest"] if is_service_owner else [],
            "application_protocol_evidence": "config_matches_live_pid_and_port" if is_service_owner else "",
            "protocol_process_scan_complete": bool(is_service_owner and complete),
            "speedtest_process_scan_complete": bool(is_service_owner and complete),
        })
    endpoints = [{"proto": proto, "port": port} for proto, port in sorted(endpoint_targets)]
    namespace_pid = int(pid or 0)
    current_epoch = vmess_guard._pid_epoch(namespace_pid) if namespace_pid > 1 else ""
    cache_key = (runtime, identity, current_epoch or namespace_epoch)
    cleanup_key = (cache_key, policy["revision"])

    inbound_services = INBOUND_SERVICES
    has_inbound_guard = bool(set(selected).intersection(inbound_services))
    has_namespace_guard = has_inbound_guard or "tcpquality" in selected
    should_cleanup_guard = not has_namespace_guard and cleanup_key not in _guard_cleanup_cache
    if selected and has_namespace_guard:
        # On an incomplete listener scan, preserve the existing ingress rules;
        # an egress-only TcpQuality update must not accidentally open an older
        # verified service port while rebuilding the same owned nft table.
        endpoint_request = endpoints if complete and not pending else None
        if "tcpquality" in selected:
            destination_request = (
                requested_destination_ips
                if target_inventory and target_inventory.get("state") == "fresh"
                else None
            )
        else:
            destination_request = []
        guard = vmess_guard.reconcile(
            namespace_pid, identity, current_epoch or namespace_epoch,
            endpoint_request,
            destination_ips=destination_request,
            host_network=bool(network_shared),
            release_if_absent=bool(complete and not pending),
            live_listeners=live_listeners if complete and not pending else None,
            preserve_existing=bool(not complete or pending or (target_inventory and target_inventory.get("state") != "fresh")),
            application_protocol="speedtest",
        )
    elif should_cleanup_guard:
        guard = vmess_guard.reconcile(
            namespace_pid, identity, current_epoch or namespace_epoch, [],
            destination_ips=[],
            host_network=bool(network_shared), release_if_absent=False,
            live_listeners=live_listeners if complete else None,
            preserve_existing=False, application_protocol="speedtest",
        )
        if guard.get("state") == "cleared":
            _guard_cleanup_cache.add(cleanup_key)
    else:
        guard = {"state": "cleared", "reason": "", "blocked_endpoints": [], "blocked_destination_ips": []}

    domains_key = (policy["revision"], tuple(selected_domains))
    blocked_domains = []
    hosts_state = "not_required"
    should_update_hosts = _hosts_cache.get(cache_key) != domains_key
    if selected_domains or should_update_hosts or cleanup_key not in _cleanup_cache:
        if callable(runner):
            ok, output = _run(runner, _hosts_script(selected_domains))
            if ok and "hosts_policy_readback_ok" in output:
                blocked_domains = list(selected_domains)
                hosts_state = "blocked" if selected_domains else "cleared"
                _hosts_cache[cache_key] = domains_key
                _cleanup_cache.add(cleanup_key)
            else:
                hosts_state = "unverified"
        else:
            hosts_state = "unverified"
    else:
        blocked_domains = list(selected_domains)
        hosts_state = "blocked" if selected_domains else "cleared"

    blocked_endpoints = guard.get("blocked_endpoints") if isinstance(guard.get("blocked_endpoints"), list) else []
    blocked_destination_ips = guard.get("blocked_destination_ips") if isinstance(guard.get("blocked_destination_ips"), list) else []
    destination_state = "not_required"
    if "tcpquality" in selected:
        if not requested_destination_ips:
            destination_state = "unverified"
        elif guard.get("state") == "blocked" and set(requested_destination_ips).issubset(set(blocked_destination_ips)):
            destination_state = "blocked" if target_inventory and target_inventory.get("state") == "fresh" else "stale"
        else:
            destination_state = "unverified"

    state = "blocked" if (blocked_domains or blocked_endpoints or blocked_destination_ips) else "not_detected"
    reason = str(guard.get("reason") or "")
    if hosts_state == "unverified" and selected_domains:
        state = "partial" if (blocked_endpoints or blocked_destination_ips) else "unverified"
        reason = "hosts_policy_unverified"
    if selected and pending:
        state = "partial" if (blocked_endpoints or blocked_domains or blocked_destination_ips) else "unverified"
        reason = reason or "service_evidence_incomplete"
    if "tcpquality" in selected and (destination_state != "blocked" or target_inventory is None or target_inventory.get("state") != "fresh"):
        state = "partial" if (blocked_domains or blocked_destination_ips or blocked_endpoints) else "unverified"
        reason = reason or (target_inventory.get("reason") if target_inventory else "target_inventory_unavailable") or "target_inventory_stale"
    if has_inbound_guard and detected.intersection(inbound_services) and guard.get("state") != "blocked":
        state = "partial" if (blocked_domains or blocked_destination_ips) else "unverified"
        reason = reason or "firewall_readback_unverified"
    return {
        "state": state,
        "reason": reason,
        "observed_at": now,
        "policy_revision": policy["revision"],
        "services": selected,
        "detected_services": sorted(detected),
        "blocked_domains": blocked_domains,
        "hosts_state": hosts_state,
        "blocked_endpoints": blocked_endpoints[:32],
        "blocked_destination_ips": blocked_destination_ips[:MAX_TARGET_IPS],
        "destination_state": destination_state,
        "target_inventory_state": target_inventory.get("state") if target_inventory else "not_required",
        "target_inventory_reason": target_inventory.get("reason") if target_inventory else "",
        "target_inventory_refreshed_at": target_inventory.get("refreshed_at") if target_inventory else None,
        "target_inventory_source": target_inventory.get("source") if target_inventory else "",
        "target_domains": target_inventory.get("domains", [])[:MAX_TARGET_DOMAINS] if target_inventory else [],
        "target_ip_count": len(target_inventory.get("target_ips", [])) if target_inventory else 0,
        "listener_inventory_complete": complete,
        "configuration_evidence": config_paths[:8] if selected and any(s in selected for s in {"librespeed", "openspeedtest"}) else [],
        "reason_detail": "service evidence incomplete" if pending else "",
    }
