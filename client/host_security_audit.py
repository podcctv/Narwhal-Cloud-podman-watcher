"""Bounded, read-only host security inventory and vulnerability checks.

Only hashes, key fingerprints, login metadata and vulnerability matches are
reported. Configuration contents, private keys and full package inventories
are never uploaded.
"""

import base64
import concurrent.futures
import glob
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import ssl
import subprocess
import sysconfig
import tempfile
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import pwd
except ImportError:  # The agent is Linux-first, but keep source imports portable.
    pwd = None

STATE_SCHEMA = 1
DEFAULT_SCAN_INTERVAL = 24 * 60 * 60
INDICATOR_SCAN_INTERVAL = 6 * 60 * 60
RETRY_INTERVAL = 60 * 60
MAX_PACKAGE_CANDIDATES = 1200
MAX_FINDINGS = 200
MAX_LOCKFILES = 1200
MAX_WALK_DIRS = 4000
MAX_PYTHON_ROOT_WALK_DIRS = 5000
MAX_INDICATOR_FINDINGS = 120
MAX_INDICATOR_CONFIG_FILES = 800
MAX_INDICATOR_CONFIG_BYTES = 8 * 1024 * 1024
MAX_INDICATOR_CONFIG_FILE_BYTES = 128 * 1024
MAX_RUNTIME_IMAGE_LINES = 500
MAX_SNAPSHOT_FILES = 256
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_AUTH_LOG_BYTES = 512 * 1024
LITELLM_COMPROMISED_IMAGE_DIGEST = "sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e"
LITELLM_INCIDENT_REFERENCE = "https://docs.litellm.ai/blog/security-incident-oct-21-2026"
PYTHON_CA_REFERENCE = "https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576"
NGINX_SECURITY_REFERENCE = "https://nginx.org/en/security_advisories.html"
RUSTSEC_WEBPKI_REFERENCE = "https://rustsec.org/advisories/RUSTSEC-2026-0381.html"
EMUDHRA_ROOT_REFERENCE = "https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/"

_STATE: Dict[str, Any] = {}
_STATE_PATH = ""


def _state_path() -> str:
    explicit = os.getenv("NARWHAL_HOST_SECURITY_STATE_FILE", "").strip()
    if explicit:
        return explicit
    env_file = os.getenv("NARWHAL_CLIENT_ENV_FILE", "/opt/narwhal-monitor/client.env")
    root = os.path.dirname(os.path.abspath(env_file)) or "/var/lib/narwhal-monitor"
    return os.path.join(root, "host-security-audit.json")


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _load_state() -> Dict[str, Any]:
    try:
        with open(_state_path(), "r", encoding="utf-8") as handle:
            state = json.load(handle)
        if isinstance(state, dict) and state.get("schema") == STATE_SCHEMA:
            return state
    except (OSError, ValueError, TypeError):
        pass
    return {"schema": STATE_SCHEMA}


def _save_state() -> bool:
    global _STATE_PATH
    if not _STATE_PATH:
        _STATE_PATH = _state_path()
    folder = os.path.dirname(_STATE_PATH) or "."
    temporary = ""
    try:
        os.makedirs(folder, mode=0o700, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=folder, prefix=".host-audit-", delete=False
        ) as handle:
            temporary = handle.name
            json.dump(_STATE, handle, ensure_ascii=False, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, _STATE_PATH)
        return True
    except OSError:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        return False


def load_ssh_cursor() -> str:
    global _STATE, _STATE_PATH
    if not _STATE_PATH:
        _STATE_PATH = _state_path()
    if not _STATE:
        _STATE = _load_state()
    return str(_STATE.get("ssh_cursor") or "")[:4096]


def commit_ssh_cursor(cursor: str) -> None:
    """Persist a journal cursor only after the server acknowledges the report."""
    global _STATE, _STATE_PATH
    if not _STATE_PATH:
        _STATE_PATH = _state_path()
    if not _STATE:
        _STATE = _load_state()
    value = str(cursor or "").strip()[:4096]
    if value:
        _STATE["ssh_cursor"] = value
        _save_state()


def _run(argv: Sequence[str], timeout: float = 8.0, max_output: int = 4_000_000) -> Tuple[int, str]:
    try:
        result = subprocess.run(
            list(argv), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout, check=False,
        )
        return int(result.returncode), result.stdout[:max_output].decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def _public_address(value: str) -> bool:
    try:
        return ipaddress.ip_address(str(value).strip()).is_global
    except ValueError:
        return False


def _account_inventory() -> Tuple[List[Dict[str, Any]], bool]:
    if os.name != "posix" or pwd is None:
        return [], False
    try:
        entries = pwd.getpwall()
    except (OSError, AttributeError):
        return [], False
    accounts = []
    for entry in entries:
        shell = str(entry.pw_shell or "")
        shell_name = shell.rsplit("/", 1)[-1].strip().lower()
        non_login_shells = {"", "false", "halt", "nologin", "shutdown", "sync"}
        # Some distributions allocate service accounts below UID 1000 but
        # still give them a real shell. Keep those in the audit baseline.
        if entry.pw_uid != 0 and entry.pw_uid < 1000 and shell_name in non_login_shells:
            continue
        name = str(entry.pw_name or "")[:64]
        if name:
            accounts.append({"name": name, "uid": int(entry.pw_uid), "shell": shell[:160]})
    accounts.sort(key=lambda item: (item["uid"], item["name"]))
    return accounts[:256], len(accounts) < 256


def _authorized_key_inventory(accounts: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, str]], bool]:
    if pwd is None:
        return [], False
    output: List[Dict[str, str]] = []
    complete = True
    inspected = 0
    for account in accounts:
        try:
            entry = pwd.getpwnam(str(account.get("name") or ""))
        except (KeyError, OSError, AttributeError):
            complete = False
            continue
        home = str(entry.pw_dir or "")
        if not home or not os.path.isdir(home):
            continue
        if os.path.islink(home):
            complete = False
            continue
        ssh_dir = os.path.join(home, ".ssh")
        if not os.path.isdir(ssh_dir):
            continue
        if os.path.islink(ssh_dir):
            complete = False
            continue
        for filename in ("authorized_keys", "authorized_keys2"):
            path = os.path.join(ssh_dir, filename)
            if not os.path.isfile(path):
                continue
            if os.path.islink(path):
                complete = False
                continue
            inspected += 1
            if inspected > 512:
                return output, False
            try:
                if os.path.getsize(path) > 64 * 1024:
                    complete = False
                    continue
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    lines = handle.read(64 * 1024).splitlines()
            except OSError:
                complete = False
                continue
            for line in lines[:512]:
                parts = line.strip().split()
                key_index = next(
                    (index for index, value in enumerate(parts[:-1]) if re.match(r"^(?:ssh-|ecdsa-|sk-|rsa-sha2-)", value)),
                    -1,
                )
                if key_index < 0:
                    continue
                try:
                    key_data = base64.b64decode(parts[key_index + 1].encode("ascii"), validate=True)
                except (ValueError, UnicodeError):
                    continue
                if not key_data:
                    continue
                digest = base64.b64encode(hashlib.sha256(key_data).digest()).decode("ascii").rstrip("=")
                output.append({
                    "user": str(account.get("name") or "")[:64],
                    "fingerprint": "SHA256:" + digest,
                    "key_type": parts[key_index][:80],
                })
    output.sort(key=lambda item: (item["user"], item["fingerprint"]))
    if len(output) >= 2048:
        complete = False
    return output[:2048], complete


def _candidate_config_paths(ssh_only: bool = False) -> List[str]:
    ssh_paths = [
        "/etc/ssh/sshd_config", "/etc/ssh/ssh_config", "/etc/passwd", "/etc/group",
        "/etc/pam.d/sshd", "/etc/pam.d/common-auth", "/etc/pam.d/common-account",
        "/etc/pam.d/common-password", "/etc/pam.d/common-session", "/etc/security/access.conf",
    ]
    fixed_paths = ssh_paths if ssh_only else ssh_paths + [
        "/etc/sudoers", "/etc/crontab", "/etc/hosts.allow", "/etc/hosts.deny",
        "/etc/nftables.conf", "/etc/iptables/rules.v4", "/etc/iptables/rules.v6",
    ]
    paths = []
    for path in fixed_paths:
        if os.path.islink(path):
            try:
                target = os.readlink(path)
            except OSError:
                target = "unreadable"
            paths.append(path + "|symlink|" + target[:256])
        else:
            paths.append(path)
    ssh_directories = (
        ("/etc/ssh/sshd_config.d", (".conf",)),
        ("/etc/ssh/ssh_config.d", (".conf",)),
        ("/etc/pam.d", ("",)),
    )
    full_directories = (
        ("/etc/sudoers.d", ("",)),
        ("/etc/security/limits.d", ("",)),
        ("/etc/ufw", ("",)),
        ("/etc/iptables", ("",)),
        ("/etc/firewalld", ("",)),
        ("/etc/systemd/system", (".service", ".timer", ".path", ".socket", ".target", ".mount")),
        ("/etc/cron.d", ()), ("/etc/cron.hourly", ()), ("/etc/cron.daily", ()),
        ("/etc/cron.weekly", ()), ("/etc/cron.monthly", ()),
        ("/var/spool/cron", ()), ("/var/spool/cron/crontabs", ()),
    )
    directories = ssh_directories if ssh_only else ssh_directories + full_directories
    for directory, suffixes in directories:
        if not os.path.isdir(directory) or os.path.islink(directory):
            continue
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.name.startswith(".") or entry.name.endswith((".wants", ".requires")):
                        continue
                    if ssh_only and directory == "/etc/pam.d" and entry.name not in {
                        "common-auth", "common-account", "common-password", "common-session",
                    }:
                        continue
                    if suffixes and not any(entry.name.endswith(suffix) for suffix in suffixes):
                        continue
                    if entry.is_symlink():
                        try:
                            target = os.readlink(entry.path)
                        except OSError:
                            target = "unreadable"
                        paths.append(entry.path + "|symlink|" + target[:256])
                    elif entry.is_file(follow_symlinks=False):
                        paths.append(entry.path)
        except OSError:
            continue
    return sorted(set(paths))


def _critical_file_inventory(ssh_only: bool = False) -> Tuple[Dict[str, str], bool]:
    inventory: Dict[str, str] = {}
    complete = True
    total = 0
    for path in _candidate_config_paths(ssh_only=ssh_only):
        if "|symlink|" in path:
            link_path, target = path.split("|symlink|", 1)
            inventory[link_path] = hashlib.sha256(("symlink:" + target).encode()).hexdigest()
            continue
        if os.path.islink(path):
            continue
        try:
            if os.path.getsize(path) > 256 * 1024:
                complete = False
                continue
            with open(path, "rb") as handle:
                data = handle.read(256 * 1024 + 1)
            if len(data) > 256 * 1024:
                complete = False
                continue
            total += len(data)
            if total > MAX_SNAPSHOT_BYTES or len(inventory) >= MAX_SNAPSHOT_FILES:
                complete = False
                break
            inventory[path] = hashlib.sha256(data).hexdigest()
        except FileNotFoundError:
            continue
        except OSError:
            complete = False
    if len(inventory) >= MAX_SNAPSHOT_FILES:
        complete = False
    return inventory, complete


def _boot_id() -> str:
    try:
        with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as handle:
            value = handle.read(128).strip().lower()
        return value if re.fullmatch(r"[0-9a-f-]{16,64}", value) else ""
    except OSError:
        return ""


def _audit_scope() -> str:
    """Detect common container boundaries so full scans never imply host coverage."""
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        return "agent_container"
    try:
        with open("/run/systemd/container", "r", encoding="ascii", errors="ignore") as handle:
            if handle.read(128).strip().lower() in {"docker", "podman", "lxc", "incus", "systemd-nspawn", "openvz"}:
                return "agent_container"
    except OSError:
        pass
    for binary in ("/usr/bin/systemd-detect-virt", "/bin/systemd-detect-virt"):
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            continue
        try:
            result = subprocess.run(
                [binary, "--container"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=1,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip().lower() not in {"", "none"}:
                return "agent_container"
        except (OSError, subprocess.SubprocessError):
            continue
    container_cgroup = re.compile(
        r"(?:^|/)(?:docker-[0-9a-f]{12,64}|libpod-[0-9a-f-]{12,64}|kubepods(?:\.slice)?|"
        r"lxc(?:\.payload)?|incus)(?:/|\.|$)", re.IGNORECASE,
    )
    for path in ("/proc/self/cgroup", "/proc/1/cgroup"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                if container_cgroup.search(handle.read(64 * 1024)):
                    return "agent_container"
        except OSError:
            continue
    for path in ("/proc/self/mountinfo", "/proc/1/mountinfo"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                mountinfo = handle.read(256 * 1024).lower()
            if any(marker in mountinfo for marker in ("/var/lib/incus/containers/", "/var/lib/lxc/containers/")):
                return "agent_container"
        except OSError:
            continue
    return "host"


def collect_snapshot(now: Optional[int] = None, ssh_only: bool = False) -> Dict[str, Any]:
    """Collect a change-detection baseline without reading secrets or key bodies."""
    captured_at = int(time.time() if now is None else now)
    accounts, accounts_complete = _account_inventory()
    keys, keys_complete = _authorized_key_inventory(accounts)
    files, files_complete = _critical_file_inventory(ssh_only=ssh_only)
    os_id = ""
    os_version = ""
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle.read(32 * 1024).splitlines():
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                value = value.strip().strip('"').strip("'")
                if key == "ID":
                    os_id = value[:64]
                elif key == "VERSION_ID":
                    os_version = value[:64]
    except OSError:
        pass
    accounts_truncated = len(accounts) >= 256
    keys_truncated = len(keys) >= 2048
    files_truncated = len(files) >= MAX_SNAPSHOT_FILES
    complete = accounts_complete and keys_complete and files_complete and not (
        accounts_truncated or keys_truncated or files_truncated
    )
    return {
        "status": "ready" if complete else "partial",
        "captured_at": captured_at,
        "scope": "agent_container" if ssh_only else "host",
        "boot_id": _boot_id(),
        "os": {"id": os_id, "version_id": os_version},
        "kernel": platform.release()[:128],
        "user_accounts": accounts,
        "authorized_keys": keys,
        "critical_files": files,
        "limits": {
            "accounts_truncated": accounts_truncated,
            "authorized_keys_truncated": keys_truncated,
            "critical_files_truncated": files_truncated,
        },
    }


def _candidate(
    output: List[Dict[str, str]], name: str, version: str, ecosystem: str, source: str
) -> None:
    name = str(name or "").strip()[:300]
    version = str(version or "").strip()[:160]
    if not name or not version or not ecosystem or len(output) >= MAX_PACKAGE_CANDIDATES + 1:
        return
    output.append({
        "name": name,
        "version": version,
        "ecosystem": ecosystem[:80],
        "source": source[:32],
    })


def _read_os_release() -> Dict[str, str]:
    values: Dict[str, str] = {}
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle.read(32 * 1024).splitlines():
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                if key in ("ID", "VERSION_ID", "ID_LIKE"):
                    values[key] = value.strip().strip('"').strip("'")[:128]
    except OSError:
        pass
    return values


def _distro_ecosystem(os_release: Dict[str, str]) -> str:
    distro = os_release.get("ID", "").lower()
    if distro == "debian":
        return "Debian"
    if distro == "ubuntu":
        return "Ubuntu"
    if distro == "alpine":
        return "Alpine"
    if distro == "fedora":
        return "Fedora"
    if distro == "rocky":
        return "Rocky Linux"
    if distro == "almalinux":
        return "AlmaLinux"
    if distro in {"rhel", "redhat"}:
        return "Red Hat"
    if distro in {"opensuse-leap", "opensuse-tumbleweed"}:
        return "openSUSE"
    if distro in {"sles", "sled"}:
        return "SUSE"
    return ""


def _system_packages(os_release: Dict[str, str]) -> Tuple[List[Dict[str, str]], bool]:
    packages: List[Dict[str, str]] = []
    ecosystem = _distro_ecosystem(os_release)
    if not ecosystem:
        return packages, False
    distro = os_release.get("ID", "").lower()
    if distro in {"debian", "ubuntu"}:
        package_format = "-f=" + "$" + "{binary:Package}" + "\t" + "$" + "{Version}" + "\t" + "$" + "{db:Status-Status}" + "\n"
        code, output = _run(("dpkg-query", "-W", package_format), timeout=20, max_output=8_000_000)
        if code != 0:
            return packages, False
        for line in output.splitlines():
            fields = line.split("\t", 2)
            if len(fields) == 3 and fields[2] == "installed" and not fields[1].startswith("<"):
                _candidate(packages, fields[0].split(":", 1)[0], fields[1], ecosystem, "system")
    elif distro == "alpine":
        code, output = _run(("apk", "info", "-v"), timeout=20, max_output=8_000_000)
        if code != 0:
            return packages, False
        for line in output.splitlines():
            match = re.match(r"^(.+)-([0-9][A-Za-z0-9.+_~:]*-r[0-9]+)$", line.strip())
            if match:
                _candidate(packages, match.group(1), match.group(2), ecosystem, "system")
    else:
        rpm = shutil_which("rpm")
        if not rpm:
            return packages, False
        package_format = "%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n"
        code, output = _run((rpm, "-qa", "--qf", package_format), timeout=30, max_output=8_000_000)
        if code != 0:
            return packages, False
        for line in output.splitlines():
            fields = line.split("\t", 1)
            if len(fields) != 2:
                continue
            version = fields[1]
            if version.startswith("(none):"):
                version = version[len("(none):"):]
            elif version.startswith("0:"):
                version = version[2:]
            _candidate(packages, fields[0], version, ecosystem, "system")
    return packages[:MAX_PACKAGE_CANDIDATES + 1], True


def shutil_which(name: str) -> str:
    for directory in os.getenv("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def _parse_npm_lock(data: Any, output: List[Dict[str, str]]) -> None:
    if not isinstance(data, dict):
        return
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, item in packages.items():
            if not path or not isinstance(item, dict):
                continue
            marker = "node_modules/"
            if marker not in path:
                continue
            name = path.rsplit(marker, 1)[1]
            _candidate(output, name, item.get("version", ""), "npm", "lockfile")
    dependencies = data.get("dependencies")
    stack = [dependencies] if isinstance(dependencies, dict) else []
    while stack and len(output) <= MAX_PACKAGE_CANDIDATES:
        current = stack.pop()
        for name, item in current.items():
            if not isinstance(item, dict):
                continue
            _candidate(output, name, item.get("version", ""), "npm", "lockfile")
            children = item.get("dependencies")
            if isinstance(children, dict):
                stack.append(children)


def _parse_json_lock(path: str, output: List[Dict[str, str]]) -> bool:
    try:
        if os.path.getsize(path) > 2 * 1024 * 1024:
            return False
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return False
    name = os.path.basename(path).lower()
    if name == "package-lock.json" or name == "npm-shrinkwrap.json":
        _parse_npm_lock(data, output)
    elif name == "composer.lock" and isinstance(data, dict):
        packages = data.get("packages") if isinstance(data.get("packages"), list) else []
        development = data.get("packages-dev") if isinstance(data.get("packages-dev"), list) else []
        for package in packages + development:
            if isinstance(package, dict):
                _candidate(output, package.get("name", ""), package.get("version", ""), "Packagist", "lockfile")
    elif name == "packages.lock.json" and isinstance(data, dict):
        stack = [data.get("dependencies")]
        while stack and len(output) <= MAX_PACKAGE_CANDIDATES:
            current = stack.pop()
            if not isinstance(current, dict):
                continue
            for package_name, item in current.items():
                if not isinstance(item, dict):
                    continue
                _candidate(output, package_name, item.get("resolved", ""), "NuGet", "lockfile")
                stack.append(item.get("dependencies"))
    return True


def _parse_maven_pom(path: str, output: List[Dict[str, str]]) -> bool:
    try:
        if os.path.getsize(path) > 2 * 1024 * 1024:
            return False
        with open(path, "rb") as handle:
            root = ET.fromstring(handle.read(2 * 1024 * 1024 + 1))
    except (OSError, ET.ParseError):
        return False
    parents = {child: parent for parent in root.iter() for child in parent}

    def tag_name(node: Any) -> str:
        return str(node.tag).rsplit("}", 1)[-1]

    complete = True
    saw_dependency_declaration = False
    for dependency in root.iter():
        if tag_name(dependency) != "dependency":
            continue
        saw_dependency_declaration = True
        dependencies = parents.get(dependency)
        if dependencies is None or tag_name(dependencies) != "dependencies":
            continue
        owner = parents.get(dependencies)
        if owner is not None and tag_name(owner) in {"dependencyManagement", "pluginManagement", "plugin", "reporting"}:
            continue
        fields = {}
        for child in dependency:
            if tag_name(child) in {"groupId", "artifactId", "version"}:
                fields[tag_name(child)] = (child.text or "").strip()
        group = fields.get("groupId", "")
        artifact = fields.get("artifactId", "")
        version = fields.get("version", "")
        if not group or not artifact:
            complete = False
            continue
        if not version or "$" in version or version.lower() in {"latest", "release"} or "[" in version or "]" in version:
            complete = False
            continue
        _candidate(output, group + ":" + artifact, version, "Maven", "manifest")
    # A POM is a manifest, not a resolved lockfile: transitive dependencies,
    # profiles, and inherited properties may alter the actual resolved set.
    return complete and not saw_dependency_declaration


def _parse_text_lock(path: str, output: List[Dict[str, str]]) -> bool:
    try:
        if os.path.getsize(path) > 2 * 1024 * 1024:
            return False
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read(2 * 1024 * 1024)
    except OSError:
        return False
    basename = os.path.basename(path).lower()
    if basename == "cargo.lock":
        name = version = ""
        for line in content.splitlines():
            match = re.match(r'^\s*name\s*=\s*"([^"]+)"\s*$', line)
            if match:
                name = match.group(1)
                continue
            match = re.match(r'^\s*version\s*=\s*"([^"]+)"\s*$', line)
            if match and name:
                version = match.group(1)
                _candidate(output, name, version, "crates.io", "lockfile")
                name = version = ""
    elif basename == "gemfile.lock":
        in_specs = False
        for line in content.splitlines():
            if re.match(r"^\s{2}specs:\s*$", line):
                in_specs = True
                continue
            if in_specs and line and not line.startswith("    "):
                in_specs = False
            if in_specs:
                match = re.match(r"^\s{4}([A-Za-z0-9_.-]+) \(([^ )]+)\)", line)
                if match:
                    _candidate(output, match.group(1), match.group(2), "RubyGems", "lockfile")
    elif basename == "go.sum":
        for line in content.splitlines():
            fields = line.split()
            if len(fields) == 2 and not fields[1].endswith("/go.mod"):
                version = fields[1]
                if version.startswith("v"):
                    module = re.sub(r"!([a-z])", lambda match: match.group(1).upper(), fields[0])
                    _candidate(output, module, version, "Go", "lockfile")
    elif basename in {"requirements.txt", "requirements.lock"}:
        for line in content.splitlines():
            match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+!-]+)", line)
            if match:
                _candidate(output, match.group(1), match.group(2), "PyPI", "lockfile")
    elif basename == "poetry.lock":
        name = version = ""
        for line in content.splitlines():
            match = re.match(r'^\s*name\s*=\s*"([^"]+)"\s*$', line)
            if match:
                name = match.group(1)
                continue
            match = re.match(r'^\s*version\s*=\s*"([^"]+)"\s*$', line)
            if match and name:
                version = match.group(1)
                _candidate(output, name, version, "PyPI", "lockfile")
                name = version = ""
    return True


def _walk_lockfiles(roots: Sequence[str]) -> Tuple[List[Dict[str, str]], bool, int]:
    packages: List[Dict[str, str]] = []
    complete = True
    file_count = 0
    visited_dirs = 0
    walk_errors = []
    json_names = {"package-lock.json", "npm-shrinkwrap.json", "composer.lock", "packages.lock.json"}
    text_names = {"cargo.lock", "gemfile.lock", "go.sum", "requirements.txt", "requirements.lock", "poetry.lock", "pom.xml"}
    skip_dirs = {".git", "node_modules", "vendor", ".cache", "__pycache__", "target", "dist"}
    for root in roots:
        if not os.path.isdir(root) or os.path.islink(root):
            continue
        for current, dirs, files in os.walk(root, followlinks=False, onerror=lambda error: walk_errors.append(error)):
            visited_dirs += 1
            dirs[:] = [name for name in dirs if name not in skip_dirs and not os.path.islink(os.path.join(current, name))]
            if visited_dirs > MAX_WALK_DIRS:
                return packages, False, file_count
            for filename in files:
                basename = filename.lower()
                if basename not in json_names | text_names:
                    continue
                if file_count >= MAX_LOCKFILES:
                    return packages, False, file_count
                path = os.path.join(current, filename)
                if os.path.islink(path):
                    continue
                file_count += 1
                if basename in json_names:
                    ok = _parse_json_lock(path, packages)
                elif basename == "pom.xml":
                    ok = _parse_maven_pom(path, packages)
                else:
                    ok = _parse_text_lock(path, packages)
                complete = complete and ok
                if len(packages) > MAX_PACKAGE_CANDIDATES:
                    return packages, False, file_count
    return packages, complete and not walk_errors, file_count


def _python_site_roots() -> Tuple[List[str], bool]:
    roots = []
    complete = True
    for pattern in (
        "/usr/lib/python*/site-packages", "/usr/lib/python*/dist-packages",
        "/usr/local/lib/python*/site-packages", "/usr/local/lib/python*/dist-packages",
    ):
        roots.extend(glob.glob(pattern))
    try:
        paths = sysconfig.get_paths()
        roots.extend(paths.get(key, "") for key in ("purelib", "platlib") if paths.get(key))
    except Exception:
        complete = False

    # Applications frequently keep vulnerable dependencies in virtualenvs,
    # outside the running Agent's interpreter. Find their metadata without
    # importing or executing any installed package or .pth/sitecustomize hook.
    walk_roots = ("/opt", "/srv", "/var/www", "/www", "/home", "/root", "/workspace", "/app")
    skip_dirs = {".git", ".cache", "node_modules", "vendor", "__pycache__", "target", "dist", "logs"}
    visited_dirs = 0
    walk_errors = []
    stop = False
    for base_root in walk_roots:
        if stop:
            break
        if not os.path.isdir(base_root) or os.path.islink(base_root):
            continue
        base_depth = base_root.rstrip(os.sep).count(os.sep)
        for current, dirs, _files in os.walk(
            base_root, followlinks=False, onerror=lambda _error: walk_errors.append(True)
        ):
            visited_dirs += 1
            if visited_dirs > MAX_PYTHON_ROOT_WALK_DIRS:
                complete = False
                stop = True
                break
            depth = current.rstrip(os.sep).count(os.sep) - base_depth
            dirs[:] = [
                name for name in dirs
                if name not in skip_dirs and depth < 8
                and not os.path.islink(os.path.join(current, name))
            ]
            if os.path.basename(current) in {"site-packages", "dist-packages"}:
                roots.append(current)
                dirs[:] = []
    if walk_errors:
        complete = False
    normalized = sorted(set(os.path.normpath(path) for path in roots if path))
    return normalized, complete


def _python_package_inventory() -> Tuple[List[Dict[str, str]], bool, List[str], List[Dict[str, str]]]:
    packages: List[Dict[str, str]] = []
    complete = True
    roots, roots_complete = _python_site_roots()
    complete = complete and roots_complete
    startup_indicators: List[Dict[str, str]] = []
    inspected_entries = 0
    for root in roots:
        if os.path.islink(root):
            complete = False
            continue
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    inspected_entries += 1
                    if inspected_entries > MAX_PACKAGE_CANDIDATES * 8:
                        complete = False
                        break
                    if entry.name in {"cook.pth", "cook.py", "sitecustomize.py"}:
                        if entry.is_file(follow_symlinks=False) and not entry.is_symlink():
                            startup_indicators.append({"kind": entry.name, "path": entry.path[:500]})
                    if entry.name == "__pycache__" and entry.is_dir(follow_symlinks=False):
                        try:
                            with os.scandir(entry.path) as cached:
                                for cached_entry in cached:
                                    if re.fullmatch(r"cook(?:\.[A-Za-z0-9_-]+)?\.pyc", cached_entry.name):
                                        if cached_entry.is_file(follow_symlinks=False) and not cached_entry.is_symlink():
                                            startup_indicators.append({
                                                "kind": "cook.pyc", "path": cached_entry.path[:500],
                                            })
                        except OSError:
                            complete = False
                    if not entry.name.endswith(".dist-info") or not entry.is_dir(follow_symlinks=False):
                        continue
                    metadata = os.path.join(entry.path, "METADATA")
                    if os.path.islink(metadata):
                        complete = False
                        continue
                    name = version = ""
                    try:
                        if os.path.getsize(metadata) > 64 * 1024:
                            complete = False
                            continue
                        with open(metadata, "r", encoding="utf-8", errors="replace") as handle:
                            for line in handle.read(64 * 1024).splitlines():
                                if line.startswith("Name: ") and not name:
                                    name = line[6:].strip()
                                elif line.startswith("Version: ") and not version:
                                    version = line[9:].strip()
                                if name and version:
                                    break
                    except OSError:
                        complete = False
                        continue
                    old_len = len(packages)
                    _candidate(packages, name, version, "PyPI", "installed")
                    if len(packages) > old_len:
                        packages[-1]["location"] = root[:500]
                    if len(packages) > MAX_PACKAGE_CANDIDATES:
                        complete = False
                        break
            if inspected_entries > MAX_PACKAGE_CANDIDATES * 8 or len(packages) > MAX_PACKAGE_CANDIDATES:
                break
        except OSError:
            complete = False
            continue
    unique_indicators = {}
    for item in startup_indicators:
        unique_indicators[(item["kind"], item["path"])] = item
    return packages[:MAX_PACKAGE_CANDIDATES + 1], complete, roots, list(unique_indicators.values())[:200]


def _python_packages() -> Tuple[List[Dict[str, str]], bool]:
    packages, complete, _roots, _startup_indicators = _python_package_inventory()
    return packages, complete


def _collect_package_candidates() -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    os_release = _read_os_release()
    system_packages, system_complete = _system_packages(os_release)
    python_packages, python_complete = _python_packages()
    lock_packages, lock_complete, lockfiles = _walk_lockfiles(
        ("/opt", "/srv", "/var/www", "/home", "/root", "/workspace", "/app")
    )
    combined = system_packages + python_packages + lock_packages
    seen = set()
    unique = []
    for item in combined:
        key = (item["ecosystem"], item["name"].lower(), item["version"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    truncated = len(unique) > MAX_PACKAGE_CANDIDATES
    unique = unique[:MAX_PACKAGE_CANDIDATES]
    coverage = system_complete and python_complete and lock_complete and not truncated
    return unique, {
        "status": "complete" if coverage else "partial",
        "os": {"id": os_release.get("ID", ""), "version_id": os_release.get("VERSION_ID", "")},
        "ecosystem": _distro_ecosystem(os_release),
        "system_packages": len(system_packages),
        "python_packages": len(python_packages),
        "lockfiles": lockfiles,
        "packages_checked": len(unique),
        "truncated": truncated,
    }


def _cvss3_base_score(vector: str) -> float:
    values = {}
    for item in str(vector or "").split("/"):
        if ":" in item:
            key, value = item.split(":", 1)
        elif "=" in item:
            key, value = item.split("=", 1)
        else:
            continue
        if key in {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}:
            values[key] = value
    av = {"N": .85, "A": .62, "L": .55, "P": .2}.get(values.get("AV", ""))
    ac = {"L": .77, "H": .44}.get(values.get("AC", ""))
    scope = values.get("S", "")
    pr_values = (
        {"N": .85, "L": .68, "H": .5} if scope == "C"
        else {"N": .85, "L": .62, "H": .27}
    )
    pr = pr_values.get(values.get("PR", ""))
    ui = {"N": .85, "R": .62}.get(values.get("UI", ""))
    impact_values = {"H": .56, "L": .22, "N": 0.0}
    c = impact_values.get(values.get("C", ""))
    i = impact_values.get(values.get("I", ""))
    a = impact_values.get(values.get("A", ""))
    if None in (av, ac, pr, ui, c, i, a) or scope not in {"U", "C"}:
        return 0.0
    isc = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * isc
    else:
        impact = 7.52 * (isc - .029) - 3.25 * ((isc - .02) ** 15)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    base = min(impact + exploitability, 10) if scope == "U" else min(1.08 * (impact + exploitability), 10)
    return math.ceil((base - 1e-10) * 10) / 10


def _vulnerability_score(vuln: Dict[str, Any]) -> float:
    severity_values = []
    database_specific = vuln.get("database_specific")
    if isinstance(database_specific, dict):
        severity_values.append(database_specific.get("severity"))
    affected = vuln.get("affected") if isinstance(vuln.get("affected"), list) else []
    for item in affected:
        if not isinstance(item, dict):
            continue
        for key in ("database_specific", "ecosystem_specific"):
            specific = item.get(key)
            if isinstance(specific, dict):
                severity_values.append(specific.get("severity"))
    severity_scores = {
        "critical": 9.0, "important": 9.0, "high": 8.0,
        "moderate": 5.5, "medium": 5.5, "low": 3.0,
    }
    for raw_severity in severity_values:
        severity_score = severity_scores.get(str(raw_severity or "").strip().lower())
        if severity_score is not None:
            return severity_score
    score = 0.0
    severities = vuln.get("severity") if isinstance(vuln.get("severity"), list) else []
    for item in severities:
        if not isinstance(item, dict):
            continue
        raw = str(item.get("score") or "")
        try:
            score = max(score, float(raw))
            continue
        except ValueError:
            pass
        if raw.startswith("CVSS:3"):
            score = max(score, _cvss3_base_score(raw))
    return score


def _osv_vulnerability_details(vulnerability_id: str, deadline: float) -> Optional[Dict[str, Any]]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    url = "https://api.osv.dev/v1/vulns/" + urllib.parse.quote(vulnerability_id, safe="")
    request = urllib.request.Request(url, headers={"User-Agent": "Narwhal-Host-Audit/1"}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=min(2.5, remaining)) as response:
            raw = response.read(128 * 1024 + 1)
        if len(raw) > 128 * 1024:
            return None
        payload = json.loads(raw.decode("utf-8", "replace"))
        if not isinstance(payload, dict) or str(payload.get("id") or "") != vulnerability_id:
            return None
        return payload
    except Exception:
        return None


def _osv_batch(packages: List[Dict[str, str]]) -> Tuple[List[Dict[str, Any]], bool, str]:
    started_at = time.monotonic()
    deadline = started_at + 45.0
    request_count = 0
    raw_matches: List[Dict[str, Any]] = []
    query_complete = True
    error = ""
    try:
        for start in range(0, len(packages), 100):
            batch = packages[start:start + 100]
            pending = [
                ({
                    "package": {"name": item["name"], "ecosystem": item["ecosystem"]},
                    "version": item["version"],
                }, item, 0)
                for item in batch
            ]
            while pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or request_count >= 30:
                    query_complete = False
                    error = "OSV 扫描达到时间或请求上限"
                    break
                queries = [query for query, _, _ in pending]
                body = json.dumps({"queries": queries}, separators=(",", ":")).encode("utf-8")
                request = urllib.request.Request(
                    "https://api.osv.dev/v1/querybatch", data=body,
                    headers={"Content-Type": "application/json", "User-Agent": "Narwhal-Host-Audit/1"},
                    method="POST",
                )
                request_count += 1
                with urllib.request.urlopen(request, timeout=min(15.0, remaining)) as response:
                    payload = json.loads(response.read(4 * 1024 * 1024).decode("utf-8", "replace"))
                results = payload.get("results") if isinstance(payload, dict) else None
                if not isinstance(results, list) or len(results) != len(pending):
                    query_complete = False
                    error = "OSV 返回的批量结果不完整"
                    break
                next_pending = []
                for (query, package, page_count), result in zip(pending, results):
                    if not isinstance(result, dict) or not isinstance(result.get("vulns", []), list):
                        query_complete = False
                        error = "OSV 返回的漏洞列表格式无效"
                        continue
                    for vuln in result.get("vulns", []):
                        if not isinstance(vuln, dict) or not str(vuln.get("id") or "").strip():
                            continue
                        if len(raw_matches) >= MAX_FINDINGS:
                            query_complete = False
                            error = "匹配结果超过保留上限"
                            break
                        raw_matches.append({
                            "id": str(vuln.get("id") or "")[:160],
                            "modified": str(vuln.get("modified") or "")[:40],
                            "package": package,
                        })
                    token = str(result.get("next_page_token") or "")
                    if token:
                        if page_count >= 3 or len(raw_matches) >= MAX_FINDINGS:
                            query_complete = False
                            error = "OSV 漏洞分页超过扫描上限"
                        else:
                            next_query = dict(query)
                            next_query["page_token"] = token[:4096]
                            next_pending.append((next_query, package, page_count + 1))
                pending = next_pending
                if not query_complete:
                    break
            if not query_complete:
                break
    except Exception as exc:
        query_complete = False
        error = f"OSV 查询失败：{str(exc)[:200]}"

    vulnerability_ids = list(dict.fromkeys(item["id"] for item in raw_matches))
    details: Dict[str, Dict[str, Any]] = {}
    detail_complete = len(vulnerability_ids) <= 200
    ids_to_fetch = vulnerability_ids[:200]
    if ids_to_fetch and time.monotonic() < deadline:
        worker_count = min(20, len(ids_to_fetch))
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_to_id = {
                executor.submit(_osv_vulnerability_details, vulnerability_id, deadline): vulnerability_id
                for vulnerability_id in ids_to_fetch
            }
            try:
                for future in concurrent.futures.as_completed(future_to_id, timeout=max(0.1, deadline - time.monotonic())):
                    vulnerability_id = future_to_id[future]
                    try:
                        detail = future.result()
                    except Exception:
                        detail = None
                    if detail is not None:
                        details[vulnerability_id] = detail
            except concurrent.futures.TimeoutError:
                pass
    if len(details) != len(vulnerability_ids):
        detail_complete = False
        if not error:
            error = "部分 OSV 漏洞详情未能在扫描时限内取得"

    findings = []
    for match in raw_matches:
        vulnerability_id = match["id"]
        vuln = details.get(vulnerability_id) or {"id": vulnerability_id}
        score = _vulnerability_score(vuln)
        aliases = vuln.get("aliases") if isinstance(vuln.get("aliases"), list) else []
        package = match["package"]
        findings.append({
            "id": vulnerability_id[:80],
            "cve": next((str(item) for item in aliases if str(item).startswith("CVE-")), "")[:80],
            "summary": str(vuln.get("summary") or "")[:500],
            "package": package["name"][:160],
            "version": package["version"][:100],
            "ecosystem": package["ecosystem"][:80],
            "source": package.get("source", "")[:32],
            "severity": "critical" if score >= 9 else "warning",
            "score": score or None,
            "modified": str(vuln.get("modified") or match.get("modified") or "")[:40],
        })
    findings.sort(key=lambda item: (item["severity"] != "critical", item["package"], item["id"]))
    return findings, query_complete and detail_complete, error


def _scan_vulnerabilities(now: int) -> Dict[str, Any]:
    global _STATE
    previous = _STATE.get("vulnerability_scan")
    previous = previous if isinstance(previous, dict) else {}
    last_attempt = _safe_int(previous.get("last_attempt_at"))
    previous_status = str(previous.get("status") or "")
    due_after = RETRY_INTERVAL if previous_status in {"partial", "unavailable", "stale"} else DEFAULT_SCAN_INTERVAL
    if last_attempt and now - last_attempt < due_after:
        return previous
    # Persist the attempt before network activity so offline nodes do not hammer OSV.
    previous["last_attempt_at"] = now
    _STATE["vulnerability_scan"] = previous
    _save_state()
    try:
        packages, inventory = _collect_package_candidates()
        findings, query_complete, error = _osv_batch(packages)
    except Exception as exc:
        packages = []
        inventory = {"status": "partial", "packages_checked": 0}
        findings, query_complete, error = [], False, f"主机软件清单采集失败：{str(exc)[:200]}"
    complete = inventory["status"] == "complete" and query_complete
    old_findings = previous.get("findings") if isinstance(previous.get("findings"), list) else []
    if complete:
        saved_findings = findings
    else:
        merged = {}
        for item in old_findings + findings:
            if not isinstance(item, dict):
                continue
            key = (
                str(item.get("ecosystem") or ""), str(item.get("package") or ""),
                str(item.get("version") or ""), str(item.get("id") or ""),
            )
            merged[key] = item
        saved_findings = list(merged.values())[:MAX_FINDINGS]
    result = {
        "status": "complete" if complete else "stale" if error else "partial",
        "last_attempt_at": now,
        "checked_at": now if complete else _safe_int(previous.get("checked_at")),
        "coverage": "complete" if complete else "partial" if packages else "unavailable",
        "packages_checked": len(packages),
        "finding_count": len(saved_findings),
        "critical_count": sum(1 for item in saved_findings if item.get("severity") == "critical"),
        "findings": saved_findings,
        "error": error[:240] if error else "",
        "inventory": inventory,
    }
    _STATE["vulnerability_scan"] = result
    _save_state()
    return result


def _version_at_least(value: str, fixed: str) -> bool:
    def parts(text: str) -> Tuple[Tuple[int, ...], bool]:
        raw = str(text or "").strip().lower()
        if "!" in raw:
            raw = raw.split("!", 1)[1]
        match = re.match(r"^v?(\d+(?:\.\d+){0,5})", raw)
        if not match:
            return (), False
        values = tuple(int(item) for item in match.group(1).split("."))
        prerelease = bool(re.search(r"(?:^|[.+-])(?:a|b|rc|dev)\d*", raw[match.end():]))
        return values, prerelease

    current, current_prerelease = parts(value)
    expected, _expected_prerelease = parts(fixed)
    if not current or not expected:
        return False
    width = max(len(current), len(expected), 4)
    current += (0,) * (width - len(current))
    expected += (0,) * (width - len(expected))
    return current > expected or (current == expected and not current_prerelease)


def _indicator(
    rule_id: str,
    severity: str,
    component: str,
    title: str,
    evidence: Sequence[str],
    guidance: str,
    reference: str = "",
) -> Dict[str, Any]:
    return {
        "id": str(rule_id)[:240],
        "rule": str(rule_id).split(":", 1)[0][:120],
        "severity": severity if severity in {"critical", "warning", "info"} else "warning",
        "component": str(component)[:120],
        "title": str(title)[:240],
        "evidence": [str(item)[:500] for item in evidence[:5]],
        "guidance": str(guidance)[:500],
        "reference": str(reference)[:500],
    }


def _collapse_security_indicators(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    severity_rank = {"critical": 2, "warning": 1, "info": 0}
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in findings:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        key = (str(item.get("rule") or item.get("id")), str(item.get("title") or ""))
        current = groups.get(key)
        if current is None:
            current = dict(item)
            current["finding_ids"] = []
            current["evidence"] = []
            current["instance_count"] = 0
            current["id"] = hashlib.sha256((key[0] + "|" + key[1]).encode()).hexdigest()[:32]
            groups[key] = current
        if len(current["finding_ids"]) < 200:
            current["finding_ids"].append(str(item["id"])[:240])
        current["instance_count"] += max(1, _safe_int(item.get("instance_count"), 1))
        if severity_rank.get(str(item.get("severity")), 0) > severity_rank.get(str(current.get("severity")), 0):
            current["severity"] = item.get("severity")
        for evidence in item.get("evidence", []) if isinstance(item.get("evidence"), list) else []:
            if evidence and evidence not in current["evidence"] and len(current["evidence"]) < 5:
                current["evidence"].append(evidence)
    output = list(groups.values())
    output.sort(key=lambda item: (severity_rank.get(str(item.get("severity")), 0) * -1, str(item.get("id") or "")))
    return output[:MAX_INDICATOR_FINDINGS]


def _python_indicator_findings(
    packages: List[Dict[str, str]], startup_indicators: List[Dict[str, str]]
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    installed: Dict[Tuple[str, str], List[str]] = {}
    for package in packages:
        name = re.sub(r"[-_.]+", "-", str(package.get("name") or "").strip().lower())
        version = str(package.get("version") or "").strip()
        location = str(package.get("location") or "Python site-packages")
        if not name or not version:
            continue
        installed.setdefault((name, version), []).append(location)
    safe_versions = {
        "certifi": ("2026.10.19", "certifi", PYTHON_CA_REFERENCE),
        "pip": ("26.2.2", "pip", PYTHON_CA_REFERENCE),
        "uv": ("0.13.4", "uv", "https://github.com/astral-sh/uv/security/advisories/GHSA-hq85-5cpj-mr62"),
        "sigstore": ("4.5.1", "sigstore", PYTHON_CA_REFERENCE),
    }
    for (name, version), locations in sorted(installed.items()):
        unique_locations = sorted(set(locations))
        if name == "litellm" and version == "1.107.0":
            findings.append(_indicator(
                "litellm-package-1.107.0:" + hashlib.sha256("|".join(unique_locations).encode()).hexdigest()[:16],
                "critical", "LiteLLM 供应链事件", "发现受影响的 litellm==1.107.0 安装元数据",
                [f"{location} · litellm=={version}" for location in unique_locations[:5]],
                "不要导入或启动该环境；先保留证据，依照官方通告隔离并从可信版本重建、轮换可能暴露的凭证。仅凭安装元数据不能证明代码已执行或主机已失陷。",
                LITELLM_INCIDENT_REFERENCE,
            ))
        baseline = safe_versions.get(name)
        if baseline and not _version_at_least(version, baseline[0]):
            findings.append(_indicator(
                "emudhra-python-ca:" + name + ":" + hashlib.sha256("|".join(unique_locations).encode()).hexdigest()[:16],
                "warning", "emSign CA 事件 / Python 信任库",
                f"{baseline[1]} {version} 低于事件修复基线 {baseline[0]}",
                [f"{location} · {name}=={version}" for location in unique_locations[:5]],
                "按上游事件公告升级该组件；该版本命中表示信任库可能未更新，不代表已发生恶意证书连接。",
                baseline[2],
            ))

    for item in startup_indicators:
        kind = str(item.get("kind") or "")
        path = str(item.get("path") or "")
        if kind in {"cook.pth", "cook.py", "cook.pyc"}:
            findings.append(_indicator(
                "litellm-startup-ioc:" + hashlib.sha256((kind + "|" + path).encode()).hexdigest()[:20],
                "critical", "LiteLLM 供应链事件", "发现 LiteLLM 事件相关 Python 启动文件 IOC",
                [path],
                "不要执行、导入或删除该文件；先保全文件元数据与镜像/主机证据，再按官方事件响应步骤隔离调查。单个 IOC 需要结合来源与哈希复核。",
                LITELLM_INCIDENT_REFERENCE,
            ))
        elif kind == "sitecustomize.py":
            findings.append(_indicator(
                "python-sitecustomize:" + hashlib.sha256(path.encode()).hexdigest()[:20],
                "warning", "Python 启动钩子复核", "发现 sitecustomize.py，需要核对来源",
                [path],
                "该启动钩子也可能由合法软件安装；本检查不读取、不执行其内容，请核对文件归属、包清单、时间戳与变更记录。",
                LITELLM_INCIDENT_REFERENCE,
            ))
    return findings


def _config_candidate(path: str) -> bool:
    name = os.path.basename(path).lower()
    normalized = path.replace("\\", "/").lower()
    exact_names = {
        "nginx.conf", "traefik.yml", "traefik.yaml", "dynamic.yml", "dynamic.yaml",
        "config.toml", "sshd_config", "docker-compose.yml", "docker-compose.yaml",
        "compose.yml", "compose.yaml", "dockerfile", ".gitlab-ci.yml",
        "wp-config.php", "config.php", "settings.py",
    }
    return (
        name in exact_names
        or (name == "config.toml" and "/etc/gitlab-runner/" in normalized)
        or (normalized.startswith("/etc/nginx/") and name.endswith(".conf"))
        or (normalized.startswith("/etc/ssh/sshd_config.d/") and name.endswith(".conf"))
        or ("/.github/workflows/" in normalized and name.endswith((".yml", ".yaml")))
    )


def _scan_static_security_configs(ssh_only: bool = False) -> Tuple[List[Dict[str, Any]], Dict[str, str], bool, int]:
    roots = ("/etc/ssh",) if ssh_only else (
        "/etc/nginx", "/etc/traefik", "/etc/gitlab-runner", "/etc/gitlab", "/etc/ssh",
        "/var/www", "/www", "/opt", "/srv",
    )
    skip_dirs = {".git", ".cache", "node_modules", "vendor", "__pycache__", "target", "dist", "logs"}
    paths = set()
    backup_paths = set()
    complete = True
    visited = 0
    discovered_files = 0
    walk_errors = []
    for root in roots:
        if not os.path.isdir(root) or os.path.islink(root):
            continue
        root_depth = root.rstrip(os.sep).count(os.sep)
        for current, dirs, files in os.walk(
            root, followlinks=False, onerror=lambda _error: walk_errors.append(True)
        ):
            visited += 1
            depth = current.rstrip(os.sep).count(os.sep) - root_depth
            dirs[:] = [
                name for name in dirs
                if name not in skip_dirs and depth < 7
                and not os.path.islink(os.path.join(current, name))
            ]
            for filename in files:
                discovered_files += 1
                if discovered_files > MAX_INDICATOR_CONFIG_FILES * 25:
                    complete = False
                    break
                path = os.path.join(current, filename)
                if os.path.islink(path):
                    continue
                if _config_candidate(path):
                    paths.add(path)
                lowered = filename.lower()
                if root in {"/var/www", "/www"} and re.search(
                    r"(?:wp-config\.php\.(?:bak|old|txt|save|backup|swp)|wp-config\.bak|(?:backup|dump)\.sql(?:\.gz)?)$",
                    lowered,
                ):
                    # Report only that a backup-like filename exists; never read it.
                    if len(backup_paths) < MAX_INDICATOR_FINDINGS:
                        backup_paths.add(path)
                    else:
                        complete = False
            if visited >= 3000 or discovered_files > MAX_INDICATOR_CONFIG_FILES * 25 or len(paths) > MAX_INDICATOR_CONFIG_FILES:
                complete = False
                break
        if visited >= 3000 or discovered_files > MAX_INDICATOR_CONFIG_FILES * 25 or len(paths) > MAX_INDICATOR_CONFIG_FILES:
            break
    if walk_errors:
        complete = False

    patterns = [
        ("nginx-upstream-tls-off", "warning", "Nginx 上游 TLS 证书验证关闭", re.compile(r"^\s*proxy_ssl_verify\s+off\s*;", re.I)),
        ("nginx-mtls-untrusted", "warning", "Nginx mTLS 接受未验证 CA 的客户端证书", re.compile(r"^\s*ssl_verify_client\s+optional_no_ca\s*;", re.I)),
        ("nginx-mtls-optional", "warning", "Nginx 客户端证书认证为可选", re.compile(r"^\s*ssl_verify_client\s+optional\s*;", re.I)),
        ("nginx-old-tls", "warning", "Nginx 配置允许 TLS 1.0/1.1", re.compile(r"^\s*ssl_protocols\s+[^;]*\bTLSv1(?:\.1)?\b[^;]*;", re.I)),
        ("traefik-tls-insecure", "warning", "Traefik 上游 TLS 证书校验关闭", re.compile(r"^\s*insecureSkipVerify\s*:\s*true\b", re.I)),
        ("traefik-mtls-optional", "warning", "Traefik 客户端证书认证为 VerifyIfGiven", re.compile(r"^\s*clientAuthType\s*:\s*[\"']?VerifyIfGiven\b", re.I)),
        ("runner-shell-executor", "warning", "GitLab Runner 使用宿主机 shell executor", re.compile(r"^\s*executor\s*=\s*[\"']shell[\"']", re.I)),
        ("runner-privileged", "warning", "GitLab Runner 启用 privileged 容器", re.compile(r"^\s*privileged\s*=\s*true\b", re.I)),
        ("runner-tls-disabled", "warning", "GitLab Runner 关闭 TLS 校验", re.compile(r"^\s*tls_verify\s*=\s*false\b", re.I)),
        ("compose-privileged", "warning", "容器编排配置启用 privileged", re.compile(r"^\s*privileged\s*:\s*true\b", re.I)),
        ("compose-docker-socket", "warning", "容器编排配置挂载 Docker Socket", re.compile(r"/var/run/docker\.sock\s*:\s*/var/run/docker\.sock", re.I)),
        ("compose-host-root", "warning", "容器编排配置将宿主机根目录挂入容器", re.compile(r"^\s*-\s*[\"']?/\s*:\s*/(?:host|root|mnt)\b", re.I)),
        ("ci-floating-action", "warning", "GitHub Actions 引用了未固定版本的浮动分支", re.compile(r"^\s*uses\s*:\s*[^\s#]+@(main|master|latest)\b", re.I)),
        ("sshd-root-login", "warning", "sshd 配置允许 root 登录", re.compile(r"^\s*PermitRootLogin\s+yes\s*(?:#.*)?$", re.I)),
        ("sshd-password-auth", "info", "sshd 配置允许密码认证", re.compile(r"^\s*PasswordAuthentication\s+yes\s*(?:#.*)?$", re.I)),
        ("tls-verification-disabled", "warning", "配置疑似关闭 TLS 证书验证", re.compile(r"^\s*(?:insecure_skip_verify|insecureSkipVerify)\s*[:=]\s*true\b|^\s*(?:verify_tls|tls_verify)\s*[:=]\s*false\b", re.I)),
    ]
    if ssh_only:
        patterns = [item for item in patterns if item[0].startswith("sshd-")]
    findings: List[Dict[str, Any]] = []
    for path in sorted(backup_paths)[:MAX_INDICATOR_FINDINGS]:
        findings.append(_indicator(
            "wordpress-backup:" + hashlib.sha256(path.encode()).hexdigest()[:20], "warning",
            "WordPress 备份文件", "Web 根目录发现可能暴露的配置/数据库备份文件", [path],
            "核对 Web 服务器是否可直接下载该文件；先限制访问并保留业务所需备份。扫描只识别文件名，不读取备份内容。",
        ))
    hashes: Dict[str, str] = {}
    total_bytes = 0
    files_checked = 0
    for path in sorted(paths):
        if files_checked >= MAX_INDICATOR_CONFIG_FILES:
            complete = False
            break
        try:
            size = os.path.getsize(path)
            if size > MAX_INDICATOR_CONFIG_FILE_BYTES:
                complete = False
                continue
            if total_bytes + size > MAX_INDICATOR_CONFIG_BYTES:
                complete = False
                break
            with open(path, "rb") as handle:
                data = handle.read(MAX_INDICATOR_CONFIG_FILE_BYTES + 1)
            if len(data) > MAX_INDICATOR_CONFIG_FILE_BYTES:
                complete = False
                continue
        except OSError:
            complete = False
            continue
        files_checked += 1
        total_bytes += len(data)
        hashes[path] = hashlib.sha256(data).hexdigest()
        name = os.path.basename(path).lower()
        normalized = path.replace("\\", "/").lower()
        if name == "wp-config.php":
            try:
                text = data.decode("utf-8", "replace")
            except Exception:
                text = ""
            match = re.search(r"define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)", text, re.I)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                findings.append(_indicator(
                    "wordpress-debug:" + hashlib.sha256(path.encode()).hexdigest()[:20], "warning",
                    "WordPress 配置", "wp-config.php 启用了 WP_DEBUG", [f"{path}:{line}"],
                    "若这是生产站点，核对是否会向访客暴露错误或敏感路径；不要把配置值加入告警。",
                ))
        for rule_id, severity, title, pattern in patterns:
            applies = (
                (rule_id.startswith("nginx-") and (name.endswith(".conf") or name == "nginx.conf") and normalized.startswith("/etc/nginx/"))
                or (rule_id.startswith("traefik-") and name in {"traefik.yml", "traefik.yaml", "dynamic.yml", "dynamic.yaml"})
                or (rule_id.startswith("runner-") and name == "config.toml" and "/gitlab-runner/" in normalized)
                or (rule_id.startswith("compose-") and name in {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "dockerfile"})
                or (rule_id == "ci-floating-action" and (name == ".gitlab-ci.yml" or "/.github/workflows/" in normalized))
                or (rule_id.startswith("sshd-") and (name == "sshd_config" or normalized.startswith("/etc/ssh/sshd_config.d/")))
                or (rule_id == "tls-verification-disabled" and name in {"config.php", "settings.py", "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "traefik.yml", "traefik.yaml", "dynamic.yml", "dynamic.yaml"})
            )
            if not applies:
                continue
            text = data.decode("utf-8", "replace")
            for line_no, line in enumerate(text.splitlines(), start=1):
                if line.lstrip().startswith(("#", "//")):
                    continue
                if pattern.search(line):
                    findings.append(_indicator(
                        rule_id + ":" + hashlib.sha256((path + ":" + str(line_no)).encode()).hexdigest()[:18],
                        severity, "只读配置风险复核", title, [f"{path}:{line_no}"],
                        "这是静态文本命中，不证明配置已生效或可从公网利用；请在对应服务的有效配置与访问控制中复核。",
                        NGINX_SECURITY_REFERENCE if rule_id.startswith("nginx-") else "",
                    ))
    if len(findings) > MAX_INDICATOR_FINDINGS:
        complete = False
    return findings[:MAX_INDICATOR_FINDINGS], hashes, complete, files_checked


def _scan_ssh_security_indicators(now: int) -> Dict[str, Any]:
    """Run only static sshd configuration checks inside child containers."""
    errors = []
    try:
        findings, _config_hashes, complete, files_checked = _scan_static_security_configs(ssh_only=True)
    except Exception as exc:
        findings, complete, files_checked = [], False, 0
        errors.append("SSH 配置检查失败：" + str(exc)[:120])
    critical_count = sum(1 for item in findings if item.get("severity") == "critical")
    return {
        "status": "complete" if complete else "partial",
        "coverage": "complete" if complete else "partial",
        "checked_at": now,
        "last_attempt_at": now,
        "finding_count": len(findings),
        "critical_count": critical_count,
        "config_files_checked": files_checked,
        "python_site_roots": 0,
        "python_packages_checked": 0,
        "ca_certificates_checked": 0,
        "runtime_inventory": {"engines": [], "images_checked": 0, "status": "not_applicable"},
        "findings": findings,
        "config_changes": [],
        "error": "；".join(errors),
    }


def _scan_default_ca_store() -> Tuple[List[Dict[str, Any]], int, bool]:
    """Look only for the named root in this Python/OpenSSL trust view."""
    try:
        certificates = ssl.create_default_context().get_ca_certs()
    except Exception:
        return [], 0, False
    checked = len(certificates)
    findings = []
    target = "emSign ECC Root CA - G3".casefold()
    for certificate in certificates:
        subject = certificate.get("subject") if isinstance(certificate, dict) else None
        common_names = [
            str(value).strip()
            for group in (subject or []) if isinstance(group, tuple)
            for field in group if isinstance(field, tuple) and len(field) == 2
            for key, value in [field] if str(key).lower() == "commonname"
        ]
        if any(value.casefold() == target for value in common_names):
            findings.append(_indicator(
                "emudhra-system-root-emsign-ecc-g3", "warning", "emSign CA 信任链复核",
                "Agent 默认 CA 信任库包含 emSign ECC Root CA - G3",
                ["当前 Agent/OpenSSL 默认 CA 视图 · 根证书自身并非本次被盗私钥的中间 CA"],
                "核对系统/客户端更新策略和业务证书链。根证书存在只表示潜在信任路径，不证明具体连接接受了受影响中间证书；该检查不覆盖 Java、浏览器或应用自带信任库。",
                EMUDHRA_ROOT_REFERENCE,
            ))
            break
    return findings, checked, True


def _scan_local_container_images() -> Tuple[List[Dict[str, Any]], Dict[str, Any], bool]:
    findings: List[Dict[str, Any]] = []
    runtime_stats: Dict[str, Any] = {"engines": [], "images_checked": 0, "status": "not_installed"}
    installed = []
    checked_any = False
    complete = True
    for engine in ("docker", "podman"):
        binary = shutil_which(engine)
        if not binary:
            continue
        installed.append(engine)
        runtime_stats["engines"].append(engine)
        code, output = _run(
            (binary, "image", "ls", "--no-trunc", "--digests", "--format", "{{.Repository}}\t{{.Tag}}\t{{.Digest}}"),
            timeout=8, max_output=1024 * 1024,
        )
        if code != 0:
            complete = False
            continue
        checked_any = True
        lines = output.splitlines()
        if len(lines) >= MAX_RUNTIME_IMAGE_LINES:
            complete = False
        for line in lines[:MAX_RUNTIME_IMAGE_LINES]:
            fields = line.split("\t", 2)
            if len(fields) != 3:
                continue
            repository, tag, digest = (value.strip() for value in fields)
            identity = (repository + ":" + tag).lower()
            if LITELLM_COMPROMISED_IMAGE_DIGEST in digest:
                findings.append(_indicator(
                    "litellm-image-digest:" + hashlib.sha256((engine + "|" + digest).encode()).hexdigest()[:20],
                    "critical", "LiteLLM 镜像供应链事件", "本地镜像摘要命中官方确认的受影响 LiteLLM 镜像",
                    [f"{engine}: {repository}:{tag} · {digest}"],
                    "不要启动该镜像；保全镜像与容器元数据后按官方响应通告隔离、重建并轮换可能暴露的凭证。发现本地镜像不代表容器正在运行或已执行。",
                    LITELLM_INCIDENT_REFERENCE,
                ))
            elif "litellm" in identity and tag.lower().lstrip("v") == "1.107.0":
                findings.append(_indicator(
                    "litellm-image-tag:" + hashlib.sha256((engine + "|" + repository + "|" + tag).encode()).hexdigest()[:20],
                    "warning", "LiteLLM 镜像供应链事件", "本地镜像使用受影响的 LiteLLM 1.107.0 标签",
                    [f"{engine}: {repository}:{tag} · 标签不能替代摘要校验"],
                    "不要启动该镜像；本地标签不等于摘要确证，保留证据并与官方受影响摘要/构建时间核对。",
                    LITELLM_INCIDENT_REFERENCE,
                ))
            elif "litellm" in identity and tag.lower() in {"latest", "main-latest", "main-stable"}:
                findings.append(_indicator(
                    "litellm-floating-image:" + hashlib.sha256((engine + "|" + repository + "|" + tag).encode()).hexdigest()[:20],
                    "warning", "LiteLLM 镜像供应链事件", "本地存在 LiteLLM 浮动标签镜像，需要核对摘要",
                    [f"{engine}: {repository}:{tag} · {digest or '无 RepoDigest'}"],
                    "浮动标签不能证明镜像落在受影响构建中；请对照官方 incident digest 与部署/拉取时间。",
                    LITELLM_INCIDENT_REFERENCE,
                ))
        runtime_stats["images_checked"] += min(len(lines), MAX_RUNTIME_IMAGE_LINES)
    if checked_any:
        runtime_stats["status"] = "available" if complete else "partial"
    elif installed:
        runtime_stats["status"] = "unavailable"
    return findings, runtime_stats, complete


def _scan_security_indicators(now: int) -> Dict[str, Any]:
    """Scan selected supply-chain IOCs and risky static settings without execution."""
    global _STATE
    pending = _STATE.get("_pending_security_indicator_scan")
    if isinstance(pending, dict):
        return pending
    previous = _STATE.get("security_indicator_scan")
    previous = previous if isinstance(previous, dict) else {}
    last_attempt = _safe_int(_STATE.get("security_indicator_last_attempt_at"))
    due_after = RETRY_INTERVAL if previous.get("coverage") in {"partial", "unavailable"} else INDICATOR_SCAN_INTERVAL
    if last_attempt and now - last_attempt < due_after:
        return previous

    _STATE["security_indicator_last_attempt_at"] = now
    _save_state()
    findings: List[Dict[str, Any]] = []
    errors = []
    try:
        python_packages, python_complete, python_roots, startup_indicators = _python_package_inventory()
        findings.extend(_python_indicator_findings(python_packages, startup_indicators))
    except Exception as exc:
        python_packages, python_complete, python_roots = [], False, []
        errors.append("Python 元数据扫描失败：" + str(exc)[:120])
    try:
        config_findings, config_hashes, config_complete, config_files = _scan_static_security_configs()
        findings.extend(config_findings)
    except Exception as exc:
        config_findings, config_hashes, config_complete, config_files = [], {}, False, 0
        errors.append("静态配置扫描失败：" + str(exc)[:120])
    try:
        ca_findings, ca_certificates_checked, ca_complete = _scan_default_ca_store()
        findings.extend(ca_findings)
    except Exception as exc:
        ca_certificates_checked, ca_complete = 0, False
        errors.append("默认 CA 信任库检查失败：" + str(exc)[:120])
    if not ca_complete:
        errors.append("无法读取 Agent 的默认 CA 信任库。")
    try:
        image_findings, runtime_stats, runtime_complete = _scan_local_container_images()
        findings.extend(image_findings)
    except Exception as exc:
        runtime_stats, runtime_complete = {"engines": [], "images_checked": 0, "status": "unavailable"}, False
        errors.append("本地镜像元数据读取失败：" + str(exc)[:120])

    unique_indicator_groups = {
        (str(item.get("rule") or item.get("id") or ""), str(item.get("title") or ""))
        for item in findings if isinstance(item, dict)
    }
    indicator_overflow = len(unique_indicator_groups) > MAX_INDICATOR_FINDINGS
    complete = python_complete and config_complete and ca_complete and runtime_complete and not indicator_overflow
    if indicator_overflow:
        errors.append("待复核指标超过保留上限，已优先保留高严重度项目。")
    deduplicated = {}
    for finding in findings:
        if isinstance(finding, dict) and finding.get("id"):
            deduplicated[str(finding["id"])] = finding
    findings = _collapse_security_indicators(list(deduplicated.values()))
    old_findings = previous.get("findings") if isinstance(previous.get("findings"), list) else []
    if not complete:
        old_by_key = {
            (str(item.get("rule") or ""), str(item.get("title") or "")): item
            for item in old_findings if isinstance(item, dict)
        }
        current_by_key = {
            (str(item.get("rule") or ""), str(item.get("title") or "")): item
            for item in findings
        }
        for key, old_item in old_by_key.items():
            current_item = current_by_key.get(key)
            if current_item is None:
                current_by_key[key] = old_item
                continue
            current_item["finding_ids"] = list(dict.fromkeys(
                (current_item.get("finding_ids") or []) + (old_item.get("finding_ids") or [])
            ))[:200]
            current_item["evidence"] = list(dict.fromkeys(
                (current_item.get("evidence") or []) + (old_item.get("evidence") or [])
            ))[:5]
            current_item["instance_count"] = max(
                _safe_int(current_item.get("instance_count")), _safe_int(old_item.get("instance_count"))
            )
        findings = list(current_by_key.values())
        findings.sort(key=lambda item: (item.get("severity") != "critical", item.get("severity") != "warning", item.get("id", "")))

    old_hashes = previous.get("config_hashes") if isinstance(previous.get("config_hashes"), dict) else {}
    config_changes = []
    if previous.get("coverage") == "complete" and config_complete:
        changed = sorted(path for path in set(old_hashes) | set(config_hashes) if old_hashes.get(path) != config_hashes.get(path))
        if changed:
            config_changes.append({
                "type": "host_integrity_change",
                "alert_key": "security-config-snapshot",
                "severity": "warning",
                "title": "主机安全配置文件新增、移除或内容变化",
                "message": "只读配置快照发现变化：" + ", ".join(changed[:12]) + "。仅上传文件路径与哈希，不包含配置内容；变化不等于已确认入侵。",
            })

    if not complete:
        errors.append("扫描范围受权限、目录/文件上限或本地容器运行时访问限制；保留了上次告警，结果可能不完整。")
    result = {
        "status": "complete" if complete else "partial" if findings or python_roots or config_files else "unavailable",
        "coverage": "complete" if complete else "partial" if python_roots or config_files or runtime_stats.get("engines") else "unavailable",
        "last_attempt_at": now,
        "checked_at": now if complete else _safe_int(previous.get("checked_at")),
        "finding_count": len(findings),
        "critical_count": sum(1 for item in findings if item.get("severity") == "critical"),
        "findings": findings[:MAX_INDICATOR_FINDINGS],
        "python_site_roots": len(python_roots),
        "python_packages_checked": len(python_packages),
        "config_files_checked": config_files,
        "ca_certificates_checked": ca_certificates_checked,
        "runtime_inventory": runtime_stats,
        "config_hashes": config_hashes if config_complete else old_hashes,
        "config_changes": config_changes,
        "error": " ".join(errors)[:400],
    }
    _STATE["_pending_security_indicator_scan"] = result
    _save_state()
    return result


def _journal_entries(cursor: str, since_ts: int = 0) -> Tuple[List[Dict[str, Any]], str, str]:
    command = ["journalctl", "--no-pager", "-o", "json", "-n", "2000"]
    if cursor:
        command.append("--after-cursor=" + cursor[:4096])
    elif since_ts > 0:
        command.extend(("--since=@" + str(max(0, int(since_ts))),))
    else:
        command.extend(("--since=24 hours ago",))
    code, output = _run(command, timeout=12, max_output=4_000_000)
    if code != 0:
        return [], cursor, "unavailable"
    entries = []
    next_cursor = cursor
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        entry_cursor = str(item.get("__CURSOR") or "")[:4096]
        if entry_cursor:
            next_cursor = entry_cursor
        message = item.get("MESSAGE")
        if isinstance(message, list):
            message = "".join(chr(value) for value in message if isinstance(value, int) and 0 <= value <= 255)
        message = str(message or "")
        match = re.search(
            r"\bAccepted\s+([A-Za-z0-9_./+-]+)\s+for\s+(\S+)\s+from\s+([0-9A-Fa-f:.]+)\s+port\s+\d+",
            message,
        )
        if not match:
            continue
        try:
            timestamp = int(item.get("__REALTIME_TIMESTAMP") or 0) // 1_000_000
        except (TypeError, ValueError):
            timestamp = 0
        entries.append({
            "cursor": entry_cursor,
            "timestamp": timestamp,
            "method": match.group(1)[:32],
            "user": match.group(2)[:64],
            "ip": match.group(3)[:64],
        })
    if len(output) >= 4_000_000:
        return entries[-100:], next_cursor, "partial"
    return entries[-100:], next_cursor, "available"


def _auth_log_entries(
    previous: Optional[Dict[str, Any]], now: int
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]], str, bool]:
    path = next((
        item for item in ("/var/log/auth.log", "/var/log/secure", "/var/log/messages")
        if os.path.isfile(item) and not os.path.islink(item)
    ), "")
    if not path:
        return [], None, "unavailable", False
    try:
        stat = os.stat(path, follow_symlinks=False)
        old_path = str((previous or {}).get("path") or "")
        old_inode = int((previous or {}).get("inode") or 0)
        old_offset = int((previous or {}).get("offset") or 0)
        same_file = old_path == path and old_inode == int(stat.st_ino) and 0 <= old_offset <= stat.st_size
        reset = not same_file
        start = old_offset if same_file else max(0, stat.st_size - 128 * 1024)
        with open(path, "rb") as handle:
            handle.seek(start)
            raw = handle.read(MAX_AUTH_LOG_BYTES + 1)
    except (OSError, TypeError, ValueError):
        return [], previous, "unavailable", False
    overflow = len(raw) > MAX_AUTH_LOG_BYTES
    raw = raw[:MAX_AUTH_LOG_BYTES]
    entries = []
    line_offset = start
    for raw_line in raw.splitlines(keepends=True):
        offset = line_offset
        line_offset += len(raw_line)
        line = raw_line.decode("utf-8", "replace")
        match = re.search(
            r"\bAccepted\s+([A-Za-z0-9_./+-]+)\s+for\s+(\S+)\s+from\s+([0-9A-Fa-f:.]+)\s+port\s+\d+",
            line,
        )
        if not match:
            continue
        cursor = hashlib.sha256(
            f"{path}:{stat.st_ino}:{offset}:{line}".encode("utf-8", "replace")
        ).hexdigest()
        entries.append({
            "cursor": cursor,
            "timestamp": now,
            "method": match.group(1)[:32],
            "user": match.group(2)[:64],
            "ip": match.group(3)[:64],
        })
    state = {"path": path, "inode": int(stat.st_ino), "offset": start + len(raw)}
    status = "partial" if reset or overflow else "available"
    return entries[-100:], state, status, reset


def _snapshot_alerts(previous: Dict[str, Any], current: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    changes = []
    ssh_only = current.get("scope") == "agent_container"
    old_accounts = {item.get("name"): item for item in previous.get("user_accounts", []) if isinstance(item, dict)}
    new_accounts = {item.get("name"): item for item in current.get("user_accounts", []) if isinstance(item, dict)}
    added_accounts = sorted(str(name) for name in new_accounts.keys() - old_accounts.keys() if name)
    removed_accounts = sorted(str(name) for name in old_accounts.keys() - new_accounts.keys() if name)
    changed_accounts = sorted(
        str(name) for name in old_accounts.keys() & new_accounts.keys()
        if any(old_accounts[name].get(field) != new_accounts[name].get(field) for field in ("uid", "shell"))
    )
    if added_accounts or removed_accounts or changed_accounts:
        parts = []
        if added_accounts:
            parts.append("新增可登录账户：" + ", ".join(added_accounts[:20]))
        if removed_accounts:
            parts.append("移除可登录账户：" + ", ".join(removed_accounts[:20]))
        if changed_accounts:
            parts.append("修改可登录账户属性：" + ", ".join(changed_accounts[:20]))
        changes.append(("user_accounts", "SSH 可登录账户发生变化" if ssh_only else "主机用户账户发生变化", "；".join(parts)))

    def key_set(snapshot: Dict[str, Any]) -> set:
        return {
            (str(item.get("user") or ""), str(item.get("fingerprint") or ""))
            for item in snapshot.get("authorized_keys", []) if isinstance(item, dict)
        }
    old_keys, new_keys = key_set(previous), key_set(current)
    added_keys = sorted(new_keys - old_keys)
    removed_keys = sorted(old_keys - new_keys)
    if added_keys or removed_keys:
        lines = []
        lines.extend("新增 " + user + " " + fingerprint for user, fingerprint in added_keys[:10])
        lines.extend("移除 " + user + " " + fingerprint for user, fingerprint in removed_keys[:10])
        changes.append(("authorized_keys", "SSH 登录公钥发生变化", "；".join(lines)))

    old_files = previous.get("critical_files") if isinstance(previous.get("critical_files"), dict) else {}
    new_files = current.get("critical_files") if isinstance(current.get("critical_files"), dict) else {}
    changed_files = sorted(path for path in set(old_files) | set(new_files) if old_files.get(path) != new_files.get(path))
    if changed_files:
        title = "SSH / PAM 认证配置发生变化" if ssh_only else "SSH、sudo、计划任务或系统服务配置发生变化"
        changes.append(("critical_config", title, "变化文件：" + ", ".join(changed_files[:20])))
    if not ssh_only:
        old_os = previous.get("os") if isinstance(previous.get("os"), dict) else {}
        new_os = current.get("os") if isinstance(current.get("os"), dict) else {}
        if old_os != new_os:
            changes.append((
                "os_release", "操作系统版本发生变化",
                "系统版本由 " + str(old_os.get("id") or "未知") + " " + str(old_os.get("version_id") or "")
                + " 更新为 " + str(new_os.get("id") or "未知") + " " + str(new_os.get("version_id") or ""),
            ))
        if previous.get("kernel") and current.get("kernel") and previous.get("kernel") != current.get("kernel"):
            changes.append(("kernel_release", "内核版本发生变化", "内核由 " + str(previous.get("kernel")) + " 更新为 " + str(current.get("kernel"))))

    for key, title, message in changes:
        alerts.append({
            "type": "host_integrity_change",
            "alert_key": "snapshot:" + key,
            "severity": "info" if key in {"os_release", "kernel_release"} else "warning",
            "title": title,
            "message": message + "；这是待复核的主机变化，不代表已确认入侵。",
        })
    return alerts


def _country_label(country: str) -> str:
    names = {
        "AU": "澳大利亚", "BR": "巴西", "CA": "加拿大", "CN": "中国",
        "DE": "德国", "FR": "法国", "GB": "英国", "HK": "香港",
        "ID": "印度尼西亚", "IN": "印度", "JP": "日本", "KR": "韩国",
        "MO": "澳门", "NL": "荷兰", "RU": "俄罗斯", "SG": "新加坡",
        "TH": "泰国", "TW": "台湾", "US": "美国", "VN": "越南",
    }
    normalized = str(country or "").upper()
    label = names.get(normalized)
    return f"{label} ({normalized})" if label else normalized


def prepare_report(country_lookup=None, now: Optional[int] = None) -> Dict[str, Any]:
    """Collect bounded host telemetry; state changes commit only after report ACK."""
    global _STATE, _STATE_PATH
    if not _STATE_PATH:
        _STATE_PATH = _state_path()
    if not _STATE:
        _STATE = _load_state()
    captured_at = int(time.time() if now is None else now)
    audit_scope = _audit_scope()
    ssh_only = audit_scope == "agent_container"
    current = collect_snapshot(captured_at, ssh_only=ssh_only)
    previous = _STATE.get("snapshot")
    previous = previous if isinstance(previous, dict) else {}
    same_scope_baseline = bool(previous and previous.get("scope") == audit_scope)
    snapshot_alerts = []
    first_baseline = not same_scope_baseline and current.get("status") == "ready"
    if same_scope_baseline and previous.get("status") == "ready" and current.get("status") == "ready":
        snapshot_alerts = _snapshot_alerts(previous, current)

    current_cursor = str(_STATE.get("ssh_cursor") or "")[:4096]
    ssh_initialized = bool(_STATE.get("ssh_initialized"))
    ssh_checked_at = _safe_int(_STATE.get("ssh_checked_at"))
    events, next_cursor, journal_status = _journal_entries(
        current_cursor, ssh_checked_at if ssh_initialized and not current_cursor else 0
    )
    baseline_events = events if not ssh_initialized else []
    fallback_cursor = None
    if journal_status == "unavailable":
        fallback_events, fallback_cursor, fallback_status, fallback_reset = _auth_log_entries(
            _STATE.get("ssh_file_cursor") if isinstance(_STATE.get("ssh_file_cursor"), dict) else None,
            captured_at,
        )
        if fallback_status != "unavailable":
            journal_status = fallback_status
            events = fallback_events
            if fallback_reset:
                baseline_events = fallback_events
                events = []
    login_state = _STATE.get("seen_ssh_logins")
    login_state = login_state if isinstance(login_state, dict) else {}
    seen_ip_order = list(dict.fromkeys(str(item) for item in login_state.get("ips", []) if isinstance(item, str)))
    seen_user_order = list(dict.fromkeys(str(item) for item in login_state.get("users", []) if isinstance(item, str)))
    seen_country_order = list(dict.fromkeys(str(item) for item in login_state.get("countries", []) if isinstance(item, str)))
    seen_ips, seen_users, seen_countries = set(seen_ip_order), set(seen_user_order), set(seen_country_order)

    def remember(seen: set, order: List[str], value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            order.append(value)

    if not ssh_initialized:
        # On first install, advance silently past the pre-existing journal.
        events = []
    public_events = [item for item in events if _public_address(item["ip"])]
    public_baseline_events = [item for item in baseline_events if _public_address(item["ip"])]
    countries = {}
    country_ips = sorted({item["ip"] for item in public_events + public_baseline_events})
    if country_lookup and country_ips:
        try:
            countries = country_lookup(country_ips)
        except Exception:
            countries = {}
    login_alerts = []
    if public_baseline_events:
        for event in public_baseline_events:
            remember(seen_ips, seen_ip_order, event["ip"])
            remember(seen_users, seen_user_order, event["user"])
            country = str(countries.get(event["ip"]) or "").upper()[:2]
            if country:
                remember(seen_countries, seen_country_order, country)
    for event in public_events:
        country = str(countries.get(event["ip"]) or "").upper()[:2]
        is_new_ip = event["ip"] not in seen_ips
        is_new_user = event["user"] not in seen_users
        is_new_country = bool(country and country not in seen_countries)
        if is_new_ip or is_new_user or is_new_country:
            reasons = []
            if is_new_ip:
                reasons.append("首次出现的公网来源 IP")
            if is_new_user:
                reasons.append("首次出现的 SSH 登录账户")
            if is_new_country:
                reasons.append("首次出现的登录国家/地区")
            location = _country_label(country) if country else "归属地未识别"
            login_alerts.append({
                "type": "host_ssh_login",
                "alert_key": "ssh-login:" + hashlib.sha256(event["cursor"].encode()).hexdigest()[:24],
                "severity": "warning",
                "title": "检测到新的公网 SSH 登录来源",
                "message": f"账户 {event['user']} 通过 {event['method']} 从 {event['ip']}（{location}）登录；触发条件：{'、'.join(reasons)}。请核对登录人和来源。",
            })
        remember(seen_ips, seen_ip_order, event["ip"])
        remember(seen_users, seen_user_order, event["user"])
        if country:
            remember(seen_countries, seen_country_order, country)
    login_alerts = login_alerts[:20]

    not_applicable_scan = {
        "status": "not_applicable", "coverage": "not_applicable", "checked_at": None,
        "last_attempt_at": None, "finding_count": 0, "critical_count": 0,
        "note": "容器 Agent 仅检查 SSH 安全，不执行主机软件漏洞扫描。",
    }
    vulnerability_scan = not_applicable_scan if ssh_only else _scan_vulnerabilities(captured_at)
    vuln_findings = vulnerability_scan.get("findings") if isinstance(vulnerability_scan.get("findings"), list) else []
    vulnerability_alerts = []
    if vuln_findings:
        scope_label = "Agent 运行环境" if _audit_scope() == "agent_container" else "宿主机"
        ids = sorted(set(str(item.get("cve") or item.get("id") or "") for item in vuln_findings if isinstance(item, dict)))
        finding_keys = sorted(set(
            "|".join(str(item.get(key) or "") for key in ("id", "ecosystem", "package", "version"))
            for item in vuln_findings if isinstance(item, dict)
        ))
        critical_count = int(vulnerability_scan.get("critical_count") or 0)
        sample = ", ".join(item for item in ids[:12] if item)
        coverage_text = "扫描覆盖完整" if vulnerability_scan.get("coverage") == "complete" else "扫描覆盖不完整，结果可能有遗漏"
        vulnerability_alerts.append({
            "type": "host_vulnerability",
            "alert_key": "osv-host-findings",
            "severity": "critical" if critical_count else "warning",
            "title": scope_label + "软件发现公开漏洞匹配",
            "message": f"{scope_label}发现 {len(vuln_findings)} 条 OSV 公告匹配（严重 {critical_count} 条）；公告：{sample or '详见证据'}。{coverage_text}。匹配项可能来自依赖锁文件、未必已安装或运行；版本匹配不等于已被利用，发行版可能包含回移补丁，请复核公告与软件包状态。",
            "value": len(vuln_findings),
            "threshold": 0,
            "finding_ids": ids[:200],
            "finding_keys": finding_keys[:200],
            "findings": vuln_findings[:40],
        })

    security_indicator_scan = _scan_ssh_security_indicators(captured_at) if ssh_only else _scan_security_indicators(captured_at)
    raw_indicators = security_indicator_scan.get("findings") if isinstance(security_indicator_scan.get("findings"), list) else []
    security_indicator_alerts = []
    for finding in raw_indicators[:MAX_INDICATOR_FINDINGS]:
        if not isinstance(finding, dict):
            continue
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
        detail = "；".join(str(item)[:500] for item in evidence[:3])
        message = f"{finding.get('component') or '主机安全检查'}：{finding.get('title') or '发现待复核项'}。"
        if detail:
            message += "证据位置：" + detail + "。"
        if finding.get("guidance"):
            message += str(finding["guidance"])
        alert_key = "indicator:" + str(finding.get("rule") or finding.get("id") or "unknown") + ":" + hashlib.sha256(str(finding.get("title") or "").encode()).hexdigest()[:16]
        security_indicator_alerts.append({
            "type": "host_security_finding",
            "alert_key": alert_key[:240],
            "severity": finding.get("severity") if finding.get("severity") in {"critical", "warning", "info"} else "warning",
            "title": str(finding.get("title") or "主机安全检查发现待复核项")[:200],
            "message": message[:2000],
            "value": _safe_int(finding.get("instance_count"), 1),
            "threshold": 0,
            "finding_ids": [str(item)[:240] for item in finding.get("finding_ids", [])[:200] if isinstance(item, str)],
            "component": str(finding.get("component") or "")[:120],
            "reference": str(finding.get("reference") or "")[:500],
            "evidence": evidence[:5],
        })

    config_change_alerts = [
        item for item in security_indicator_scan.get("config_changes", [])
        if isinstance(item, dict)
    ]

    host_audit = {
        "enabled": True,
        "scope": audit_scope,
        "snapshot_status": current.get("status", "partial"),
        "snapshot_at": current.get("captured_at", captured_at),
        "baseline_at": _safe_int(previous.get("captured_at")) if same_scope_baseline else 0,
        "baseline_pending": bool(first_baseline),
        "snapshot_files": len(current.get("critical_files") or {}),
        "user_accounts": len(current.get("user_accounts") or []),
        "ssh_key_count": len(current.get("authorized_keys") or []),
        "ssh_log_status": journal_status,
        "ssh_events_last_period": len(events),
        "new_ssh_login_events": len(login_alerts),
        "country_lookup": "local_mmdb" if countries else "unavailable",
        "vulnerability_scan": {
            key: vulnerability_scan.get(key)
            for key in ("status", "coverage", "checked_at", "last_attempt_at", "packages_checked", "finding_count", "critical_count", "error")
        },
        "security_indicator_scan": {
            key: security_indicator_scan.get(key)
            for key in ("status", "coverage", "checked_at", "last_attempt_at", "finding_count", "critical_count",
                        "python_site_roots", "python_packages_checked", "config_files_checked", "ca_certificates_checked",
                        "runtime_inventory", "error")
        },
        "recent_events": (snapshot_alerts + config_change_alerts + login_alerts + security_indicator_alerts)[:40],
        "recent_findings": vuln_findings[:20],
        "recent_indicators": raw_indicators[:40],
    }
    _STATE["_pending_report"] = {
        "snapshot": current if current.get("status") == "ready" else None,
        "security_indicator_scan": (
            security_indicator_scan
            if not ssh_only and isinstance(_STATE.get("_pending_security_indicator_scan"), dict)
            else None
        ),
        "ssh_cursor": next_cursor,
        "ssh_file_cursor": fallback_cursor,
        "ssh_initialized": True,
        "ssh_checked_at": captured_at,
        "seen_ssh_logins": {
            "ips": seen_ip_order[-5000:],
            "users": seen_user_order[-1000:],
            "countries": seen_country_order[-256:],
        },
    }
    _save_state()
    return {
        "host_audit": host_audit,
        "alerts": snapshot_alerts + config_change_alerts + login_alerts + vulnerability_alerts + security_indicator_alerts,
        "pending_ssh_cursor": next_cursor,
    }


def commit_report() -> None:
    """Acknowledge the latest report before committing baselines and cursors."""
    global _STATE
    pending = _STATE.get("_pending_report") if isinstance(_STATE, dict) else None
    if not isinstance(pending, dict):
        return
    snapshot = pending.get("snapshot")
    if isinstance(snapshot, dict):
        _STATE["snapshot"] = snapshot
    indicator_scan = pending.get("security_indicator_scan")
    if isinstance(indicator_scan, dict):
        committed_scan = dict(indicator_scan)
        committed_scan.pop("config_changes", None)
        _STATE["security_indicator_scan"] = committed_scan
        _STATE.pop("_pending_security_indicator_scan", None)
    cursor = str(pending.get("ssh_cursor") or "")[:4096]
    if cursor:
        _STATE["ssh_cursor"] = cursor
    file_cursor = pending.get("ssh_file_cursor")
    if isinstance(file_cursor, dict):
        _STATE["ssh_file_cursor"] = file_cursor
    _STATE["ssh_initialized"] = bool(pending.get("ssh_initialized"))
    _STATE["ssh_checked_at"] = int(pending.get("ssh_checked_at") or time.time())
    logins = pending.get("seen_ssh_logins")
    if isinstance(logins, dict):
        _STATE["seen_ssh_logins"] = logins
    _STATE.pop("_pending_report", None)
    _save_state()
