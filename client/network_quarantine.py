"""Identity-scoped, reversible ingress AND egress quarantine.

No stopping/deleting instances, no guest firewall commands, no shared-network edits.
Write a private recovery journal before changing connectivity; failures stay visible.
"""
import copy
import http.client
import json
import os
import re
import socket
import stat
import tempfile
import threading
import time
from urllib.parse import quote


_LOCK = threading.RLock()
PROTECTED = {'narwhal-monitor-client', 'narwhal-monitor-server', 'narwhal-monitor-caddy'}
NETWORK_DEVICES = {'nic', 'proxy', 'infiniband'}


class QuarantineError(RuntimeError):
    pass


def target(runtime, project, name, instance_id):
    if runtime not in {'incus', 'podman'}:
        raise QuarantineError('unsupported runtime; no network change performed')
    if not re.fullmatch(r'[A-Za-z0-9_.:@+-]{1,200}', name or '') or name in PROTECTED:
        raise QuarantineError('invalid or protected instance')
    if project and not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', project):
        raise QuarantineError('invalid project')
    if not re.fullmatch(r'[A-Za-z0-9-]{12,100}', instance_id or ''):
        raise QuarantineError('stable instance identity required')
    return json.dumps([runtime, project or '', name, instance_id], separators=(',', ':'))


class Journal:
    def __init__(self, path=None):
        self.path = path or os.getenv('SECURITY_ABUSE_QUARANTINE_FILE', '/opt/narwhal-monitor/abuse-quarantine.json')
        if not os.path.isabs(self.path):
            raise QuarantineError('journal path must be absolute')

    def read(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        except FileNotFoundError:
            return {}
        with os.fdopen(fd, 'r', encoding='utf-8') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 8*1024*1024:
                raise QuarantineError('invalid quarantine journal')
            data = json.load(stream)
        if not isinstance(data, dict) or len(data) > 1000:
            raise QuarantineError('invalid quarantine journal schema')
        return data

    def write(self, data):
        if len(data) > 1000:
            raise QuarantineError('quarantine journal capacity exceeded')
        directory = os.path.dirname(self.path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        if os.path.lexists(self.path) and os.path.islink(self.path):
            raise QuarantineError('journal symlink rejected')
        fd, temporary = tempfile.mkstemp(prefix='.abuse-quarantine-', dir=directory)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                os.chmod(temporary, 0o600)
                json.dump(data, stream, ensure_ascii=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if os.name == 'posix':
                directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=35)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class IncusAPI:
    def __init__(self, project='', socket_path='/var/lib/incus/unix.socket'):
        self.project = project or 'default'
        self.socket_path = socket_path

    def request(self, method, path, data=None, etag=None):
        connection = _UnixHTTP(self.socket_path)
        headers = {'Content-Type': 'application/json'}
        if etag:
            headers['If-Match'] = etag
        path += ('&' if '?' in path else '?') + 'project=' + quote(self.project, safe='')
        try:
            connection.request(method, path, body=None if data is None else json.dumps(data), headers=headers)
            response = connection.getresponse()
            raw = response.read(2*1024*1024+1)
            if response.status >= 400 or len(raw) > 2*1024*1024:
                raise QuarantineError('Incus API request failed: status '+str(response.status))
            parsed = json.loads(raw)
            response_etag = response.getheader('ETag')
        except (OSError, ValueError, http.client.HTTPException):
            raise QuarantineError('Incus local API unavailable') from None
        finally:
            connection.close()
        if parsed.get('type') == 'async':
            operation = str(parsed.get('operation') or '').split('?', 1)[0]
            if not re.fullmatch(r'/1.0/operations/[a-fA-F0-9-]{36}', operation):
                raise QuarantineError('invalid Incus operation identity')
            result, _ = self.request('GET', operation+'/wait?timeout=30')
            if result.get('status_code') != 200:
                raise QuarantineError('Incus network update was not confirmed')
        return parsed.get('metadata', {}), response_etag


class IncusIsolation:
    def __init__(self, api, name, instance_id):
        self.api, self.name, self.instance_id = api, name, instance_id
        self.path = '/1.0/instances/' + quote(name, safe='')

    def inspect(self):
        item, etag = self.api.request('GET', self.path)
        identity = item.get('config', {}).get('volatile.uuid')
        if identity != self.instance_id:
            raise QuarantineError('Incus instance identity changed; refused')
        if not etag:
            raise QuarantineError('Incus conditional-update support required')
        if re.search(r'(?m)^\s*lxc\.net\.', str(item.get('config', {}).get('raw.lxc', ''))):
            raise QuarantineError('unmanaged Incus network requires manual isolation')
        return item, etag

    def snapshot(self):
        item, _ = self.inspect()
        expanded = item.get('expanded_devices', {})
        devices = {k: v for k, v in expanded.items() if v.get('type') in NETWORK_DEVICES}
        if any(v.get('type') in {'pci', 'usb', 'unix-hotplug'} for v in expanded.values()):
            raise QuarantineError('passthrough devices require manual isolation')
        if not devices:
            raise QuarantineError('no managed network devices; cannot prove isolation')
        return {'original': {k: copy.deepcopy(item.get('devices', {}).get(k)) for k in devices},
                'expanded': copy.deepcopy(devices), 'guest_names': self.guest_names(item, devices)}

    def guest_names(self, item, devices):
        """Resolve auto-named NICs before changing anything, never guess eth0."""
        result = {}
        state = None
        for key, device in devices.items():
            if device.get('type') not in {'nic', 'infiniband'}:
                continue
            name = device.get('name') or item.get('config', {}).get('volatile.'+key+'.name')
            if not name:
                if state is None:
                    state, _ = self.api.request('GET', self.path+'/state')
                mac = device.get('hwaddr') or item.get('config', {}).get('volatile.'+key+'.hwaddr')
                matches = [n for n, interface in (state.get('network') or {}).items()
                           if mac and str(interface.get('hwaddr', '')).lower() == str(mac).lower()]
                if len(matches) == 1:
                    name = matches[0]
            if not name:
                raise QuarantineError('original guest interface identity unavailable; no new device mutation')
            result[key] = str(name)
        return result

    def set_devices(self, item, etag, devices):
        # PUT + If-Match replaces the device map (PATCH can merge it and leave
        # inherited-device masks behind during release). Preserve all other fields.
        data = {k: copy.deepcopy(item[k]) for k in ('architecture', 'config', 'profiles', 'ephemeral', 'description') if k in item}
        data['devices'] = devices
        self.api.request('PUT', self.path, data, etag)

    def refresh_backup(self, backup):
        item, _ = self.inspect()
        added = {}
        for key, value in item.get('expanded_devices', {}).items():
            if value.get('type') in NETWORK_DEVICES and key not in backup['original']:
                added[key] = value
        names = self.guest_names(item, added)
        for key, value in added.items():
            backup['original'][key] = copy.deepcopy(item.get('devices', {}).get(key))
            backup['expanded'][key] = copy.deepcopy(value)
        backup.setdefault('guest_names', {}).update(names)

    def isolate(self, backup):
        item, etag = self.inspect()
        current = copy.deepcopy(item.get('devices', {}))
        expanded = item.get('expanded_devices', {})
        # The journal is refreshed before mutation to cover newly attached devices.
        network_keys = {k for k, v in expanded.items() if v.get('type') in NETWORK_DEVICES} | set(backup['original'])
        for key in network_keys:
            if key not in backup['original']:
                raise QuarantineError('network topology changed; manual review required')
            local_type = (current.get(key) or {}).get('type')
            if local_type and local_type not in NETWORK_DEVICES | {'none'}:
                raise QuarantineError('device is no longer a network device; manual review required')
            current[key] = {'type': 'none'}
        if current != item.get('devices', {}):
            self.set_devices(item, etag, current)
        self.verify(backup)

    def verify(self, backup):
        item, _ = self.inspect()
        expanded = item.get('expanded_devices', {})
        if any(v.get('type') in NETWORK_DEVICES for v in expanded.values()):
            raise QuarantineError('Incus network devices remain connected')
        if any(item.get('devices', {}).get(k) != {'type': 'none'} for k in backup['original']):
            raise QuarantineError('Incus quarantine masks not confirmed')
        state, _ = self.api.request('GET', self.path+'/state')
        interfaces = state.get('network', {}) or {}
        for key, device in backup['expanded'].items():
            if device.get('type') in {'nic', 'infiniband'}:
                name = backup.get('guest_names', {}).get(key) or device.get('name')
                if not name:
                    raise QuarantineError('original guest interface identity unavailable')
                if str(interfaces.get(name, {}).get('state', '')).lower() == 'up':
                    raise QuarantineError('original guest interface is still up')

    def release(self, backup):
        item, etag = self.inspect()
        devices = copy.deepcopy(item.get('devices', {}))
        for key, original in backup['original'].items():
            if devices.get(key) != {'type': 'none'}:
                raise QuarantineError('quarantine mask changed; refused to overwrite operator configuration')
            if original is None:
                devices.pop(key)
            else:
                devices[key] = original
        self.set_devices(item, etag, devices)
        fresh, _ = self.inspect()
        if any(fresh.get('devices', {}).get(k) != original for k, original in backup['original'].items()):
            raise QuarantineError('Incus restore readback mismatch')


class PodmanIsolation:
    def __init__(self, run, binary, name, instance_id):
        self.run, self.binary, self.name, self.instance_id = run, binary, name, instance_id

    def command(self, args):
        ok, output = self.run([self.binary, *args])
        if not ok:
            raise QuarantineError('Podman network operation failed')
        return output

    def inspect(self):
        try:
            item = json.loads(self.command(['inspect', self.name]))[0]
        except (ValueError, IndexError, TypeError):
            raise QuarantineError('invalid Podman inspection') from None
        identity = str(item.get('Id') or item.get('ID') or '')
        if not identity.startswith(self.instance_id) or len(self.instance_id) < 12:
            raise QuarantineError('Podman container identity changed; refused')
        mode = str(item.get('HostConfig', {}).get('NetworkMode') or '')
        if item.get('Pod') or mode == 'host' or mode.startswith(('container:', 'ns:', 'pasta', 'slirp4netns')):
            raise QuarantineError('shared/host/rootless network requires manual isolation')
        if item.get('HostConfig', {}).get('Privileged') or item.get('HostConfig', {}).get('Devices'):
            raise QuarantineError('privileged/device-passthrough container requires manual isolation')
        return item

    def snapshot(self):
        item = self.inspect()
        networks = item.get('NetworkSettings', {}).get('Networks')
        if not isinstance(networks, dict) or not networks:
            raise QuarantineError('no managed Podman attachments; cannot prove isolation')
        return {'networks': copy.deepcopy(networks), 'id': item.get('Id') or item.get('ID')}

    def isolate(self, backup):
        item = self.inspect()
        for network in item.get('NetworkSettings', {}).get('Networks', {}):
            self.command(['network', 'disconnect', '--force', network, backup['id']])
        self.verify(backup)

    def verify(self, backup):
        if self.inspect().get('NetworkSettings', {}).get('Networks'):
            raise QuarantineError('Podman networks remain attached')

    def release(self, backup):
        self.verify(backup)
        restored = []
        try:
            for name, network in backup['networks'].items():
                options = []
                for field, flag in (('IPAddress', '--ip'), ('GlobalIPv6Address', '--ip6'), ('MacAddress', '--mac-address')):
                    if network.get(field):
                        options.extend([flag, str(network[field])])
                for alias in (network.get('Aliases') or []):
                    if isinstance(alias, str):
                        options.extend(['--alias', alias])
                self.command(['network', 'connect', *options, name, backup['id']])
                restored.append(name)
            fresh = self.inspect().get('NetworkSettings', {}).get('Networks', {})
            if set(fresh) != set(backup['networks']):
                raise QuarantineError('Podman restore readback mismatch')
            for name, previous in backup['networks'].items():
                for field in ('IPAddress', 'GlobalIPv6Address', 'MacAddress'):
                    if previous.get(field) and str(fresh[name].get(field, '')).lower() != str(previous[field]).lower():
                        raise QuarantineError('Podman restored address readback mismatch')
                if not set(previous.get('Aliases') or []).issubset(set(fresh[name].get('Aliases') or [])):
                    raise QuarantineError('Podman restored aliases readback mismatch')
        except QuarantineError:
            # Never leave a partially released instance reporting as quarantined.
            for name in restored:
                try:
                    self.command(['network', 'disconnect', '--force', name, backup['id']])
                except QuarantineError:
                    pass
            raise


def quarantine(journal, key, driver, evidence):
    with _LOCK:
        entries = journal.read()
        entry = entries.get(key)
        if entry is None:
            if len(entries) >= 1000:
                raise QuarantineError('quarantine journal full')
            entry = {'status': 'applying', 'created_at': int(time.time()),
                     'backup': driver.snapshot(), 'evidence': safe_evidence(evidence)}
            entries[key] = entry
            journal.write(entries)  # Durable recovery BEFORE connectivity changes.
        try:
            if hasattr(driver, 'refresh_backup'):
                driver.refresh_backup(entry['backup'])
                journal.write(entries)
            driver.isolate(entry['backup'])
            entry.update(status='isolated', verified_at=int(time.time()), last_error='')
        except QuarantineError as exc:
            entry.update(status='failed', last_error=str(exc))
            journal.write(entries)
            raise
        journal.write(entries)
        return {'status': 'isolated', 'ingress_blocked': True, 'egress_blocked': True,
                'verified_at': entry['verified_at'], 'data_preserved': True}


def release(journal, key, driver):
    with _LOCK:
        entries = journal.read()
        entry = entries.get(key)
        if not entry:
            raise QuarantineError('no quarantine recovery record')
        try:
            driver.release(entry['backup'])
        except QuarantineError as exc:
            entry.update(status='release_failed', last_error=str(exc))
            try:
                driver.isolate(entry['backup'])
            except QuarantineError:
                entry['status'] = 'failed'
            journal.write(entries)
            raise
        entries.pop(key)
        journal.write(entries)
        return {'status': 'released', 'data_preserved': True}


def safe_evidence(evidence):
    """Whitelist only typed feature metadata; never persist argv, code or records."""
    if not isinstance(evidence, list):
        raise QuarantineError('typed abuse evidence required')
    result = []
    strings = {'kind', 'confidence', 'basis', 'tool', 'start_ticks', 'source_sha256'}
    numbers = {'pid', 'public_target_count', 'owned_http_connections', 'pending_attempts',
               'vertical_ports', 'horizontal_targets', 'failed_ratio'}
    for item in evidence[:20]:
        if not isinstance(item, dict):
            continue
        clean = {k: str(v)[:100] for k, v in item.items() if k in strings and isinstance(v, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', v)}
        clean.update({k: v for k, v in item.items() if k in numbers and isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 1000000000})
        features = item.get('features', {})
        if isinstance(features, dict):
            clean['features'] = {k: v for k, v in features.items() if k in {'http_calls', 'enumeration', 'dictionary_inputs', 'identity_generator', 'concurrency', 'corroborating_samples'} and isinstance(v, (bool, int))}
        if clean.get('kind'):
            result.append(clean)
    if not result:
        raise QuarantineError('no safe abuse evidence')
    return result

