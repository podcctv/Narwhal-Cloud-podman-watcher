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
PODMAN_INSPECT_FORMAT = ('[{"Id":{{json .ID}},"Pod":{{json .Pod}},"HostConfig":{'
    '"NetworkMode":{{json .HostConfig.NetworkMode}},"PidMode":{{json .HostConfig.PidMode}},'
    '"Privileged":{{json .HostConfig.Privileged}},"Devices":{{if .HostConfig.Devices}}[{}]{{else}}[]{{end}}},'
    '"NetworkSettings":{"Networks":{{json .NetworkSettings.Networks}}},"State":{"Pid":{{json .State.Pid}}}}]')


def podman_inspect_args(name):
    # Keep restore/identity fields, not arbitrary environment/labels. The Agent's
    # action transport is bounded; full inspect JSON can exceed its 8 KiB limit.
    return ['inspect', '--format', PODMAN_INSPECT_FORMAT, name]


class QuarantineError(RuntimeError):
    pass


def target(runtime, project, name, instance_id):
    if runtime not in {'incus', 'podman', 'runman'}:
        raise QuarantineError('unsupported runtime; no network change performed')
    if not re.fullmatch(r'[A-Za-z0-9_.:@+-]{1,200}', name or '') or name in PROTECTED:
        raise QuarantineError('invalid or protected instance')
    if project and not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', project):
        raise QuarantineError('invalid project')
    if runtime == 'runman':
        vm_id = re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}', name or '')
        generation = re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', instance_id or '')
        if project != 'default' or not vm_id or not generation:
            raise QuarantineError('Runman requires a canonical VM UUID and current UUID generation')
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
        effective = item.get('expanded_config') or item.get('config', {})
        if re.search(r'(?m)^\s*lxc\.(?:net|network)\.', str(effective.get('raw.lxc', ''))):
            raise QuarantineError('unmanaged Incus network requires manual isolation')
        if any(value.get('type') in {'pci', 'usb', 'unix-hotplug'} for value in item.get('expanded_devices', {}).values()):
            raise QuarantineError('passthrough devices require manual isolation')
        return item, etag

    def prove_replaced(self):
        """Prove the named instance is new and the quarantined UUID is gone."""
        current, _ = self.api.request('GET', self.path)
        current_id = str(current.get('config', {}).get('volatile.uuid') or '')
        if not re.fullmatch(r'[A-Za-z0-9-]{12,100}', current_id) or current_id == self.instance_id:
            raise QuarantineError('Incus replacement identity could not be verified')
        instances, _ = self.api.request('GET', '/1.0/instances?recursion=2')
        if not isinstance(instances, list):
            raise QuarantineError('Incus instance inventory could not be verified')
        found_current = False
        for instance in instances:
            if not isinstance(instance, dict):
                raise QuarantineError('Incus instance inventory was invalid')
            identity = str((instance.get('config') or {}).get('volatile.uuid') or '')
            if identity == self.instance_id:
                raise QuarantineError('old Incus instance still exists')
            if instance.get('name') == self.name and identity == current_id:
                found_current = True
        if not found_current:
            raise QuarantineError('replacement was not present in the Incus project inventory')
        return current_id

    def snapshot(self):
        item, _ = self.inspect()
        expanded = item.get('expanded_devices', {})
        devices = {k: v for k, v in expanded.items() if v.get('type') in NETWORK_DEVICES}
        if not devices:
            raise QuarantineError('no managed network devices; cannot prove isolation')
        return {'original': {k: copy.deepcopy(item.get('devices', {}).get(k)) for k in devices},
                'expanded': copy.deepcopy(devices), 'guest_names': self.guest_names(item, devices),
                'volatile_identity': self.volatile_identity(item, devices)}

    def volatile_identity(self, item, devices):
        # Incus clears per-device volatile keys when a NIC is masked. Preserve
        # MAC/name, NOT host veth names or transient counters; changing the MAC
        # can change DHCP/SLAAC addresses and invalidate customer NAT mappings.
        keys = {'volatile.'+key+'.'+field for key in devices for field in ('hwaddr','name')}
        return {key: value for key, value in item.get('config', {}).items() if key in keys}

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

    def set_devices(self, item, etag, devices, restore_identity=None):
        # PUT + If-Match replaces the device map (PATCH can merge it and leave
        # inherited-device masks behind during release). Preserve all other fields.
        data = {k: copy.deepcopy(item[k]) for k in ('architecture', 'config', 'profiles', 'ephemeral', 'description') if k in item}
        data['devices'] = devices
        if restore_identity:
            data.setdefault('config', {}).update(restore_identity)
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
        backup.setdefault('volatile_identity', {}).update(self.volatile_identity(item, added))

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
        identity = backup.get('volatile_identity') or {}
        if identity:
            # A none->NIC transition clears volatile keys even if supplied in
            # that PUT (Incus 6.0). First use explicit original MAC/name, seed
            # volatile keys while the NIC exists, then restore inheritance.
            # Keep proxies masked until the final verified configuration step.
            temporary = copy.deepcopy(item.get('devices', {}))
            for key, expanded in backup['expanded'].items():
                if expanded.get('type') not in {'nic', 'infiniband'}:
                    continue
                device = copy.deepcopy(expanded)
                for field in ('hwaddr', 'name'):
                    if identity.get('volatile.'+key+'.'+field):
                        device[field] = identity['volatile.'+key+'.'+field]
                temporary[key] = device
            self.set_devices(item, etag, temporary)
            item, etag = self.inspect()
            self.set_devices(item, etag, item.get('devices', {}), identity)
            item, etag = self.inspect()
        self.set_devices(item, etag, devices)
        fresh, _ = self.inspect()
        if any(fresh.get('devices', {}).get(k) != original for k, original in backup['original'].items()):
            raise QuarantineError('Incus restore readback mismatch')
        for key, value in identity.items():
            if fresh.get('config', {}).get(key) != value:
                raise QuarantineError('Incus restored NIC identity readback mismatch')
        for key, expected in backup['expanded'].items():
            if fresh.get('expanded_devices', {}).get(key) != expected:
                raise QuarantineError('Incus inherited network configuration changed; manual review required')
        if identity:
            state, _ = self.api.request('GET', self.path+'/state')
            for key, name in backup.get('guest_names', {}).items():
                mac = identity.get('volatile.'+key+'.hwaddr')
                if mac and str((state.get('network') or {}).get(name, {}).get('hwaddr', '')).lower() != str(mac).lower():
                    raise QuarantineError('Incus runtime MAC restoration was not confirmed')


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
            item = json.loads(self.command(podman_inspect_args(self.name)))[0]
        except (ValueError, IndexError, TypeError):
            raise QuarantineError('invalid Podman inspection') from None
        identity = str(item.get('Id') or item.get('ID') or '')
        if not identity.startswith(self.instance_id) or len(self.instance_id) < 12:
            raise QuarantineError('Podman container identity changed; refused')
        mode = str(item.get('HostConfig', {}).get('NetworkMode') or '')
        pid_mode = str(item.get('HostConfig', {}).get('PidMode') or '')
        if item.get('Pod') or mode == 'host' or mode.startswith(('container:', 'ns:', 'pasta', 'slirp4netns')) or pid_mode == 'host' or pid_mode.startswith('container:'):
            raise QuarantineError('shared/host/rootless network requires manual isolation')
        if item.get('HostConfig', {}).get('Privileged') or item.get('HostConfig', {}).get('Devices'):
            raise QuarantineError('privileged/device-passthrough container requires manual isolation')
        return item

    def prove_replaced(self):
        """Prove the name points to a different ID and the old ID is absent."""
        try:
            current = json.loads(self.command(podman_inspect_args(self.name)))[0]
        except (ValueError, IndexError, TypeError):
            raise QuarantineError('invalid Podman replacement inspection') from None
        current_id = str(current.get('Id') or current.get('ID') or '')
        if not re.fullmatch(r'[0-9a-fA-F]{12,64}', current_id):
            raise QuarantineError('Podman replacement identity could not be verified')
        if current_id.lower().startswith(self.instance_id.lower()) or self.instance_id.lower().startswith(current_id.lower()):
            raise QuarantineError('Podman container identity did not change')
        ok, output = self.run([self.binary, 'inspect', '--type', 'container', '--format', '{{.Id}}', self.instance_id])
        if ok:
            old_ids = [line.strip().lower() for line in str(output or '').splitlines() if line.strip()]
            if not old_ids or any(old_id == self.instance_id.lower() or old_id.startswith(self.instance_id.lower()) or self.instance_id.lower().startswith(old_id) for old_id in old_ids):
                raise QuarantineError('old Podman container still exists')
            raise QuarantineError('Podman returned an unexpected old-container identity')
        if not re.search(r'(?i)(no such object|no such container|no container with name or id|not found)', str(output or '')):
            raise QuarantineError('Podman could not prove the old container absent')
        return current_id

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


class RunmanIsolation:
    """Generation-bound quarantine through Runman's persistent veth control."""

    def __init__(self, name, instance_id, socket_path='/run/narwhal-agent/connlimit.sock'):
        self.name, self.instance_id, self.socket_path = name, instance_id, socket_path

    def command(self, action):
        connection = _UnixHTTP(self.socket_path)
        connection.timeout = 15
        body = json.dumps({
            'container_name': self.name,
            'project': 'default',
            'instance_id': self.instance_id,
            'action': action,
        }, separators=(',', ':'))
        try:
            connection.request('POST', '/v1/network-quarantine', body=body,
                               headers={'Content-Type': 'application/json', 'Connection': 'close'})
            response = connection.getresponse()
            raw = response.read(16*1024+1)
            if response.status != 200 or len(raw) > 16*1024:
                raise QuarantineError('Runman network quarantine request was not confirmed')
            result = json.loads(raw.decode('utf-8')) if raw else {}
        except QuarantineError:
            raise
        except (OSError, ValueError, UnicodeDecodeError, http.client.HTTPException):
            raise QuarantineError('Runman network quarantine socket unavailable or invalid') from None
        finally:
            connection.close()
        if not isinstance(result, dict) or result.get('ok') is not True:
            raise QuarantineError('Runman network quarantine returned an invalid response')
        generation = str(result.get('instance_id') or '')
        if action != 'replacement' and generation != self.instance_id:
            raise QuarantineError('Runman instance generation changed; refused')
        if type(result.get('isolated')) is not bool or type(result.get('interface_up')) is not bool or type(result.get('running')) is not bool:
            raise QuarantineError('Runman network quarantine readback is incomplete')
        return result

    def inspect(self):
        return self.command('inspect')

    def snapshot(self):
        state = self.inspect()
        if state['running'] is not True or state['isolated'] is not False or state['interface_up'] is not True:
            raise QuarantineError('Runman interface is not in a verified connected state')
        return {'interface_was_up': True}

    def isolate(self, backup):
        if not isinstance(backup, dict) or backup.get('interface_was_up') is not True:
            raise QuarantineError('Runman quarantine recovery state is invalid')
        state = self.command('isolate')
        if state['running'] is not True or state['isolated'] is not True or state['interface_up'] is not False:
            raise QuarantineError('Runman interface-down isolation was not confirmed')

    def verify(self, backup):
        state = self.inspect()
        if state['running'] is not True or state['isolated'] is not True or state['interface_up'] is not False:
            raise QuarantineError('Runman quarantine is not active on the host veth')

    def release(self, backup):
        if not isinstance(backup, dict) or backup.get('interface_was_up') is not True:
            raise QuarantineError('Runman quarantine recovery state is invalid')
        self.verify(backup)
        state = self.command('release')
        if state['isolated'] is not False or (state['running'] and not state['interface_up']):
            raise QuarantineError('Runman network release readback mismatch')

    def prove_replaced(self):
        state = self.command('replacement')
        generation = str(state.get('instance_id') or '')
        if not generation or generation == self.instance_id:
            raise QuarantineError('Runman replacement generation could not be verified')
        return generation


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


def retire_replaced(journal, key, driver):
    """Archive only the old journal after runtime identity absence is proven."""
    with _LOCK:
        entries = journal.read()
        current_id = driver.prove_replaced()
        entries.pop(key, None)
        journal.write(entries)
        return current_id


def safe_evidence(evidence):
    """Whitelist only typed feature metadata; never persist argv, code or records."""
    if not isinstance(evidence, list):
        raise QuarantineError('typed abuse evidence required')
    result = []
    strings = {'kind', 'confidence', 'basis', 'tool', 'start_ticks', 'source_sha256'}
    numbers = {'pid', 'target_count', 'public_target_count', 'private_target_count', 'owned_http_connections', 'pending_attempts',
               'vertical_ports', 'horizontal_targets', 'failed_ratio', 'pending_ratio'}
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

