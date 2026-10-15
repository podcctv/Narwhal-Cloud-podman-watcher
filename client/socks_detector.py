"""Direction-aware SOCKS facts. Never return credentials or infer public exposure."""
import ipaddress
import json
import posixpath
import re
import shlex

MAX_CONFIG_BYTES = 262144
FAMILIES = {'xray', 'v2ray', 'sing-box', 'gost'}
WEAK = {'123456', '12345678', '123123', 'admin', 'admin123', 'changeme',
        'default', 'guest', 'letmein', 'pass', 'password', 'qwerty', 'root',
        'socks', 'socks5', 'test', 'toor'}


def auth_strength(users, user_key, password_key):
    if not isinstance(users, list) or not users:
        return 'unknown'
    modes = []
    for user in users[:100]:
        if not isinstance(user, dict):
            return 'unknown'
        username, password = user.get(user_key), user.get(password_key)
        if not isinstance(username, str) or not username or not isinstance(password, str):
            return 'unknown'
        modes.append('weak_password' if len(password) < 8 or password.lower() in WEAK else 'configured')
    if len(users) > 100:
        return 'unknown'
    return 'weak_password' if 'weak_password' in modes else 'configured'


def parse_config(raw, process):
    """Parse only inbound sections; a bad/oversized document is NOT negative evidence."""
    result = {'parsed': False, 'endpoints': [], 'single_purpose': False}
    if process not in FAMILIES or len(raw.encode('utf-8')) > MAX_CONFIG_BYTES:
        return result
    # JSONC comments are allowed by Xray. Preserve quoted strings, including URLs.
    raw = re.sub(r'"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*.*?\*/',
                 lambda m: m[0] if m[0].startswith('"') else ' ', raw, flags=re.S)
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return result
    if not isinstance(data, dict):
        return result
    if process == 'gost':  # External authers/YAML remain unknown, verified by handshake.
        return result
    inbounds = data.get('inbounds', [])
    if not isinstance(inbounds, list) or len(inbounds) > 100 or any(not isinstance(i, dict) for i in inbounds):
        return result
    result['parsed'] = True
    for inbound in inbounds:
        kind = str(inbound.get('protocol') if process in {'xray', 'v2ray'} else inbound.get('type')).lower()
        if kind not in {'socks', 'mixed'} or (kind == 'mixed' and process != 'sing-box'):
            continue
        port = inbound.get('port') if process in {'xray', 'v2ray'} else inbound.get('listen_port')
        try:
            ports = [int(port)] if not isinstance(port, bool) else []
        except (TypeError, ValueError):
            ports = []  # Ranges/dynamic ports must not accidentally match other listeners.
        ports = [p for p in ports if 0 < p < 65536]
        mode = 'unknown'
        if process in {'xray', 'v2ray'}:
            settings = inbound.get('settings', {})
            if isinstance(settings, dict):
                auth = settings.get('auth', 'noauth')
                if auth == 'noauth':
                    mode = 'no_auth'
                elif auth == 'password':
                    mode = auth_strength(settings.get('users', settings.get('accounts')), 'user', 'pass')
        else:
            users = inbound.get('users', [])
            mode = 'no_auth' if users == [] else auth_strength(users, 'username', 'password')
        for p in ports:
            listen = inbound.get('listen', '*')
            result['endpoints'].append({'port': p, 'listen': listen if isinstance(listen, str) else '*', 'auth_state': mode})
    result['single_purpose'] = len(inbounds) == 1 and len(result['endpoints']) == 1
    return result


def process_configs(output):
    """Exact executable + explicit config paths, not arbitrary words in argv."""
    rows = []
    for line in output.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) != 4 or not parts[0].isdigit() or 'z' in parts[1].lower():
            continue
        try:
            tokens = shlex.split(parts[3])
        except ValueError:
            continue
        process = parts[2].lower()
        if process not in FAMILIES or not tokens or posixpath.basename(tokens[0]).lower() != process:
            continue
        paths = []
        for index, token in enumerate(tokens):
            value = ''
            if token in {'-c', '-config', '--config', '-conf', '--config-file'} and index + 1 < len(tokens):
                value = tokens[index + 1]
            elif token.startswith(('--config=', '-config=')):
                value = token.split('=', 1)[1]
            if re.fullmatch(r'/[A-Za-z0-9_./-]{1,240}', value) and value.endswith('.json'):
                paths.append(value)
        if not paths and not any(t.startswith(('-c', '--config', '-config', '-confdir')) for t in tokens):
            paths = [f'/etc/{process}/config.json']
        rows.append({'pid': int(parts[0]), 'process': process, 'paths': list(dict.fromkeys(paths))[:4]})
        if len(rows) >= 8:
            break
    return rows


def endpoint(value):
    text = str(value or '').strip()
    if text.lower().startswith(('tcp:', 'udp:')):
        text = text.split(':', 1)[1]
    try:
        host, port = text.rsplit(':', 1)
        return host.strip('[]'), int(port)
    except (ValueError, TypeError):
        return '', 0


def loopback(host):
    try:
        address = ipaddress.ip_address(host)
        return address.is_loopback or bool(getattr(address, 'ipv4_mapped', None) and address.ipv4_mapped.is_loopback)
    except ValueError:
        return host.lower() == 'localhost'


def exposed(listener, forwards):
    host, port = endpoint(listener.get('local'))
    if not host or not 0 < port < 65536:
        return None
    if not loopback(host):
        return True  # Includes LAN: network-accessible is not a claim about Internet reachability.
    for item in forwards:
        if not isinstance(item, dict):
            continue
        target_host, target_port = endpoint(item.get('target', item.get('connect', '')))
        listen_host, _ = endpoint(item.get('listen', ''))
        if target_port == port and loopback(target_host) and listen_host and not loopback(listen_host):
            return True
    return False


def greeting_mode(response):
    # Offering 00 + 02 sends no password and never issues CONNECT/UDP ASSOCIATE.
    return {b'\x05\x00': 'no_auth', b'\x05\x02': 'auth_required'}.get(response, 'unknown')


PROBE_CODE = '''import json,socket,sys
host,port=json.loads(sys.argv[1])
result='unknown'
try:
 with socket.create_connection((host,port),timeout=1) as s:
  s.settimeout(1); s.sendall(bytes([5,2,0,2])); data=b''
  while len(data)<2:
   part=s.recv(2-len(data))
   if not part: break
   data+=part
  result={bytes([5,0]):'no_auth',bytes([5,2]):'auth_required'}.get(data,'unknown')
except OSError: pass
print(result)
'''
