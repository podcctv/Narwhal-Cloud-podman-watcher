"""Direction-aware SOCKS facts. Never return credentials or infer public exposure."""
import ipaddress
import json
import posixpath
import re
import shlex
import string
from collections import Counter
from urllib.parse import urlsplit, unquote

MAX_CONFIG_BYTES = 262144
FAMILIES = {'xray', 'v2ray', 'sing-box', 'gost'}
WEAK = {'123456', '12345678', '123123', 'admin', 'admin123', 'changeme',
        'default', 'guest', 'letmein', 'pass', 'password', 'qwerty', 'root',
        'socks', 'socks5', 'test', 'toor'}


def password_profile(value):
    """Only aggregate counts leave the node: no characters, order, username or hash."""
    if not isinstance(value, str) or len(value) > 4096 or '${' in value:
        return {'available': False, 'reason': '密码缺失、外部引用或超过统计上限'}
    digits = Counter(c for c in value if c in string.digits)
    longest = current = 0
    previous = None
    for char in value:
        current = current + 1 if char == previous else 1
        previous = char
        longest = max(longest, current)
    return {'available': True, 'length': len(value),
            'lowercase': sum(c in string.ascii_lowercase for c in value),
            'uppercase': sum(c in string.ascii_uppercase for c in value),
            'digits': sum(digits.values()), 'symbols': sum(c in string.punctuation for c in value),
            'other': sum(c not in string.ascii_letters + string.digits + string.punctuation for c in value),
            'repeated_digits': sum(n - 1 for n in digits.values()),
            'max_digit_frequency': max(digits.values(), default=0), 'longest_identical_run': longest}


def profiles(users, key):
    if not isinstance(users, list) or not users:
        return [{'available': False, 'reason': '未找到内联入站认证账号；可能使用外部认证'}]
    result = [dict(password_profile(u.get(key) if isinstance(u, dict) else None), account_index=i+1)
              for i, u in enumerate(users[:20])]
    if len(users) > 20:
        result.append({'available': False, 'reason': '仅展示前 20 个账号，未统计其余账号'})
    return result


def gost_url(value):
    """GOST v2 inbound URL only. The caller must never pass a forwarding chain."""
    try:
        parsed = urlsplit(value)
        if parsed.scheme.split('+')[0] not in {'socks', 'socks5'} or not parsed.port:
            return None
        profile = password_profile(unquote(parsed.password)) if parsed.password is not None else {
            'available': False, 'reason': '入站 URL 未提供内联密码；以握手结果为准'}
        return {'port': parsed.port, 'listen': parsed.hostname or '*', 'auth_state': 'unknown',
                'password_profiles': [profile]}
    except (ValueError, TypeError):
        return None


def gost_config(raw):
    result = {'parsed': False, 'endpoints': [], 'single_purpose': False}
    if len(raw.encode('utf-8')) > MAX_CONFIG_BYTES:
        return result
    try:
        try:
            data = json.loads(raw)
        except ValueError:
            import yaml
            # No aliases, custom tags, or expansive graph construction. Deep input fails closed.
            for token in yaml.scan(raw):
                if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken)):
                    return result
            data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            return result
        services = data.get('services', data.get('serveNodes', []))
        if not isinstance(services, list) or not services or len(services) > 100:
            return result
        for service in services:
            if isinstance(service, str):
                entry = gost_url(service)
                if entry:
                    result['endpoints'].append(entry)
                continue
            if not isinstance(service, dict):
                continue
            handler = service.get('handler', {})
            if not isinstance(handler, dict) or handler.get('type') not in {'socks', 'socks5'}:
                continue
            host, port = endpoint(service.get('addr'))
            if not 0 < port < 65536:
                continue
            auth = handler.get('auth')
            users = [auth] if isinstance(auth, dict) else []
            # Authers are live external sources; their contents are not proved by this file.
            facts = profiles(users, 'password') if not handler.get('auther') else [
                {'available': False, 'reason': '使用外部 auther，配置未包含可统计的入站密码'}]
            result['endpoints'].append({'port': port, 'listen': host or '*', 'auth_state': 'unknown',
                                        'password_profiles': facts})
        result['parsed'] = True
        result['single_purpose'] = len(services) == 1 and len(result['endpoints']) == 1
    except Exception:
        # YAML/JSON errors can embed source lines. Never log exception text or raw config.
        return {'parsed': False, 'endpoints': [], 'single_purpose': False}
    return result


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
    if process == 'gost':
        return gost_config(raw)
    # JSONC comments are allowed by Xray. Preserve quoted strings, including URLs.
    raw = re.sub(r'"(?:\\.|[^"\\])*"|//[^\r\n]*|/\*.*?\*/',
                 lambda m: m[0] if m[0].startswith('"') else ' ', raw, flags=re.S)
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return result
    if not isinstance(data, dict):
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
            ports = [int(port)] if not isinstance(port, (bool, float)) else []
        except (TypeError, ValueError, OverflowError):
            ports = []  # Ranges/dynamic ports must not accidentally match other listeners.
        ports = [p for p in ports if 0 < p < 65536]
        if not ports:
            result['parsed'] = False
        mode = 'unknown'
        password_facts = []
        if process in {'xray', 'v2ray'}:
            settings = inbound.get('settings', {})
            if isinstance(settings, dict):
                auth = settings.get('auth', 'noauth')
                if auth == 'noauth':
                    mode = 'no_auth'
                elif auth == 'password':
                    users = settings.get('users', settings.get('accounts'))
                    mode = auth_strength(users, 'user', 'pass')
                    password_facts = profiles(users, 'pass')
        else:
            users = inbound.get('users', [])
            mode = 'no_auth' if users == [] else auth_strength(users, 'username', 'password')
            password_facts = profiles(users, 'password') if users else []
        for p in ports:
            listen = inbound.get('listen', '*')
            entry = {'port': p, 'listen': listen if isinstance(listen, str) else '*', 'auth_state': mode}
            if password_facts:
                entry['password_profiles'] = password_facts
            result['endpoints'].append(entry)
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
        if process not in FAMILIES | {'danted', 'sockd', '3proxy'} or not tokens or posixpath.basename(tokens[0]).lower() != process:
            continue
        paths = []
        for index, token in enumerate(tokens):
            value = ''
            if token in {'-c', '-C', '-f', '-config', '--config', '-conf', '--config-file'} and index + 1 < len(tokens):
                value = tokens[index + 1]
            elif token.startswith(('--config=', '-config=')):
                value = token.split('=', 1)[1]
            if re.fullmatch(r'/[A-Za-z0-9_./-]{1,240}', value) and value.endswith(('.json', '.yaml', '.yml', '.conf', '.cfg')) and '..' not in value.split('/'):
                paths.append(value)
        if process == '3proxy':
            paths += [t for t in tokens[1:] if re.fullmatch(r'/[A-Za-z0-9_./-]{1,240}\.cfg', t) and '..' not in t.split('/')]
        if not paths and not any(t.startswith(('-c', '-C', '-f', '--config', '-config', '-confdir')) for t in tokens):
            paths = {'danted': ['/etc/danted.conf'], 'sockd': ['/etc/sockd.conf'],
                     '3proxy': ['/etc/3proxy/3proxy.cfg'], 'gost': ['/etc/gost/config.json', '/etc/gost/config.yaml']}.get(process, [f'/etc/{process}/config.json'])
        rows.append({'pid': int(parts[0]), 'process': process, 'paths': list(dict.fromkeys(paths))[:4],
                     'additional_configs': any(t.startswith(('-confdir', '--config-dir')) for t in tokens)})
        if len(rows) >= 8:
            break
    return rows


def legacy_profiles(raw, process):
    if process in {'danted', 'sockd'}:
        return [{'available': False, 'reason': 'Dante 使用系统/PAM 认证；不能从密码哈希还原长度或组成'}]
    if process == '3proxy' and len(raw.encode('utf-8')) <= MAX_CONFIG_BYTES:
        found = []
        for line in raw.splitlines():
            try:
                tokens = shlex.split(line, comments=True)
            except ValueError:
                continue
            if tokens[:1] != ['users']:
                continue
            for token in tokens[1:21]:
                parts = token.split(':', 2)
                found.append(password_profile(parts[2]) if len(parts) == 3 and parts[1] == 'CL' else
                             {'available': False, 'reason': '加密或外部密码，不能还原组成'})
                if len(found) >= 20:
                    return found
        if found:
            return found
    return [{'available': False, 'reason': '配置未读取、格式不支持或认证保存在外部；未按空密码处理'}]


def gost_cli(output, pid):
    for line in output.splitlines():
        parts = line.split(None, 3)
        if len(parts) != 4 or parts[0] != str(pid):
            continue
        try:
            tokens = shlex.split(parts[3])
        except ValueError:
            return None
        listeners = []
        for i, token in enumerate(tokens):
            if token == '-L' and i+1 < len(tokens):
                listeners.append(tokens[i+1])
            elif token.startswith('-L='):
                listeners.append(token[3:])
        if listeners:
            entries = [e for e in (gost_url(v) for v in listeners[:100]) if e]
            return {'parsed': len(listeners) <= 100, 'endpoints': entries,
                    'single_purpose': len(listeners) == 1 and len(entries) == 1
                        and not any(t in {'-C', '-c', '--config'} or t.startswith('--config=') for t in tokens)}
    return None


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
