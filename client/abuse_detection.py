"""Bounded abuse evidence classification. Never return source, credentials or PII.

High concurrency, Python, Telegram, TLS and ordinary proxy fanout are not proof.
Decisions here describe observable prohibited behaviour, not a legal verdict.
"""
import ast
import hashlib
import ipaddress
import re
from collections import defaultdict
from urllib.parse import urlsplit


SOURCE_LIMIT = 65536
NODE_LIMIT = 12000
SCANNERS = {'masscan', 'zmap', 'nmap', 'rustscan'}
AUTH_TOOLS = {'hydra', 'medusa', 'ncrack', 'patator'}
SENSITIVE_PORTS = {21, 22, 23, 25, 110, 139, 143, 445, 1433, 3306, 3389,
                   5432, 5900, 6379, 11211, 27017}
IDENTITY_KEYS = {'idcard', 'id_card', 'idnumber', 'id_number', 'identity_number',
                 'idno', 'id_no', 'idcardno', 'identitycard', 'identityno', 'certificateno', 'certificate_no', '身份证', '身份证号'}
USERNAME_KEYS = {'username', 'user', 'login', 'email', 'account'}
PASSWORD_KEYS = {'password', 'passwd', 'pwd', 'pass'}


def public_ip(value):
    try:
        parsed = ipaddress.ip_address(str(value).split('%', 1)[0])
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
            parsed = parsed.ipv4_mapped
        return str(parsed) if parsed.is_global else ''
    except ValueError:
        return ''


def _url_host(value):
    """No DNS queries, HTTP requests, query strings or user-info in evidence."""
    try:
        parsed = urlsplit(str(value))
        host = (parsed.hostname or '').lower().rstrip('.')
        if parsed.scheme not in {'http', 'https'}:
            return ''
        try:
            return public_ip(host) if ipaddress.ip_address(host) else ''
        except ValueError:
            if not re.fullmatch(r'[a-z0-9.-]{1,253}', host) or '.' not in host:
                return ''
            if host.endswith(('.localhost', '.local', '.internal', '.invalid', '.test')):
                return ''
            return host
    except (ValueError, TypeError):
        return ''


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _name(node.value) + '.' + node.attr
    return ''


def _literal(node, constants):
    """Resolve only bounded literals; never evaluate customer code or expressions."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)) and not isinstance(node.value, bool):
        value = node.value
        if isinstance(value, str) and len(value) <= 4096 or isinstance(value, int) and abs(value) <= 1000000:
            return value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal(node.left, constants), _literal(node.right, constants)
        if type(left) == type(right) and isinstance(left, (str, int)):
            value = left+right
            if isinstance(value, str) and len(value) <= 4096 or isinstance(value, int) and abs(value) <= 1000000:
                return value
    return None


def _nodes(tree):
    """Do not promote comments/docstrings or constant-dead branches to activity."""
    queue = [tree]
    seen = 0
    while queue:
        node = queue.pop()
        seen += 1
        if seen > NODE_LIMIT:
            raise ValueError('source complexity limit')
        yield node
        if isinstance(node, ast.If) and isinstance(node.test, ast.Constant):
            queue.extend(node.body if node.test.value else node.orelse)
        elif isinstance(node, ast.While) and isinstance(node.test, ast.Constant) and not node.test.value:
            queue.extend(node.orelse)
        else:
            queue.extend(ast.iter_child_nodes(node))


def _reachable_tree(tree):
    """Unused audit/test functions must not implicate the running application."""
    functions = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    bodies = [n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    included = set()
    while True:
        module = ast.Module(body=bodies, type_ignores=[])
        calls = [n for n in _nodes(module) if isinstance(n, ast.Call)]
        referenced = {_name(n.func) for n in calls}
        for call in calls:
            referenced.update(arg.id for arg in call.args if isinstance(arg, ast.Name))
        newly = (referenced & set(functions)) - included
        if not newly:
            return module
        included.update(newly)
        bodies.extend(functions[name] for name in newly)


def source_evidence(source):
    """Classify a running Python entrypoint; raw source exists only in memory."""
    if not isinstance(source, str) or len(source.encode('utf-8')) > SOURCE_LIMIT:
        return {'available': False, 'reason': 'source_unavailable_or_truncated'}
    digest = hashlib.sha256(source.encode('utf-8')).hexdigest()
    try:
        nodes = list(_nodes(_reachable_tree(ast.parse(source))))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return {'available': False, 'reason': 'source_unparseable', 'sha256': digest}
    imports, constants, assignments = {}, {}, {}
    for node in nodes:
        if isinstance(node, ast.Import):
            imports.update({n.asname or n.name: n.name for n in node.names})
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.update({n.asname or n.name: node.module + '.' + n.name for n in node.names})
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(node.value)
    for _ in range(4):
        for node in nodes:
            if isinstance(node, ast.Assign):
                literal = _literal(node.value, constants)
                if literal is not None:
                    constants.update({t.id: literal for t in node.targets if isinstance(t, ast.Name) and len(assignments[t.id]) == 1})

    def qualified(node):
        name = _name(node)
        head, _, tail = name.partition('.')
        return imports.get(head, head) + ('.' + tail if tail else '')

    sessions = set()
    for node in nodes:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if qualified(node.value.func) in {'requests.Session', 'httpx.Client', 'httpx.AsyncClient', 'aiohttp.ClientSession'}:
                sessions.update(t.id for t in node.targets if isinstance(t, ast.Name))
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call) and qualified(item.context_expr.func) in {'aiohttp.ClientSession', 'httpx.AsyncClient', 'httpx.Client'} and isinstance(item.optional_vars, ast.Name):
                    sessions.add(item.optional_vars.id)
    keys, public_hosts, workers = set(), set(), []
    request_count = 0
    auth_endpoints = 0
    identity_hosts, auth_hosts = set(), set()
    enumeration = False
    dictionary_inputs = False
    identity_generator = False
    has_loop = any(isinstance(n, (ast.For, ast.AsyncFor, ast.While, ast.comprehension)) for n in nodes)
    for node in nodes:
        if isinstance(node, ast.Dict):
            keys.update(str(k.value).lower() for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            identity_generator |= bool(re.search(r'(generate|gen|random|枚举|生成).*(id_?(card|number|no)|identity|身份证)', node.name, re.I))
        if not isinstance(node, ast.Call):
            continue
        call = qualified(node.func)
        root, _, method = call.partition('.')
        is_http = (root in {'requests', 'httpx', 'aiohttp'} or _name(node.func).split('.')[0] in sessions) and method.rsplit('.', 1)[-1] in {'get', 'post', 'request', 'put'}
        if is_http:
            request_count += 1
            payload_keys = set()
            for keyword in node.keywords:
                if keyword.arg in {'data', 'json', 'params'}:
                    payload = keyword.value
                    if isinstance(payload, ast.Name) and len(assignments.get(payload.id, [])) == 1:
                        payload = assignments[payload.id][0]
                    if isinstance(payload, ast.Dict):
                        payload_keys.update(str(k.value).lower() for k in payload.keys if isinstance(k, ast.Constant) and isinstance(k.value, str))
            for arg in [*node.args, *(kw.value for kw in node.keywords if kw.arg == 'url')]:
                url = _literal(arg, constants)
                if isinstance(url, str):
                    host = _url_host(url)
                    if host:
                        public_hosts.add(host)
                        authentication = bool(re.search(r'/(login|auth|authenticate|token|signin|sessions?)(/|$|[?])', urlsplit(url).path, re.I))
                        auth_endpoints += authentication
                        if payload_keys & IDENTITY_KEYS:
                            identity_hosts.add(host)
                        if authentication and payload_keys & USERNAME_KEYS and payload_keys & PASSWORD_KEYS:
                            auth_hosts.add(host)
        if call.endswith(('.ThreadPoolExecutor', '.ProcessPoolExecutor', '.Semaphore')) or call in {'ThreadPoolExecutor', 'ProcessPoolExecutor', 'Semaphore'}:
            candidates = [kw.value for kw in node.keywords if kw.arg == 'max_workers'] + list(node.args[:1])
            workers.extend(v for v in (_literal(candidate, constants) for candidate in candidates) if isinstance(v, int) and not isinstance(v, bool) and 0 < v < 1000000)
        if call in {'itertools.product', 'builtins.range', 'range', 'random.randint', 'random.choice', 'random.choices', 'secrets.randbelow'}:
            enumeration = True
        if call in {'open', 'pathlib.Path'}:
            for arg in node.args[:1]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    # Only the category survives. Never retain paths or file contents.
                    dictionary_inputs |= bool(re.search(r'(passwords?|passlist|wordlist|users|usernames|密码|字典)', arg.value, re.I))
        identity_generator |= bool(re.search(r'(generate|gen|random|枚举|生成).*(id_?(card|number|no)|identity|身份证)', call, re.I))
    kinds = []
    concurrent = max(workers, default=0) >= 20
    if identity_hosts and request_count and has_loop and enumeration and identity_generator and keys & IDENTITY_KEYS and concurrent:
        kinds.append('identity_enumeration')
    if auth_hosts and auth_endpoints and request_count and has_loop and keys & USERNAME_KEYS and keys & PASSWORD_KEYS and dictionary_inputs:
        kinds.append('credential_stuffing' if enumeration else 'authentication_bruteforce')
    return {'available': True, 'sha256': digest, 'kinds': kinds,
            'features': {'http_calls': request_count, 'enumeration': enumeration,
                         'dictionary_inputs': dictionary_inputs, 'identity_generator': identity_generator,
                         'concurrency': max(workers, default=0)},
            'target_hosts': sorted(identity_hosts | auth_hosts)[:10],
            'targets_by_kind': {kind: sorted(identity_hosts if kind == 'identity_enumeration' else auth_hosts)[:10] for kind in kinds}}


def tool_evidence(argv):
    if not isinstance(argv, list) or not argv or len(argv) > 256:
        return []
    tool = str(argv[0]).rsplit('/', 1)[-1].lower()
    if tool not in SCANNERS | AUTH_TOOLS:
        return []
    args = [str(v)[:1024] for v in argv[1:]]
    help_flags = {'--help', '--version', '-V', '-sL'} | ({'-h'} if tool != 'medusa' else set())
    if any(v in help_flags for v in args):
        return []
    public_targets = set()
    skip_value = False
    ignored_options = {'--exclude', '--excludefile', '-S', '--source-ip', '-D', '-oN', '-oX', '-oG',
                       '-oA', '-p', '--ports', '--rate', '--max-rate', '-l', '-L', '-p', '-P', '-u', '-U',
                       '-m', '-M', '-t', '-T', '-I', '-iL', '--adapter-ip'}
    for value in args:
        if skip_value:
            skip_value = False
            continue
        if value in ignored_options:
            skip_value = True
            continue
        if value.startswith('-'):
            # Explicit destination options; do not confuse passwords/source IPs
            # or excluded addresses with actual scan/authentication targets.
            if tool == 'medusa' and value.startswith('-h') and len(value) > 2:
                value = value[2:]
            elif tool == 'rustscan' and value.startswith('--addresses='):
                value = value.split('=', 1)[1]
            else:
                continue
        candidate = value
        if '://' in value:
            candidate = urlsplit(value).hostname or ''
        try:
            network = ipaddress.ip_network(candidate, strict=False)
            if network.network_address.is_global and network.broadcast_address.is_global:
                public_targets.add(str(network))
        except ValueError:
            pass
    # Domains/target files are deliberately not guessed; other evidence is required.
    if not public_targets:
        return []
    return [{'kind': 'outbound_scan' if tool in SCANNERS else 'authentication_bruteforce',
             'confidence': 'high', 'basis': 'active_prohibited_tool', 'tool': tool,
             'public_target_count': len(public_targets)}]


def network_evidence(sockets):
    """Require same-process public TCP SYN fanout; inbound/CDN/TLS counts do not qualify."""
    owners = defaultdict(list)
    for item in sockets[:2000] if isinstance(sockets, list) else []:
        if not isinstance(item, dict) or item.get('direction') != 'outbound' or item.get('proto') != 'tcp':
            continue
        ip = public_ip(item.get('remote_ip'))
        try:
            pid = int(item.get('pid') or 0)
            port = int(str(item.get('remote', '')).rsplit(':', 1)[-1])
        except (ValueError, TypeError):
            continue
        if ip and pid > 1 and 0 < port <= 65535:
            owners[pid].append((ip, port, str(item.get('state', '')).lower().replace('_', '-')))
    findings = []
    for pid, flows in owners.items():
        attempts = {(ip, port) for ip, port, state in flows if state in {'syn-sent', 'syn-sent2'}}
        total = {(ip, port) for ip, port, _ in flows}
        if len(attempts) < 32 or len(attempts) / max(1, len(total)) < .9:
            continue
        by_ip, by_port = defaultdict(set), defaultdict(set)
        for ip, port in attempts:
            by_ip[ip].add(port)
            by_port[port].add(ip)
        vertical = max((len(v) for v in by_ip.values()), default=0)
        horizontal = max((len(v) for k, v in by_port.items() if k in SENSITIVE_PORTS), default=0)
        if vertical >= 32 or horizontal >= 64:
            findings.append({'kind': 'outbound_scan', 'confidence': 'corroboration_required',
                             'basis': 'same_process_failed_public_fanout', 'pid': pid,
                             'pending_attempts': len(attempts), 'vertical_ports': vertical,
                             'horizontal_targets': horizontal, 'failed_ratio': round(len(attempts)/len(total), 3)})
    return findings


def evaluate_process(process, sockets):
    """No raw argv/source in results. Source features need live process-owned egress."""
    try:
        pid = int(process.get('pid') or 0)
    except (TypeError, ValueError):
        return []
    if pid <= 1 or not process.get('start_ticks'):
        return []
    argv = process.get('argv') or []
    executable = str(process.get('executable') or '').rsplit('/', 1)[-1].lower()
    result = tool_evidence(argv) if argv and executable == str(argv[0]).rsplit('/', 1)[-1].lower() else []
    source = source_evidence(process.get('source')) if process.get('source') is not None else {}
    active_egress = [s for s in sockets if isinstance(s, dict) and s.get('pid') == pid and s.get('direction') == 'outbound'
                     and public_ip(s.get('remote_ip')) and s.get('proto') == 'tcp'
                     and str(s.get('remote', '')).rsplit(':', 1)[-1] in {'80', '443', '8080', '8443'}]
    if active_egress:
        for kind in source.get('kinds', []):
            peers = {s['remote_ip'] for s in active_egress}
            verified = process.get('target_ips', {})
            matched_hosts = [host for host in source.get('targets_by_kind', {}).get(kind, [])
                             if peers & ({public_ip(host)} | set(verified.get(host, [])))]
            if not matched_hosts:
                continue  # A bot's Telegram polling socket is NOT evidence of requests to an identity API.
            result.append({'kind': kind, 'confidence': 'high', 'basis': 'running_entrypoint_and_owned_public_http',
                           'source_sha256': source['sha256'], 'features': source['features'],
                           'target_hosts': matched_hosts, 'owned_http_connections': len(active_egress)})
    for finding in result:
        finding.update(pid=pid, start_ticks=str(process['start_ticks'])[:32])
    return result

