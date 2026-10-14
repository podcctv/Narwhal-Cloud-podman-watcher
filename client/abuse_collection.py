"""Read bounded metadata and *running entrypoints*, not customer record stores.

Guest output is untrusted; nothing is executed from an inspected source file.
The transient argv/source is consumed locally and is never included in reports.
"""
import base64
import os
import posixpath
import re
import shlex
import stat

try:
    from client import network_quarantine as isolation, abuse_detection as detection
except ImportError:
    import network_quarantine as isolation
    import abuse_detection as detection


PROCESS_SCRIPT = r'''
command -v base64 >/dev/null 2>&1 || exit 2
printf '@@NW_ABUSE_V1@@\n'
visited=0; emitted=0
for d in /proc/[0-9]*; do
    visited=$((visited+1)); [ "$visited" -le 512 ] || break
    [ "$emitted" -lt 64 ] || break
    p=${d##*/}; [ "$p" -ge 1 ] 2>/dev/null || continue
    [ -r "$d/stat" ] && [ -r "$d/cmdline" ] || continue
    comm=$(cat "$d/comm" 2>/dev/null)
    case "$comm" in python*|node|nmap|masscan|zmap|rustscan|hydra|medusa|ncrack|patator) ;; *) continue;; esac
    raw=$(cat "$d/stat" 2>/dev/null); rest=${raw##*) }
    ticks=$(printf '%s\n' "$rest" | awk '{print $20}')
    state=$(printf '%s\n' "$rest" | awk '{print $1}')
    [ "$state" != Z ] || continue
    exe=$(readlink "$d/exe" 2>/dev/null | base64 | tr -d '\n')
    cwd=$(readlink "$d/cwd" 2>/dev/null | base64 | tr -d '\n')
    argv=$(head -c 8192 "$d/cmdline" 2>/dev/null | base64 | tr -d '\n')
    printf '%s\t%s\t%s\t%s\t%s\n' "$p" "$ticks" "$exe" "$cwd" "$argv"
    emitted=$((emitted+1))
done
printf '@@NW_END@@:%s:%s\n' "$visited" "$emitted"
'''


def _decode(value, maximum):
    data = base64.b64decode(value, validate=True)
    if len(data) > maximum:
        raise ValueError('bounded process field exceeded')
    return data


def parse_processes(output):
    if not isinstance(output, str) or len(output) > 1024*1024 or '@@NW_ABUSE_V1@@' not in output:
        raise isolation.QuarantineError('process collector unavailable')
    processes = []
    seen = set()
    for line in output.splitlines():
        fields = line.split('\t')
        if len(fields) != 5 or not fields[0].isdigit() or not fields[1].isdigit():
            continue
        try:
            if fields[0] in seen:
                continue
            raw = _decode(fields[4], 8192)
            if len(raw) >= 8192:
                continue  # A truncated argument vector is not safe actuation evidence.
            argv = [p.decode('utf-8', errors='replace') for p in raw.split(b'\0') if p]
            processes.append({'pid': int(fields[0]), 'start_ticks': fields[1],
                              'executable': _decode(fields[2], 4096).decode('utf-8', errors='replace').strip(),
                              'cwd': _decode(fields[3], 4096).decode('utf-8', errors='replace').strip(),
                              'argv': argv})
            seen.add(fields[0])
        except (ValueError, UnicodeError):
            continue
        if len(processes) >= 64:
            break
    if '@@NW_END@@:' not in output:
        raise isolation.QuarantineError('process collector incomplete')
    return processes


def python_entrypoint(process):
    argv = process.get('argv') or []
    if not argv or not re.fullmatch(r'python(?:[0-9.]+)?', posixpath.basename(process.get('executable', ''))):
        return None, None
    for index, argument in enumerate(argv[1:], 1):
        if argument == '-m':
            return None, None  # Do not recursively search import paths/customer files.
        if argument == '-c':
            return (argv[index+1], None) if index+1 < len(argv) else (None, None)
        if argument in {'-W', '-X'}:
            return None, None  # Ambiguous interpreter-option parsing: fail open to observation, not isolation.
        if argument.startswith('-'):
            continue
        if not argument.endswith('.py') or '\x00' in argument or len(argument) > 4096:
            return None, None
        cwd = process.get('cwd', '')
        path = posixpath.normpath(argument if argument.startswith('/') else posixpath.join(cwd, argument))
        return (None, path) if path.startswith('/') else (None, None)
    return None, None


def process_script(sockets):
    """Prioritize socket owners, including custom-named scanning binaries."""
    owners = {}
    for item in sockets if isinstance(sockets, list) else []:
        if isinstance(item, dict) and item.get('direction') == 'outbound':
            pid = item.get('pid')
            if isinstance(pid, int) and not isinstance(pid, bool) and 1 < pid <= 4194304:
                owners[pid] = owners.get(pid, 0)+1
    pids = sorted(owners, key=lambda pid: (-owners[pid], pid))[:64]
    if not pids:
        return PROCESS_SCRIPT
    paths = ' '.join('/proc/'+str(pid) for pid in pids)
    script = PROCESS_SCRIPT.replace('for d in /proc/[0-9]*;', 'for d in '+paths+' /proc/[0-9]*;')
    old = 'case "$comm" in python*|node|nmap|masscan|zmap|rustscan|hydra|medusa|ncrack|patator) ;; *) continue;; esac'
    return script.replace(old, 'case "$p" in '+('|'.join(map(str, pids)))+') ;; *) '+old+';; esac')


def resolve_targets(container, execute, process):
    evidence = detection.source_evidence(process.get('source'))
    if not evidence.get('kinds'):
        return
    process['target_ips'] = {}
    for host in evidence.get('target_hosts', [])[:4]:
        literal = detection.public_ip(host)
        if literal:
            process['target_ips'][host] = [literal]
            continue
        quoted = shlex.quote(host)
        command = ("command -v timeout >/dev/null 2>&1 || exit 2; "
                   f"if command -v getent >/dev/null 2>&1; then timeout 2 getent ahosts {quoted} 2>/dev/null | awk '{{print $1}}'; fi; "
                   f"if command -v nslookup >/dev/null 2>&1; then timeout 2 nslookup {quoted} 2>/dev/null | "
                   "awk '/^Name[[:space:]]*:/ {answer=1; next} answer && /^Address/ {print $NF}'; fi")
        success, addresses = execute(container, command)
        if success:
            process['target_ips'][host] = sorted({detection.public_ip(value) for value in addresses.split() if detection.public_ip(value)})[:20]


def collect(container, execute, sockets):
    ok, output = execute(container, process_script(sockets))
    if not ok:
        raise isolation.QuarantineError('process metadata unavailable')
    processes = parse_processes(output)
    owned_counts = {}
    for item in sockets:
        if isinstance(item, dict) and item.get('direction') == 'outbound':
            pid = item.get('pid', 0)
            owned_counts[pid] = owned_counts.get(pid, 0)+1
    processes.sort(key=lambda p: owned_counts.get(p['pid'], 0), reverse=True)
    read_sources = 0
    for process in processes:
        inline, path = python_entrypoint(process)
        if not owned_counts.get(process['pid']):
            continue
        if inline is not None:
            process['source'] = inline
        elif path and read_sources < 4:
            read_sources += 1
            # No globs, recursive scans, history/credential files, or eval.
            quoted = shlex.quote(path)
            command = f'if [ -f {quoted} ] && [ ! -L {quoted} ]; then head -c 65537 -- {quoted} 2>/dev/null | base64; fi'
            success, encoded = execute(container, command)
            if success:
                try:
                    source = base64.b64decode(''.join(encoded.split()), validate=True)
                    if len(source) <= 65536:
                        process['source'] = source.decode('utf-8')
                except (ValueError, UnicodeError):
                    pass
        if process.get('source'):
            resolve_targets(container, execute, process)
    return processes


def host_metadata(host_pid):
    """Kernel-owned process incarnation; transient argv is never reported."""
    if not isinstance(host_pid, int) or host_pid <= 1:
        raise isolation.QuarantineError('invalid host process identity')
    base = '/proc/'+str(host_pid)
    with open(base+'/stat', encoding='utf-8') as stream:
        value = stream.read(4096)
    fields = value[value.rfind(')')+2:].split()
    if len(fields) <= 19 or fields[0] == 'Z' or not fields[19].isdigit():
        raise isolation.QuarantineError('host process is no longer live')
    with open(base+'/status', encoding='utf-8') as stream:
        namespace = re.search(r'(?m)^NSpid:\s+(.+)$', stream.read(16384))
    if not namespace:
        raise isolation.QuarantineError('kernel PID namespace identity unavailable')
    pid = int(namespace.group(1).split()[-1])
    with open(base+'/cmdline', 'rb') as stream:
        raw = stream.read(8192)
    if len(raw) >= 8192:
        raise isolation.QuarantineError('truncated host argument vector')
    return {'pid':pid,'start_ticks':fields[19],'host_pid':host_pid,
            'argv':[v.decode('utf-8',errors='replace') for v in raw.split(b'\0') if v],
            'executable':os.readlink(base+'/exe'),'cwd':os.readlink(base+'/cwd')}


def scoped_host_processes(init_pid, proc_root='/proc', scan_limit=20000):
    """Select by kernel PID namespace, not ancestry (podman exec has another parent)."""
    root=os.fspath(proc_root)
    namespace=os.stat(root+'/'+str(init_pid)+'/ns/pid').st_ino
    pids=sorted(int(value) for value in os.listdir(root) if value.isdigit())
    if len(pids)>scan_limit:
        raise isolation.QuarantineError('kernel process inventory exceeded safe bound; coverage unavailable')
    result=[]
    for host_pid in pids:
        base=root+'/'+str(host_pid)
        try:
            if os.stat(base+'/ns/pid').st_ino!=namespace:
                continue
            with open(base+'/status',encoding='utf-8') as stream:
                fields=re.search(r'(?m)^NSpid:\s+(.+)$',stream.read(16384))
            if not fields:
                continue
            pid=int(fields.group(1).split()[-1])
            with open(base+'/comm',encoding='utf-8') as stream:
                comm=stream.read(256).strip()[:120]
            result.append({'host_pid':host_pid,'pid':pid,'process':comm})
        except (OSError,ValueError):
            continue
    if not any(value['host_pid']==init_pid for value in result):
        raise isolation.QuarantineError('container init incarnation disappeared during process discovery')
    return result


def read_host_entrypoint(process):
    """Read ONLY a running .py entrypoint through its process root/cwd.

    Walk every component without following symlinks. No traversal, magic links,
    recursive search, history files or reads outside the target process root.
    """
    argv = process.get('argv') or []
    inline, parsed = python_entrypoint({**process,'cwd':'/'})
    if inline is not None:
        return inline
    if parsed is None:
        return None
    argument = next((v for v in argv[1:] if not v.startswith('-')), '')
    pieces = argument.split('/')
    if '..' in pieces or len(pieces)>64 or '\x00' in argument:
        return None
    base='/proc/'+str(process['host_pid'])+('/root' if argument.startswith('/') else '/cwd')
    directory=os.open(base,os.O_RDONLY|os.O_DIRECTORY)
    try:
        components=[v for v in pieces if v and v!='.']
        for component in components[:-1]:
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
            os.close(directory);directory=child
        if not components:
            return None
        fd=os.open(components[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        with os.fdopen(fd,'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return None
            source=stream.read(65537)
        return source.decode('utf-8') if len(source)<=65536 else None
    finally:
        os.close(directory)


def collect_host(host_processes, sockets, container, execute):
    """No dependency on guest ps/ss/base64; no customer record-store reads."""
    owners={}
    for flow in sockets:
        if flow.get('direction')=='outbound':
            pid=flow.get('pid');owners[pid]=owners.get(pid,0)+1
    selected=sorted(host_processes,key=lambda p:owners.get(p.get('pid'),0),reverse=True)[:64]
    result=[];read_sources=0
    for observed in selected:
        try:
            process=host_metadata(observed['host_pid'])
            if process['pid']<1 or process['pid']!=observed['pid']:
                continue
            if owners.get(process['pid']) and read_sources<4:
                read_sources+=1
                try:
                    source=read_host_entrypoint(process)
                    if source is not None:
                        process['source']=source
                        resolve_targets(container,execute,process)
                except (OSError,ValueError,UnicodeError):
                    process['source_coverage']='unavailable'
            if host_metadata(process['host_pid'])['start_ticks']==process['start_ticks']:
                result.append(process)
        except (OSError,ValueError,isolation.QuarantineError):
            continue
    if not result:
        raise isolation.QuarantineError('no fresh kernel process metadata; not a clean observation')
    return result


def verify_host_processes(host_processes, findings):
    for process in host_processes:
        if not any(item.get('pid')==process.get('pid') and item.get('start_ticks')==process.get('start_ticks') for item in findings):
            continue
        try:
            current=host_metadata(process['host_pid'])
            if current['pid']==process['pid'] and current['start_ticks']==process['start_ticks']:
                return
        except (OSError,ValueError,isolation.QuarantineError):
            pass
    raise isolation.QuarantineError('offending kernel process incarnation is no longer fresh')


def verify_live_processes(container, execute, findings):
    """Check fresh PID incarnation before a destructive network operation."""
    sockets = [{'pid': item.get('pid'), 'direction': 'outbound'} for item in findings]
    ok, output = execute(container, process_script(sockets))
    if not ok:
        raise isolation.QuarantineError('fresh process verification unavailable; no new quarantine')
    current = {p['pid']: p['start_ticks'] for p in parse_processes(output)}
    if not any(current.get(item.get('pid')) == item.get('start_ticks') for item in findings):
        raise isolation.QuarantineError('offending process evidence is no longer fresh; no new quarantine')

