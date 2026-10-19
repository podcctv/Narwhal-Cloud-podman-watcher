"""Exact PasarGuard-node identity; no broad main/node/xray process matching."""
import json
import os
import posixpath
import re
import struct
import threading
import time
from pathlib import Path

try:
    from client import abuse_collection, admission_observe, network_quarantine as isolation
except ImportError:
    import abuse_collection
    import admission_observe
    import network_quarantine as isolation

_results={}
_thread=None
EXEC_PATH=r'/(?:app|opt|usr/local/bin|var/lib|root|home|srv)/[A-Za-z0-9_./+-]{1,200}'


def image_match(value):
    if not isinstance(value,str):return False
    repo=value.lower().split('@',1)[0]
    if ':' in repo.rsplit('/',1)[-1]:repo=repo.rsplit(':',1)[0]
    return repo in {'pasarguard/node','docker.io/pasarguard/node','ghcr.io/pasarguard/node'}


def go_module(path):
    """Read bounded ELF Go build-info, not arbitrary strings or process argv."""
    with open(path,'rb') as stream:
        header=stream.read(64)
        if header[:4]!=b'\x7fELF' or header[5] not in (1,2):return ''
        endian='<' if header[5]==1 else '>'
        if header[4]==2:
            offset=struct.unpack_from(endian+'Q',header,40)[0]
            size,count,index=struct.unpack_from(endian+'HHH',header,58)
            fmt=endian+'IIQQQQIIQQ'
        elif header[4]==1:
            offset=struct.unpack_from(endian+'I',header,32)[0]
            size,count,index=struct.unpack_from(endian+'HHH',header,46)
            fmt=endian+'IIIIIIIIII'
        else:return ''
        if count>4096 or size!=struct.calcsize(fmt) or index>=count:return ''
        stream.seek(offset);sections=stream.read(size*count)
        if len(sections)!=size*count:return ''
        entries=[struct.unpack_from(fmt,sections,i*size) for i in range(count)]
        names_entry=entries[index]
        if names_entry[5]>1024*1024:return ''
        stream.seek(names_entry[4]);names=stream.read(names_entry[5])
        for entry in entries:
            name=names[entry[0]:].split(b'\0',1)[0]
            if name!=b'.go.buildinfo':continue
            if not 32<=entry[5]<=65536:return ''
            stream.seek(entry[4]);data=stream.read(entry[5])
            if data[:14]!=b'\xff Go buildinf:' or not data[15]&2:return ''
            position=32
            def text():
                nonlocal position
                length=0
                for shift in range(0,35,7):
                    part=data[position];position+=1;length|=(part&127)<<shift
                    if part<128:break
                if length>65536 or position+length>len(data):raise ValueError('invalid build info')
                value=data[position:position+length];position+=length
                return value
            text();module=text()
            # Go frames module data with two 16-byte sentinels. They are not
            # part of the first "path" line (notably in stripped releases).
            if len(module)>=33 and module[-17:-16]==b'\n':module=module[16:-16]
            module=module.decode('utf-8',errors='replace')
            if '\npath\tgithub.com/pasarguard/node/cmd/node\n' in '\n'+module:
                return 'github.com/pasarguard/node/cmd/node'
    return ''


def native_matches(pid):
    init_group=Path(f'/proc/{pid}/cgroup').read_text()
    root_ns=os.stat(f'/proc/{pid}/ns/pid').st_ino
    result=[]
    for item in abuse_collection.scoped_host_processes(pid)[:256]:
        host_pid=int(item.get('host_pid') or item.get('pid') or 0)
        if host_pid<=1:continue
        try:
            if os.stat(f'/proc/{host_pid}/ns/pid').st_ino!=root_ns:continue
            if not go_module(f'/proc/{host_pid}/exe'):continue
            metadata=abuse_collection.host_metadata(host_pid)
            status=Path(f'/proc/{host_pid}/status').read_text()
            inner=int(re.search(r'^NSpid:\s+([\d\s]+)$',status,re.M)[1].split()[-1])
            executable=os.readlink(f'/proc/{host_pid}/exe').removesuffix(' (deleted)')
            if inner<=1 or not re.fullmatch(EXEC_PATH,executable) or posixpath.normpath(executable)!=executable:continue
            group=Path(f'/proc/{host_pid}/cgroup').read_text()
            unit=''
            initial=init_group.strip().split(':',2)[-1].rstrip('/')
            current=group.strip().split(':',2)[-1]
            if current.startswith(initial+'/'):
                candidates=[p for p in current[len(initial):].split('/') if re.fullmatch(r'[A-Za-z0-9_@.-]+\.service',p)]
                if candidates:unit=candidates[-1]
            result.append({'pid':inner,'host_pid':host_pid,'start_ticks':metadata['start_ticks'],
                           'executable':executable,'unit':unit,'module':'github.com/pasarguard/node/cmd/node'})
        except (OSError,ValueError,TypeError,IndexError):continue
    return result[:8]


def cleanup_script(finding):
    pid=int(finding['pid']);ticks=str(finding['start_ticks']);exe=finding['executable'];unit=finding.get('unit','')
    if pid<=1 or not ticks.isdigit() or not re.fullmatch(EXEC_PATH,exe) or posixpath.normpath(exe)!=exe:
        raise ValueError('invalid exact software scope')
    if unit and not re.fullmatch(r'[A-Za-z0-9_@.-]+\.service',unit):raise ValueError('invalid service scope')
    # Paths are fixed/validated; data volumes and the outer instance stay intact.
    return f'''set -eu
p={pid}; expected={ticks}; exe='{exe}'; unit='{unit}'
[ -r /proc/$p/stat ] || exit 0
line=$(cat /proc/$p/stat); rest=${{line##*) }}; actual=$(printf '%s' "$rest" | awk '{{print $20}}')
[ "$actual" = "$expected" ] || exit 31
case "$(readlink /proc/$p/exe)" in "$exe"|"$exe (deleted)") :;; *) exit 32;; esac
backup=/var/lib/narwhal-disabled-pasarguard
[ ! -L "$backup" ] || exit 37
mkdir -p "$backup"; chmod 700 "$backup"
if [ -n "$unit" ] && command -v systemctl >/dev/null 2>&1; then
 launch=$(systemctl show --property=ExecStart --value "$unit" 2>/dev/null || true)
 case "$launch" in *"path=$exe ;"*)
  systemctl disable --now "$unit" >/dev/null 2>&1 || exit 33
  for base in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
   if [ -f "$base/$unit" ] && [ ! -L "$base/$unit" ]; then mv -- "$base/$unit" "$backup/$unit.$expected"; fi
  done
  systemctl daemon-reload;;
 esac
fi
for base in /etc/init.d /etc/supervisor/conf.d; do
 [ -d "$base" ] || continue
 for f in "$base"/*; do
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  grep -Fq -- "$exe" "$f" || continue
  grep -Eiq 'pasarguard|pg-node' "$f" || continue
  service=${{f##*/}}
  case "$service" in *pasarguard*|*pg-node*) :;; *) continue;; esac
  if [ "$base" = /etc/init.d ]; then
   command -v rc-service >/dev/null 2>&1 && rc-service "$service" stop >/dev/null 2>&1 || true
   command -v rc-update >/dev/null 2>&1 && rc-update del "$service" >/dev/null 2>&1 || true
  else command -v supervisorctl >/dev/null 2>&1 && supervisorctl stop "$service" >/dev/null 2>&1 || true; fi
  mv -- "$f" "$backup/$service.$expected"
 done
done
for base in /etc/cron.d /var/spool/cron/crontabs; do
 [ -d "$base" ] || continue
 for f in "$base"/*; do
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  grep -Fq -- "$exe" "$f" || continue
  grep -Eiq 'pasarguard|pg-node' "$f" || continue
  tmp=$(mktemp)
  awk -v exe="$exe" '!(index($0,exe) && tolower($0) ~ /pasarguard|pg-node/)' "$f" > "$tmp"
  cp -p -- "$f" "$backup/cron.${{f##*/}}.$expected"
  cat "$tmp" > "$f"; rm -f -- "$tmp"
 done
done
if [ -r /proc/$p/stat ]; then
 line=$(cat /proc/$p/stat); rest=${{line##*) }}
 [ "$(printf '%s' "$rest" | awk '{{print $20}}')" = "$expected" ] || exit 34
 kill -TERM "$p"
 for n in 1 2 3 4 5 6 7 8 9 10; do [ -d /proc/$p ] || break; sleep 1; done
 if [ -r /proc/$p/stat ]; then
  line=$(cat /proc/$p/stat); rest=${{line##*) }}
  [ "$(printf '%s' "$rest" | awk '{{print $20}}')" = "$expected" ] || exit 35
  kill -KILL "$p"
 fi
fi
if [ -f "$exe" ] && [ ! -L "$exe" ]; then mv -- "$exe" "$backup/program.$expected"; fi
[ ! -e /proc/$p/exe ] || exit 36
printf 'PasarGuard node service removed; private rollback files retained; outer instance preserved'
'''


def nested_script():
    # Runs only through a verified Incus/Podman guest exec, never on the mother.
    return '''set -eu
unset DOCKER_HOST DOCKER_CONTEXT
count=0
for runtime in docker; do
 command -v "$runtime" >/dev/null 2>&1 || continue
 ids=$("$runtime" --host unix:///var/run/docker.sock ps -aq --no-trunc) || exit 41
 for id in $ids; do
  case "$id" in *[!a-f0-9]*|'') exit 42;; esac
  image=$("$runtime" --host unix:///var/run/docker.sock inspect --format '{{.Config.Image}}' "$id") || exit 43
  repo=${image%%@*}; repo=${repo%:*}
  case "$repo" in pasarguard/node|docker.io/pasarguard/node|ghcr.io/pasarguard/node)
   "$runtime" --host unix:///var/run/docker.sock update --restart=no "$id" >/dev/null || exit 44
   "$runtime" --host unix:///var/run/docker.sock stop --time 10 "$id" >/dev/null || exit 45
   "$runtime" --host unix:///var/run/docker.sock rm "$id" >/dev/null || exit 46
   count=$((count+1));;
  esac
 done
done
printf 'NW_PASAR_REMOVED=%s\\n' "$count"
'''


def private_docker(pid):
    """Never follow a mother's bind-mounted Docker socket into host services."""
    try:
        nested=os.stat(f'/proc/{pid}/root/var/run/docker.sock')
        try:
            mother=os.stat('/var/run/docker.sock')
            if (nested.st_dev,nested.st_ino)==(mother.st_dev,mother.st_ino):return False
        except FileNotFoundError:pass
        return any(item.get('process')=='dockerd' for item in abuse_collection.scoped_host_processes(pid))
    except OSError:return False


def start(inventory,provider,runner,runtime_bins,guest_exec,emit):
    global _thread
    if os.name!='posix' or any(os.getenv(k,'true').lower() in {'false','0','off','no'} for k in ('SECURITY_PASARGUARD_BAN_ENABLED','SECURITY_MONITOR_ENABLED')):return
    if _thread and _thread.is_alive():return
    def work():
        while True:
            try:targets=inventory()
            except Exception:time.sleep(30);continue
            for container in targets:
                if container.get('runtime') not in {'incus','podman'} or container.get('name') in isolation.PROTECTED:continue
                key=(container['runtime'],container.get('project') or '',container['name'])
                identity='';receipt=[];confirmed=False
                try:
                    snap=provider(container)
                    identity=snap['instance_id']
                    if container['runtime']=='podman':
                        binary=runtime_bins().get('podman')
                        ok,image=runner([binary,'inspect','--format','{{.ImageName}}',identity])
                        if ok and image_match(image.strip()):
                            confirmed=True
                            # Disable restart before stopping exactly the inspected
                            # container. No compose down, prune, rm -v or Docker.
                            for args in ([binary,'update','--restart=no',identity],[binary,'stop','--time','10',identity]):
                                success,_=runner(args)
                                if not success:raise RuntimeError('exact Podman service cleanup failed')
                            receipt=[{'kind':'service','target':identity,'status':'ok'}]
                    if not receipt:
                        matches=native_matches(snap['pid'])
                        confirmed=bool(matches)
                        for finding in matches:
                            fresh=provider(container)
                            if fresh['instance_id']!=identity or fresh['epoch']!=snap['epoch']:raise ValueError('instance changed')
                            ok,_=guest_exec(container,cleanup_script(finding))
                            receipt.append({'kind':'service','target':finding['unit'] or finding['executable'],'status':'ok' if ok else 'failed'})
                        fresh=provider(container)
                        if fresh['instance_id']!=identity or fresh['epoch']!=snap['epoch']:raise ValueError('instance changed')
                        ok,output=guest_exec(container,nested_script()) if private_docker(snap['pid']) else (True,'NW_PASAR_REMOVED=0')
                        match=re.search(r'^NW_PASAR_REMOVED=(\d+)$',output,re.M) if ok else None
                        if match and int(match[1]):
                            confirmed=True
                            receipt.append({'kind':'service','target':'pasarguard/node','status':'ok'})
                        if matches and native_matches(snap['pid']):
                            receipt.append({'kind':'service','target':'pasarguard-node-surviving-process','status':'failed'})
                        if not confirmed:continue
                    cleaned=bool(receipt) and all(x['status']=='ok' for x in receipt)
                    _results[key]={'type':'pasarguard_node_removed','severity':'critical','runtime':container['runtime'],
                        'project':container.get('project') or '', 'container_name':container['name'],'instance_id':identity,
                        'title':'禁止运行 PasarGuard Node：'+('已清理服务' if cleaned else '清理失败'),
                        'message':'已停止并移除确认归属的 PasarGuard Node 服务；未删除客户实例或磁盘。' if cleaned else 'PasarGuard Node 清理未全部成功，需管理员处理。',
                        'automatic_remediation':{'attempted':True,'succeeded':cleaned,'items':receipt},
                        'value':len(receipt),'threshold':0,'observed_at':int(time.time())}
                    try:emit(container,_results[key])
                    except Exception:pass
                except Exception:
                    # Do not kill generic binaries or disclose raw runtime output.
                    if confirmed:
                        _results[key]={'type':'pasarguard_node_removed','severity':'critical','runtime':container['runtime'],
                            'project':container.get('project') or '', 'container_name':container['name'],'instance_id':identity,
                            'title':'PasarGuard Node 清理未完成','message':'已确认禁止服务，但执行或复查失败，需要管理员处理。',
                            'automatic_remediation':{'attempted':True,'succeeded':False,'items':receipt},
                            'observed_at':int(time.time()),'value':1,'threshold':0}
                        try:emit(container,_results[key])
                        except Exception:pass
                    continue
            now=time.time()
            for key in list(_results):
                if now-_results[key]['observed_at']>86400:_results.pop(key,None)
            time.sleep(30)
    _thread=threading.Thread(target=work,name='narwhal-pasarguard-ban',daemon=True);_thread.start()


def alerts(container):
    value=_results.get((container['runtime'],container.get('project') or '',container['name']))
    return [dict(value)] if value and time.time()-value['observed_at']<900 else []
