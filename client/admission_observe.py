"""Read-only kernel observations tied to a verified private container namespace."""
import ipaddress
import json
import os
import socket
import re
import subprocess
import time
from pathlib import Path
from urllib.parse import quote

try:
    from client import admission_policy as policy, network_quarantine as isolation
except ImportError:
    import admission_policy as policy
    import network_quarantine as isolation


def decode(value):
    raw=bytes.fromhex(value)
    raw=b''.join(raw[i:i+4][::-1] for i in range(0,len(raw),4))
    return policy.address(socket.inet_ntop(socket.AF_INET if len(raw)==4 else socket.AF_INET6,raw))


def incarnation(pid):
    if type(pid) is not int or pid<=1:
        raise ValueError('invalid init PID')
    for kind in ('pid','net'):
        if os.stat(f'/proc/{pid}/ns/{kind}').st_ino==os.stat(f'/proc/1/ns/{kind}').st_ino:
            raise ValueError('shared host namespace')
    text=Path(f'/proc/{pid}/stat').read_text()
    ticks=text.rsplit(')',1)[1].split()[19]
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    return f'{boot}:{os.stat(f"/proc/{pid}/ns/net").st_ino}:{ticks}'


def sockets(pid):
    epoch=incarnation(pid)
    entries=[]
    for name in ('tcp','tcp6','udp','udp6'):
        with open(f'/proc/{pid}/net/{name}',encoding='ascii') as stream:
            text=stream.read(8*1024*1024+1)
        if len(text)>8*1024*1024:
            raise ValueError('socket observation exceeds budget')
        for line in text.splitlines()[1:]:
            fields=line.split()
            if len(fields)<10:
                raise ValueError('incomplete socket observation')
            if name.startswith('udp'):
                continue
            state=fields[3]
            local,port=fields[1].split(':');remote,rport=fields[2].split(':')
            entries.append((state,local,int(port,16),remote,int(rport,16)))
    listen={port for state,_,port,_,_ in entries if state=='0A'}
    flows=set();inbound=[]
    for state,local,port,remote,rport in entries:
        if state not in {'01','02','03'}:
            continue
        try:laddr,raddr=decode(local),decode(remote)
        except ValueError:continue
        flows.add((laddr,port,raddr,rport))
        if (port in listen or state=='03') and raddr not in inbound:
            inbound.append(raddr)
    if epoch!=incarnation(pid):
        raise ValueError('container restarted during observation')
    return epoch,flows,inbound


def snapshot(container, runtime_bins, run, require_forward=True):
    runtime=container['runtime'];name=container['name'];project=container.get('project') or ''
    if runtime=='incus':
        api=isolation.IncusAPI(project)
        item,_=api.request('GET','/1.0/instances/'+quote(name,safe=''))
        identity=str(item.get('config',{}).get('volatile.uuid') or '')
        driver=isolation.IncusIsolation(api,name,identity)
        driver.inspect()
        if item.get('type','container')!='container':
            raise ValueError('VM networking needs a separate driver')
        state,_=api.request('GET','/1.0/instances/'+quote(name,safe='')+'/state')
        pid=int(state.get('pid') or 0)
        ips=[a['address'] for device in state.get('network',{}).values() for a in device.get('addresses',[]) if a.get('scope')=='global']
    elif runtime=='podman':
        binary=runtime_bins.get('podman')
        if not binary:raise ValueError('Podman unavailable')
        ok,output=run([binary,*isolation.podman_inspect_args(name)])
        if not ok:raise ValueError('Podman inspect unavailable')
        item=json.loads(output)[0]
        identity=str(item.get('Id') or '')
        expected=str(container.get('id') or '')
        if len(expected)<12 or not identity.startswith(expected):
            raise ValueError('Podman instance identity changed')
        mode=str(item.get('HostConfig',{}).get('NetworkMode') or '')
        if mode in {'host','none'} or mode.startswith(('container:','ns:','slirp','pasta')) or item.get('Pod'):
            raise ValueError('shared or non-forwarded Podman network')
        pid=int(item.get('State',{}).get('Pid') or 0)
        ips=[v.get(k) for v in item.get('NetworkSettings',{}).get('Networks',{}).values() for k in ('IPAddress','GlobalIPv6Address') if v.get(k)]
    else:raise ValueError('unsupported runtime')
    isolation.target(runtime,project,name,identity)
    ips=sorted(set(policy.address(x) for x in ips))
    if not ips:raise ValueError('private instance addresses unavailable')
    epoch,flows,inbound=sockets(pid)
    if not require_forward:
        return {'instance_id':identity,'ips':ips,'epoch':epoch,'flows':flows,'inbound':inbound,'pid':pid,'observed_at':int(time.time())}
    # Prove the host-side veth for every protected address. An address alone is
    # not an isolation boundary (different Incus projects can reuse a subnet).
    def links(args):
        value=subprocess.run(args,capture_output=True,text=True,timeout=3)
        if value.returncode or len(value.stdout)>1024*1024:
            raise ValueError('network interface proof unavailable')
        return json.loads(value.stdout)
    guest=links(['nsenter','-t',str(pid),'-n','ip','-d','-j','address','show'])
    host=links(['ip','-j','link','show'])
    peers={int(x['ifindex']):x for x in host}
    interfaces=set()
    proven=set()
    internal=set()
    for dev in guest:
        addresses={policy.address(a['local']) for a in dev.get('addr_info',[])
                   if a.get('scope')=='global'}
        if not addresses.intersection(ips):continue
        if dev.get('linkinfo',{}).get('info_kind') in {'bridge','dummy','tun','wireguard','vxlan','ifb'}:
            internal.update(addresses.intersection(ips));continue
        peer=peers.get(int(dev.get('link_index') or 0),{})
        name=str(peer.get('ifname') or '')
        # veth is required; macvlan, physical passthrough and routed host
        # namespaces need a different driver, never an address-only fallback.
        detail=links(['ip','-d','-j','link','show','dev',name]) if name else []
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',name) or not detail or detail[0].get('linkinfo',{}).get('info_kind')!='veth':
            raise ValueError('private veth ownership unavailable')
        master=peer.get('master')
        if master:
            bridge=next((x for x in host if x['ifindex']==master or x.get('ifname')==master),{})
            name=str(bridge.get('ifname') or '')
            detail=links(['ip','-d','-j','link','show','dev',name]) if name else []
            if not detail or detail[0].get('linkinfo',{}).get('info_kind')!='bridge':
                raise ValueError('unverified forwarding bridge')
        interfaces.add(name);proven.update(addresses.intersection(ips))
    if not proven or proven|internal!=set(ips) or epoch!=incarnation(pid):
        raise ValueError('incomplete or changed interface identity')
    return {'instance_id':identity,'ips':sorted(proven),'interfaces':sorted(interfaces),'epoch':epoch,'flows':flows,'inbound':inbound,'pid':pid,'observed_at':int(time.time())}
