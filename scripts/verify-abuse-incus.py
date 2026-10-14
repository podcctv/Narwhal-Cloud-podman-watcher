#!/usr/bin/env python3
"""Opt-in Incus canary using a LOCAL cached image, no tenant cloning.

Creates its own bridge/profile/two containers; no existing profile/network edits.
Tests IPv4/IPv6 ingress/egress, host proxy, live PID/data and exact restoration.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--image', required=True, help='local image with Python or busybox httpd; never a remote alias')
    parser.add_argument('--pool', required=True)
    parser.add_argument('--module', required=True)
    parser.add_argument('--existing-network', help='attach lab instances without changing/deleting this network')
    parser.add_argument('--keep-on-failure', action='store_true', help='retain only owned lab resources for diagnosis')
    args = parser.parse_args()
    if not args.run or not all(c in '0123456789abcdef' for c in args.image) or len(args.image) < 12:
        parser.error('--run and local image fingerprint required')
    spec = importlib.util.spec_from_file_location('canary_quarantine', args.module)
    q = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(q)

    def command(argv, check=True, input=''):
        # Incus create commands accept redirected YAML. Send explicit EOF so a
        # persistent SSH channel is never mistaken for a still-open config file.
        result = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=90)
        if check and result.returncode:
            raise RuntimeError('canary operation failed: '+str(argv[:4])+' '+result.stderr[:500])
        return result

    command(['incus', 'image', 'info', args.image])
    suffix = uuid.uuid4().hex[:10]
    network = args.existing_network or 'nwq'+suffix  # Linux bridge interface names must fit 15 bytes.
    profile, victim, sibling = ['nw-isolation-lab-'+suffix+'-'+kind for kind in ('profile','victim','peer')]
    routes = json.loads(command(['ip','-j','route','show','table','all']).stdout)
    occupied = []
    for route in routes:
        try:
            value = ipaddress.ip_network(route.get('dst',''), strict=False)
            if value.prefixlen:
                occupied.append(value)
        except ValueError:
            pass
    subnet = ipaddress.ip_network('10.'+str(200+int(suffix[:2],16)%54)+'.'+str(int(suffix[2:4],16))+'.0/29')
    if any(subnet.overlaps(value) for value in occupied if value.version == 4):
        raise RuntimeError('canary subnet overlaps an existing route; no network mutation')
    ipv4 = str(subnet.network_address+1)+'/29'
    ipv6 = 'fd78:'+suffix[:4]+':'+suffix[4:8]+':1::1/64'
    created = []
    created_network = created_profile = False
    succeeded = False
    api = q.IncusAPI('default')
    proof = []
    http_engines = {}
    def mark(name, condition):
        if not condition:
            raise AssertionError(name)
        proof.append(name)
        print('PASS '+name, flush=True)
    def state(name):
        return api.request('GET', '/1.0/instances/'+name+'/state')[0]
    def addresses(name):
        values = [v for item in (state(name).get('network') or {}).values() for v in item.get('addresses', []) if v.get('scope') == 'global']
        v4 = next((v['address'] for v in values if v.get('family') == 'inet'), '')
        v6 = next((v['address'] for v in values if v.get('family') == 'inet6'), '')
        return v4, v6
    def probe(source, address):
        if not address:
            return False
        url = 'http://'+('['+address+']' if ':' in address else address)+':8080/'
        if http_engines.get(source) == 'python':
            code = "import sys,urllib.request;o=urllib.request.build_opener(urllib.request.ProxyHandler({}));r=o.open(sys.argv[1],timeout=2);assert r.status==200"
            return command(['incus','exec',source,'--','python3','-c',code,url],check=False).returncode == 0
        return command(['incus','exec',source,'--','env','-u','http_proxy','-u','https_proxy',
                        'busybox','wget','-T','2','-q','-O','/dev/null',url], check=False).returncode == 0
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1',0))
        port = reservation.getsockname()[1]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def proxy_probe():
        try:
            with opener.open('http://127.0.0.1:'+str(port)+'/', timeout=2) as response:
                return response.status == 200
        except OSError:
            return False
    marker = 'synthetic-isolation-evidence-'+suffix
    def digest():
        return command(['incus','exec',victim,'--','sha256sum','/var/lib/narwhal-canary/index.html']).stdout.split()[0]
    try:
        if args.existing_network:
            command(['incus','network','show',network])
        else:
            command(['incus','network','create',network,'ipv4.address='+ipv4,'ipv6.address='+ipv6,'ipv4.nat=false','ipv6.nat=false'])
            created_network = True
        command(['incus','profile','create',profile])
        created_profile = True
        command(['incus','profile','edit',profile], input=json.dumps({'config':{'limits.memory':'128MiB'},
            'description':'Temporary Narwhal network-isolation canary; no tenant data',
            'devices':{'root':{'type':'disk','path':'/','pool':args.pool},'eth0':{'type':'nic','network':network}}}))
        with tempfile.TemporaryDirectory(prefix='nw-incus-marker-') as directory:
            sample = Path(directory)/'index.html'
            sample.write_text(marker)
            for name in (victim,sibling):
                command(['incus','init',args.image,name,'--profile',profile])
                created.append(name)
                command(['incus','start',name])
                # cloud-init may clean /tmp during first boot; use a test-owned
                # persistent directory inside this fresh disposable instance.
                command(['incus','exec',name,'--','mkdir','-p','/var/lib/narwhal-canary'])
                command(['incus','file','push',str(sample),name+'/var/lib/narwhal-canary/index.html'])
                if command(['incus','exec',name,'--','python3','--version'],check=False).returncode == 0:
                    http_engines[name] = 'python'
                    command(['incus','exec',name,'--','sh','-c',
                             'python3 -m http.server 8080 --bind :: --directory /var/lib/narwhal-canary </dev/null >/var/log/narwhal-canary-http.log 2>&1 &'])
                else:
                    http_engines[name] = 'busybox'
                    command(['incus','exec',name,'--','busybox','httpd','-p','[::]:8080','-h','/var/lib/narwhal-canary'])
            for _ in range(80):
                a4,a6 = addresses(victim)
                b4,b6 = addresses(sibling)
                if all((a4,a6,b4,b6)) and probe(sibling,a4) and probe(victim,b4):
                    break
                time.sleep(.5)
            flows = [('ingress_ipv4',sibling,a4),('ingress_ipv6',sibling,a6),
                     ('egress_ipv4',victim,b4),('egress_ipv6',victim,b6)]
            for label,source,address in flows:
                mark('baseline_'+label,probe(source,address))
            command(['incus','config','device','add',victim,'canary-forward','proxy',
                     'listen=tcp:127.0.0.1:'+str(port),'connect=tcp:127.0.0.1:8080'])
            mark('baseline_proxy_ingress',proxy_probe())
            item,_ = api.request('GET','/1.0/instances/'+victim)
            identity = item['config']['volatile.uuid']
            original_devices = item['devices']
            original_pid = state(victim)['pid']
            expected_digest = hashlib.sha256(marker.encode()).hexdigest()
            driver = q.IncusIsolation(api,victim,identity)
            journal = q.Journal(str(Path(directory)/'quarantine.json'))
            key = q.target('incus','default',victim,identity)
            q.quarantine(journal,key,driver,[{'kind':'outbound_scan','confidence':'high','pid':22,
                'start_ticks':'123','basis':'controlled_synthetic_lab','features':{'corroborating_samples':2}}])
            for label,source,address in flows:
                mark('isolated_'+label,not probe(source,address))
            mark('isolated_proxy_ingress',not proxy_probe())
            mark('sibling_ipv4_unaffected',probe(sibling,b4))
            mark('sibling_ipv6_unaffected',probe(sibling,b6))
            mark('same_live_container_pid',state(victim)['pid'] == original_pid)
            mark('disk_data_preserved',digest() == expected_digest)
            q.quarantine(journal,key,driver,[])  # Existing journal survives quiet traffic.
            mark('persistent_isolation',not probe(victim,b4))
            q.release(journal,key,driver)
            for _ in range(60):
                # IPv6 DAD/RA may complete later than IPv4 DHCP. Do not declare
                # readiness from IPv4 alone, then falsely fail a healthy restore.
                if all(probe(source,address) for _,source,address in flows):
                    break
                time.sleep(.5)
            for label,source,address in flows:
                mark('restored_'+label,probe(source,address))
            mark('restored_proxy_ingress',proxy_probe())
            item,_ = api.request('GET','/1.0/instances/'+victim)
            mark('local_devices_exactly_restored',item['devices'] == original_devices)
            mark('disk_data_preserved_after_release',digest() == expected_digest)
            mark('recovery_record_cleared',journal.read() == {})
            print(json.dumps({'result':'passed','checks':proof,'synthetic_only':True}),flush=True)
            succeeded = True
    finally:
        if args.keep_on_failure and not succeeded:
            print(json.dumps({'owned_lab_resources':created,'profile':profile,'network':network,
                'created_profile':created_profile,'created_network':created_network}),flush=True)
        else:
            for name in reversed(created):
                command(['incus','delete','--force',name],check=False)
            if created_profile:
                command(['incus','profile','delete',profile],check=False)
            if created_network:
                command(['incus','network','delete',network],check=False)


if __name__ == '__main__':
    main()
