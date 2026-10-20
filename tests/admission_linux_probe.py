"""Privileged integration probe, invoked ONLY inside an isolated network namespace.

Run: unshare --net --mount --fork --propagation private python3 tests/admission_linux_probe.py
No host interfaces, host rules or customer instances are used.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from client import admission_guard as guard, admission_observe as observe


def run(*args):
    return subprocess.check_output(list(args),text=True,stderr=subprocess.STDOUT,timeout=8).strip()


def main():
    # Refuse a probe in the mother's initial namespace even when run by root.
    assert os.geteuid()==0 and os.stat('/proc/self/ns/net').st_ino!=os.stat('/proc/1/ns/net').st_ino
    assert len(json.loads(run('ip','-j','link')))==1,'isolated empty network namespace required'
    os.makedirs('/run/netns',exist_ok=True)
    run('mount','-t','tmpfs','-o','mode=755','tmpfs','/run/netns')
    children=[];queues=None
    try:
        for ns in ('nwtest-client','nwtest-target'):run('ip','netns','add',ns)
        for host,peer,ns in (('nwtest-in','eth0','nwtest-client'),('nwtest-out','eth0','nwtest-target')):
            run('ip','link','add',host,'type','veth','peer','name',host+'p')
            run('ip','link','set',host+'p','netns',ns)
            run('ip','-n',ns,'link','set',host+'p','name',peer)
            run('ip','link','set',host,'up');run('ip','-n',ns,'link','set',peer,'up');run('ip','-n',ns,'link','set','lo','up')
        run('ip','link','add','nwtest-br','type','bridge')
        run('ip','link','set','nwtest-out','master','nwtest-br');run('ip','link','set','nwtest-br','up')
        for dev,ip in (('nwtest-in','192.0.2.1/24'),('nwtest-br','10.244.239.1/24')):run('ip','addr','add',ip,'dev',dev)
        for dev,ip in (('nwtest-in','2001:db8:1::1/64'),('nwtest-br','2001:db8:2::1/64')):run('ip','-6','addr','add',ip,'dev',dev,'nodad')
        for n in (11,12,13,14,15,99):
            run('ip','-n','nwtest-client','addr','add',f'192.0.2.{n}/24','dev','eth0')
            run('ip','-n','nwtest-client','-6','addr','add',f'2001:db8:1::{n}/64','dev','eth0','nodad')
        for ip in ('10.244.239.2/24','10.244.239.3/24'):run('ip','-n','nwtest-target','addr','add',ip,'dev','eth0')
        run('ip','-n','nwtest-target','-6','addr','add','2001:db8:2::2/64','dev','eth0','nodad')
        for ns,gateway,gateway6 in (('nwtest-client','192.0.2.1','2001:db8:1::1'),('nwtest-target','10.244.239.1','2001:db8:2::1')):
            run('ip','-n',ns,'route','add','default','via',gateway)
            run('ip','-n',ns,'-6','route','add','default','via',gateway6)
        run('sysctl','-qw','net.ipv4.ip_forward=1');run('sysctl','-qw','net.ipv6.conf.all.forwarding=1')
        run('ip','link','set','lo','up')
        server='''import asyncio,socket
async def echo(reader,writer):
 try:
  while data:=await reader.read(32):writer.write(data);await writer.drain()
 finally:writer.close()
async def main():
 a=await asyncio.start_server(echo,'0.0.0.0',45556)
 b=await asyncio.start_server(echo,'::',45556,family=socket.AF_INET6)
 print('ready',flush=True)
 await asyncio.Event().wait()
asyncio.run(main())'''
        for ns in ('nwtest-target','nwtest-client'):
            process=subprocess.Popen(['ip','netns','exec',ns,sys.executable,'-u','-c',server],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(process);assert process.stdout.readline().strip()=='ready'
        target_pid=children[0].pid
        def connect(source,destination,ns='nwtest-client',quiet=False):
            code="import socket,sys;s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET);s.settimeout(2);s.bind((sys.argv[1],0));s.connect((sys.argv[2],45556));s.sendall(b'ok');assert s.recv(2)==b'ok';s.close()"
            result=subprocess.run(['ip','netns','exec',ns,sys.executable,'-c',code,source,destination],capture_output=True,timeout=4)
            if result.returncode and not quiet:print('CONNECT FAIL',source,destination,result.stderr.decode(),flush=True)
            return result.returncode==0
        # Cold bridge/NDP setup may discard its first SYN before neighbours are
        # resolved. Warm only the unfiltered baseline; enforcement has no retry.
        if not any(connect('2001:db8:1::11','2001:db8:2::2',quiet=True) for _ in range(3)):
            for args in [('ip','-6','route'),('ip','-n','nwtest-client','-6','route'),('ip','-n','nwtest-target','-6','route'),('ip','-6','neigh'),('ip','-n','nwtest-target','-6','neigh'),('ip','netns','exec','nwtest-target','ss','-6','-ltn'),('sysctl','net.ipv6.conf.all.forwarding','net.ipv6.conf.nwtest-in.forwarding','net.ipv6.conf.nwtest-out.forwarding')]:print(args,run(*args),flush=True)
            for ns in ('nwtest-client','nwtest-target'):
                print(ns,'snmp6', {k:int(v) for k,v in (line.split() for line in run('ip','netns','exec',ns,'cat','/proc/net/snmp6').splitlines()) if int(v)},flush=True)
            raise AssertionError('IPv6 baseline route failed')
        with tempfile.TemporaryDirectory(prefix='narwhal-admission-probe-') as directory:
            print('PROBE guard-register',flush=True)
            g=guard.Guard(journal=guard.isolation.Journal(str(Path(directory)/'journal.json')))
            original=g.decision
            def traced(*args):
                try:return original(*args)
                except Exception as error:print('QUEUE ERROR',type(error).__name__,str(error),flush=True);raise
            g.decision=traced
            c={'runtime':'incus','project':'test','name':'isolated-probe'}
            snap={'instance_id':'a'*36,'ips':['10.244.239.2','2001:db8:2::2'],'interfaces':['nwtest-br'],'epoch':'probe:net:pid','flows':set(),'inbound':[]}
            g.update(c,snap);queues=g.queues
            print('PROBE sources',flush=True)
            five=['192.0.2.11','2001:db8:1::11','192.0.2.12','2001:db8:1::12','192.0.2.13']
            for source in five:assert connect(source,'2001:db8:2::2' if ':' in source else '10.244.239.2'),source
            assert connect('192.0.2.14','10.244.239.2'),'sixth IPv4 source incorrectly blocked by IP count'
            assert connect('2001:db8:1::14','2001:db8:2::2'),'sixth IPv6 source incorrectly blocked by IP count'
            assert connect(five[0],'10.244.239.2'),'existing source lost'
            assert connect('192.0.2.14','10.244.239.3'),'unrelated destination affected'
            assert connect('10.244.239.2','192.0.2.99','nwtest-target'),'outbound reply incorrectly treated as incoming source'
            state=next(iter(g.states.values()));record=next(iter(g.records.values()))
            print('PROBE tcp-cap',flush=True)
            assert len(state.data['sources'])<=5
            # 500 real open sockets, followed by an actual rejected 501st flow.
            hold="import socket,sys;s=[]\nfor i in range(500):\n c=socket.socket();c.settimeout(2);c.bind(('192.0.2.11',0));c.connect(('10.244.239.2',45556));c.sendall(b'x');assert c.recv(1)==b'x';s.append(c)\nprint('500-ready',flush=True)\nsys.stdin.readline();s.pop().close();print('499-ready',flush=True);sys.stdin.readline()"
            process=subprocess.Popen(['ip','netns','exec','nwtest-client',sys.executable,'-u','-c',hold],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(process);assert process.stdout.readline().strip()=='500-ready'
            def refresh():
                with mock.patch.object(observe,'incarnation',return_value='probe:net:pid'):
                    _,flows,inbound=observe.sockets(target_pid)
                state.observe(flows,inbound,set(five),int(time.time())+1,epoch='probe:net:pid')
                record['verified_at']=int(time.time())
            refresh();assert len(state.flows)==500,len(state.flows)
            state.data.update(limited=True,limited_since=int(time.time()),review_at=int(time.time())+1800)
            g.nft.apply(record['table'],record['ips'],record['queue'],state.data['sources'],True,interfaces=record['interfaces'])
            assert not connect(five[0],'10.244.239.2',quiet=True),'501st TCP flow unexpectedly admitted'
            process.stdin.write('close\n');process.stdin.flush();assert process.stdout.readline().strip()=='499-ready'
            time.sleep(1.1);refresh();assert len(state.flows)==499,len(state.flows)
            assert connect(five[0],'10.244.239.2'),'available 500th TCP slot rejected'
            print(json.dumps({'ok':True,'source_count_never_blocks':True,'source_sample_bounded':True,'outbound_reply_allowed':True,'unrelated_target_allowed':True,'tcp_501_blocked':True,'tcp_free_slot_allowed':True,'scope':'isolated namespaces only'}),flush=True)
            g.nft.remove(record['table'])
    finally:
        for process in reversed(children):
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
        if queues:queues.close()
        for ns in ('nwtest-client','nwtest-target'):
            subprocess.run(['ip','netns','delete',ns],capture_output=True)


if __name__=='__main__':main()
