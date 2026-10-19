"""Private nftables forward-only tables and bounded NFQUEUE admission.

No INPUT/OUTPUT hooks, no flush ruleset, no shell, no queue bypass. nftables
changes are atomic. A queue without its worker rejects unknown/new traffic.
"""
import ctypes as C
import ctypes.util
import hashlib
import ipaddress
import json
import os
import re
import select
import socket
import struct
import subprocess
import threading


def command(args, data=None):
    p = subprocess.run(args, input=data, capture_output=True, text=True, timeout=5)
    if p.returncode or len(p.stdout) > 2*1024*1024:
        raise RuntimeError('local admission command failed: '+args[0])
    return p.stdout


def packet(raw):
    if not raw:
        raise ValueError('empty packet')
    version = raw[0] >> 4
    if version == 4 and len(raw) >= 20:
        offset, proto = (raw[0] & 15)*4, raw[9]
        if offset < 20 or struct.unpack('!H',raw[6:8])[0] & 0x1fff:
            raise ValueError('fragment or invalid header')
        src, dst = socket.inet_ntop(2,raw[12:16]), socket.inet_ntop(2,raw[16:20])
    elif version == 6 and len(raw) >= 40:
        src, dst = socket.inet_ntop(10,raw[8:24]), socket.inet_ntop(10,raw[24:40])
        offset, proto = 40, raw[6]
        for _ in range(8):
            if proto in {6,17}:
                break
            if proto not in {0,43,60} or len(raw)<offset+2:
                raise ValueError('unsupported extension')
            nxt, length = raw[offset], (raw[offset+1]+1)*8
            offset += length
            proto = nxt
    else:
        raise ValueError('invalid IP header')
    if proto not in {6,17} or len(raw)<offset+4:
        raise ValueError('invalid transport')
    sport,dport = struct.unpack('!HH',raw[offset:offset+4])
    return src,dst,proto,sport,dport


def rules(table, ips, queue, sources, limited=False, management_ports=(), interfaces=()):
    if not re.fullmatch(r'nwguard_[a-f0-9]{16}',table) or not 20000<=queue<60000 or queue%2:
        raise ValueError('invalid rule identity')
    by_family = {4:[],6:[]}
    for value in ips:
        addr = ipaddress.ip_address(value)
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
            raise ValueError('unsafe container address')
        by_family[addr.version].append(str(addr))
    if not any(by_family.values()) or len(ips)>32:
        raise ValueError('container addresses unavailable')
    if not interfaces or len(interfaces)>8 or any(not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',x) for x in interfaces):
        raise ValueError('verified private veth required')
    devices='{ '+', '.join('"'+x+'"' for x in interfaces)+' }'
    allowed={4:[],6:[]}
    if len(sources)>5:
        raise ValueError('source capacity exceeded')
    for source in sources:
        addr=ipaddress.ip_address(source['ip'])
        allowed[addr.version].append(str(addr))
    lines=[f'add table inet {table}',
           f'add set inet {table} sources4 {{ type ipv4_addr; flags dynamic,timeout; timeout 90s; size 5; }}',
           f'add set inet {table} sources6 {{ type ipv6_addr; flags dynamic,timeout; timeout 90s; size 5; }}',
           f'add chain inet {table} incoming',f'add chain inet {table} outgoing',
           f'add chain inet {table} forward {{ type filter hook forward priority -20; policy accept; }}']
    for family, values in allowed.items():
        if values:
            lines.append(f'add element inet {table} sources{family} {{ '+', '.join(values)+' }')
    for family, values in by_family.items():
        if not values:
            continue
        kind='ip' if family==4 else 'ip6'
        values=', '.join(values)
        lines.append(f'add rule inet {table} forward oifname {devices} {kind} daddr {{ {values} }} ct direction original meta l4proto {{ tcp, udp }} jump incoming')
        if limited:
            lines.append(f'add rule inet {table} forward iifname {devices} {kind} saddr {{ {values} }} ct direction original meta l4proto tcp ct state new jump outgoing')
    ports=sorted(set(management_ports))
    if ports:
        if len(ports)>8 or any(type(p) is not int or not 1<=p<=65535 for p in ports):
            raise ValueError('invalid management ports')
        lines.append(f'add rule inet {table} incoming meta l4proto tcp tcp dport {{ '+', '.join(map(str,ports))+' } return')
    if limited:
        lines.append(f'add rule inet {table} incoming meta l4proto tcp ct state new queue num {queue}')
    for family in (4,6):
        kind='ip' if family==4 else 'ip6'
        lines.append(f'add rule inet {table} incoming {kind} saddr @sources{family} update @sources{family} {{ {kind} saddr timeout 90s }} return')
    lines.extend([f'add rule inet {table} incoming counter queue num {queue}',
                  f'add rule inet {table} outgoing counter queue num {queue+1}'])
    return '\n'.join(lines)+'\n'


class NFT:
    def __init__(self, runner=command):
        self.run=runner
        self.digests={}

    def apply(self, table, ips, queue, sources, limited=False, management_ports=(), interfaces=()):
        text=rules(table,ips,queue,sources,limited,management_ports,interfaces)
        try:
            self.run(['nft','list','table','inet',table])
        except RuntimeError:
            pass
        else:
            text=f'delete table inet {table}\n'+text
        self.run(['nft','--check','-f','-'],text)
        self.run(['nft','-f','-'],text)

    def admit(self, table, source):
        parsed=ipaddress.ip_address(source)
        self.run(['nft','add','element','inet',table,'sources'+str(parsed.version),'{',str(parsed),'}'])

    def live(self, table):
        value=json.loads(self.run(['nft','-j','list','table','inet',table]))
        def stable(item):
            if isinstance(item,list):return [stable(x) for x in item]
            if not isinstance(item,dict):return item
            return {k:({} if k=='counter' else stable(v)) for k,v in item.items() if k not in {'handle','index'}}
        definition=[]
        for item in value.get('nftables',[]):
            if 'metainfo' in item:continue
            item=stable(item)
            if 'set' in item:item['set'].pop('elem',None)
            definition.append(item)
        self.digests[table]=hashlib.sha256(json.dumps(definition,sort_keys=True).encode()).hexdigest()
        result=set()
        for item in value.get('nftables',[]):
            entry=item.get('set',{})
            if entry.get('name') not in {'sources4','sources6'}:
                continue
            for elem in entry.get('elem',[]):
                val=elem if isinstance(elem,str) else elem.get('elem',{}).get('val')
                try:result.add(str(ipaddress.ip_address(val)))
                except ValueError:pass
        return result

    def remove(self, table):
        if not re.fullmatch(r'nwguard_[a-f0-9]{16}',table):
            raise ValueError('invalid table')
        try:self.run(['nft','delete','table','inet',table])
        except RuntimeError:
            tables=json.loads(self.run(['nft','-j','list','tables']))
            if any(x.get('table',{}).get('family')=='inet' and x['table'].get('name')==table for x in tables.get('nftables',[])):raise


class Queues:
    def __init__(self, decide):
        library=ctypes.util.find_library('netfilter_queue')
        if not library:
            raise RuntimeError('libnetfilter_queue is unavailable')
        self.lib=C.CDLL(library)
        self.decide=decide
        self.handles={}
        self.lock=threading.RLock()
        definitions={
            'nfq_open':([],C.c_void_p), 'nfq_fd':([C.c_void_p],C.c_int),
            'nfq_bind_pf':([C.c_void_p,C.c_uint16],C.c_int),
            'nfq_set_mode':([C.c_void_p,C.c_uint8,C.c_uint32],C.c_int),
            'nfq_set_queue_maxlen':([C.c_void_p,C.c_uint32],C.c_int),
            'nfq_handle_packet':([C.c_void_p,C.c_void_p,C.c_int],C.c_int),
            'nfq_get_msg_packet_hdr':([C.c_void_p],C.c_void_p),
            'nfq_get_payload':([C.c_void_p,C.POINTER(C.c_void_p)],C.c_int),
            'nfq_set_verdict':([C.c_void_p,C.c_uint32,C.c_uint32,C.c_uint32,C.c_void_p],C.c_int),
            'nfq_destroy_queue':([C.c_void_p],C.c_int), 'nfq_close':([C.c_void_p],C.c_int)}
        for name,(args,result) in definitions.items():
            function=getattr(self.lib,name);function.argtypes=args;function.restype=result
        self.callback_type=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p)
        self.callback=self.callback_type(self._callback)
        self.lib.nfq_create_queue.argtypes=[C.c_void_p,C.c_uint16,self.callback_type,C.c_void_p]
        self.lib.nfq_create_queue.restype=C.c_void_p
        self.handle=self.lib.nfq_open()
        if not self.handle:
            raise RuntimeError('NFQUEUE handle unavailable')
        for family in (socket.AF_INET,socket.AF_INET6):
            if self.lib.nfq_bind_pf(self.handle,family)<0:
                self.lib.nfq_close(self.handle)
                raise RuntimeError('NFQUEUE protocol binding unavailable')
        self.fd=self.lib.nfq_fd(self.handle)
        self.stopped=threading.Event()
        self.thread=threading.Thread(target=self.loop,name='narwhal-admission-packets',daemon=True)
        self.thread.start()

    def add(self, number):
        with self.lock:
            if number in self.handles:
                return
            handle=self.lib.nfq_create_queue(self.handle,number,self.callback,C.c_void_p(number))
            if not handle:
                raise RuntimeError('admission queue number already in use')
            if self.lib.nfq_set_mode(handle,2,256)<0 or self.lib.nfq_set_queue_maxlen(handle,1024)<0:
                self.lib.nfq_destroy_queue(handle)
                raise RuntimeError('admission queue configuration unavailable')
            self.handles[number]=handle

    def _callback(self, handle, message, data, context):
        header=self.lib.nfq_get_msg_packet_hdr(data)
        if not header:
            return 0
        identity=struct.unpack('!I',C.string_at(header,4))[0]
        pointer=C.c_void_p()
        length=self.lib.nfq_get_payload(data,C.byref(pointer))
        accepted=False
        try:
            if length>0:
                accepted=self.decide(int(context or 0),C.string_at(pointer,min(length,256)))
        except Exception:
            pass
        if self.lib.nfq_set_verdict(handle,identity,1 if accepted else 0,0,None)<0:
            self.stopped.set()
        return 0

    def remove(self, number):
        with self.lock:
            handle=self.handles.pop(number,None)
            if handle:self.lib.nfq_destroy_queue(handle)

    def loop(self):
        while not self.stopped.is_set():
            try:
                # libnfqueue control calls synchronously receive ACKs on this
                # same socket. Never let the packet thread steal their replies.
                with self.lock:
                    ready,_,_=select.select([self.fd],[],[],.05)
                    if ready:
                        raw=os.read(self.fd,131072)
                        if not raw or self.lib.nfq_handle_packet(self.handle,C.create_string_buffer(raw),len(raw))<0:
                            self.stopped.set()
                # Let waiting queue-registration calls acquire the shared lock.
                self.stopped.wait(.001)
            except OSError:
                # Queue overflow is fail-closed; service supervisor restarts the
                # owning worker if its liveness check fails.
                self.stopped.set()

    def healthy(self):
        return self.thread.is_alive() and not self.stopped.is_set()

    def close(self):
        self.stopped.set()
        self.thread.join(timeout=2)
        with self.lock:
            for handle in self.handles.values():self.lib.nfq_destroy_queue(handle)
            self.handles.clear()
            self.lib.nfq_close(self.handle)
