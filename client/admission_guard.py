"""Bounded independent local guard for Incus/Podman. Never controls Docker.

Each private forward table is bound to immutable instance identity and addresses.
Notification failures do not roll back enforcement. The recovery journal contains
policy facts only, never argv, passwords or environment values.
"""
import copy
import hashlib
import ipaddress
import json
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    from client import admission_policy as policy, admission_linux as linux, network_quarantine as isolation, admission_observe as observation
except ImportError:
    import admission_policy as policy
    import admission_linux as linux
    import network_quarantine as isolation
    import admission_observe as observation


def failure_details(error, stage):
    """Return bounded, non-sensitive diagnostics for operator-facing receipts."""
    if stage == 'ownership':
        return 'ambiguous_ownership', 'ownership', '容器地址或宿主机接口无法唯一归属；未确认保护规则已生效'
    if isinstance(error, observation.UnsupportedNetwork):
        return 'unsupported_network', 'sampling', '容器网络模式不在当前自动保护支持范围'
    if isinstance(error, subprocess.TimeoutExpired):
        return 'sample_timeout', 'sampling', '容器网络采样命令超时'
    if isinstance(error, PermissionError):
        return 'permission_denied', stage if stage in {'startup', 'sampling', 'ownership', 'enforcement'} else 'enforcement', 'Agent 缺少读取网络或应用防火墙规则所需的权限'
    if isinstance(error, FileNotFoundError):
        return 'dependency_unavailable', stage if stage in {'startup', 'sampling', 'ownership', 'enforcement'} else 'enforcement', 'Agent 依赖的网络工具或内核接口不可用'
    if isinstance(error, RuntimeError):
        if stage == 'sampling':
            return 'sample_failed', 'sampling', 'Incus/Podman 或网络采样接口返回失败'
        return 'firewall_apply_failed', 'enforcement', 'nftables/NFQUEUE 规则应用或内核读回失败'
    if isinstance(error, ValueError):
        if stage == 'sampling':
            return 'sample_invalid', 'sampling', '网络采样数据不完整或无效'
        return 'firewall_apply_failed', 'enforcement', '保护规则配置无效，未能完成应用或验证'
    return 'worker_error', stage if stage in {'startup', 'sampling', 'ownership', 'enforcement'} else 'enforcement', '保护检查未完成，具体原因无法归类'


class Guard:
    def __init__(self, journal=None, nft=None, queues=None):
        self.journal=journal or isolation.Journal('/var/lib/narwhal-monitor/admission.json')
        self.records=self.journal.read()
        self.nft=nft or linux.NFT()
        self.queues=queues
        self.states={key:policy.Policy(value.get('policy')) for key,value in self.records.items()}
        self.by_queue={}
        self.lock=threading.RLock()
        self.results={}
        self.notifications={}
        self.ready=False

    def save(self):
        for key,state in self.states.items():
            if key in self.records:
                self.records[key]['policy']=state.data
        self.journal.write(self.records)

    def decision(self, queue, raw):
        src,dst,proto,sport,dport=linux.packet(raw)
        now=int(time.time())
        with self.lock:
            key,direction=self.by_queue[queue]
            record=self.records[key]
            state=self.states[key]
            if now-record.get('verified_at',0)>30:
                return False
            if (dst if direction=='in' else src) not in record['ips']:
                return False
            flow=(dst,dport,src,sport) if direction=='in' else (src,sport,dst,dport)
            if proto==6 and not state.admit_tcp(flow,now):
                return False
            if direction=='out':
                return True
            # Source addresses are not authenticated users. A scanner, NAT,
            # mobile hand-off, or legitimate multi-egress client can all
            # produce multiple IPs; only the separate TCP concurrency rule
            # may reject a flow here.
            return True

    def start(self):
        if self.ready:
            if not self.queues.healthy():
                self.queues.close()
                self.queues=linux.Queues(self.decision)
                self.ready=False
            else:
                return
        self.queues=self.queues or linux.Queues(self.decision)
        self.ready=True

    def update(self, container, snapshot, now=None):
        now=int(time.time()) if now is None else now
        runtime,project,name=container['runtime'],container.get('project') or '',container['name']
        identity=str(snapshot['instance_id'])
        key=isolation.target(runtime,project,name,identity)
        ips=sorted(set(map(policy.address,snapshot['ips'])))
        interfaces=snapshot.get('interfaces') or []
        if not ips or len(ips)>32 or snapshot.get('shared_network'):
            raise ValueError('private unshared container addresses required')
        epoch=snapshot['epoch']
        if not epoch:
            raise ValueError('container incarnation unavailable')
        if now-snapshot.get('observed_at',now)>30:
            raise ValueError('container sample expired')
        self.start()
        with self.lock:
            # A rename of the same immutable instance keeps its slot order.
            for old,entry in list(self.records.items()):
                prior=entry['container']
                if old!=key and prior['runtime']==runtime and prior.get('project','')==project and json.loads(old)[3]==identity:
                    self.records[key]=self.records.pop(old)
                    self.states[key]=self.states.pop(old)
                    self.records[key]['container']=dict(container)
                    for number,(target,direction) in list(self.by_queue.items()):
                        if target==old:self.by_queue[number]=(key,direction)
            # A different target may not claim an address already enforced here.
            for other,record in self.records.items():
                if other!=key and not record.get('disabled') and set(record['ips']) & set(ips) and set(record.get('interfaces',[])) & set(interfaces):
                    raise ValueError('ambiguous container address; manual review required')
            record=self.records.get(key)
            fresh=record is None
            if fresh:
                digest=hashlib.sha256(key.encode()).hexdigest()
                queue=20000+2*(int(digest[:8],16)%20000)
                occupied={r['queue'] for r in self.records.values()}
                while queue in occupied:
                    queue=20000+(queue-20000+2)%40000
                record={'table':'nwguard_'+digest[:16],'queue':queue,'ips':ips,'container':{k:container[k] for k in ('runtime','project','name','id') if k in container},
                        'verified_at':now,'epoch':epoch,'interfaces':interfaces,'pid':snapshot.get('pid')}
                self.records[key]=record
                self.states[key]=policy.Policy()
            self.by_queue[record['queue']]=(key,'in')
            self.by_queue[record['queue']+1]=(key,'out')
        # Queue registration may deliver packets, whose callback owns self.lock.
        # Never wait for the netlink queue lock while holding the policy lock.
        self.queues.add(record['queue']);self.queues.add(record['queue']+1)
        with self.lock:
            state=self.states[key]
            try:live=self.nft.live(record['table']) if not fresh else set(snapshot['inbound'])
            except RuntimeError:
                fresh=True;live=set(snapshot['inbound'])
            changed=state.observe(snapshot['flows'],snapshot['inbound'],live,now,epoch=epoch)
            digest=self.nft.digests.get(record['table'])
            digest=digest if isinstance(digest,str) else ''
            desired=hashlib.sha256(json.dumps([ips,interfaces,epoch,bool(state.data.get('limited'))],sort_keys=True).encode()).hexdigest()
            changed=changed or fresh or record.get('dirty') or record.get('disabled') or not digest or record.get('fingerprint')!=digest or record.get('applied_config')!=desired
            record.update(ips=ips,epoch=epoch,verified_at=now,interfaces=interfaces,pid=snapshot.get('pid'))
            self.save()
            if changed:
                self.nft.apply(record['table'],ips,record['queue'],state.data['sources'],state.data.get('limited',False),interfaces=interfaces)
            # Readback is required; a missing/overwritten table is never green.
            self.nft.live(record['table'])
            digest=self.nft.digests.get(record['table'])
            record['fingerprint']=digest if isinstance(digest,str) else ''
            record['applied_config']=desired
            record.pop('dirty',None);record.pop('disabled',None)
            self.save()
            result={**state.status(),'instance_id':identity,'state':'enforced','source_limit':5,
                    'source_limit_enforced':False,'source_policy':'observe_only',
                    'tcp_limit':500 if state.data.get('limited') else None,'observed_at':now}
            self.results[(runtime,project,name)]=result
            return result

    def withdraw_unsupported(self,container,identity):
        # A complete runtime response proving a network change authorizes
        # removal of *our* old rules. A timeout/missing sample never does.
        with self.lock:
            for key,record in self.records.items():
                runtime,project,_,stable=json.loads(key)
                if runtime==container['runtime'] and project==(container.get('project') or '') and stable==identity:
                    self.nft.remove(record['table'])
                    record.update(disabled=True,dirty=True,verified_at=0)
            self.save()

    def retire_exited(self):
        """Absence from inventory is not proof; an exited init incarnation is."""
        removed=[]
        with self.lock:
            for key,record in list(self.records.items()):
                pid=record.get('pid')
                if type(pid) is not int or pid<=1:continue
                try:
                    actual=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19]
                    gone=actual!=record['epoch'].rsplit(':',1)[-1]
                except FileNotFoundError:gone=True
                except (OSError,ValueError,IndexError):continue
                if not gone:continue
                try:self.nft.remove(record['table'])
                except RuntimeError:continue
                self.records.pop(key);self.states.pop(key,None)
                c=record['container']
                self.results.pop((c['runtime'],c.get('project') or '',c['name']),None)
                for queue,(target,_) in list(self.by_queue.items()):
                    if target==key:self.by_queue.pop(queue);removed.append(queue)
            self.save()
        # Queue control calls must not hold the callback's policy lock.
        if self.queues:
            for queue in removed:self.queues.remove(queue)

    def failed(self, container, now, reason=None, stage='enforcement'):
        code,stage,message=failure_details(reason, stage)
        # Keep compatibility with older callers passing an explanatory string,
        # but never forward arbitrary exception text to users or the server.
        if isinstance(reason, str):
            code,stage,message='worker_error','enforcement','保护检查未完成，具体原因无法归类'
        with self.lock:
            key=(container['runtime'],container.get('project') or '',container['name'])
            previous=self.results.get(key,{})
            self.results[key]={**previous,'state':'unverified','error':message,'failure_code':code,'failure_stage':stage,'observed_at':now}
            for target,record in self.records.items():
                c=record['container']
                if (c['runtime'],c.get('project') or '',c['name'])==key:
                    self.states[target].observe([],[],[],now,valid=False)
                    record['dirty']=True
                    record['verified_at']=0
            try:self.save()
            except Exception:pass

    def status(self, container):
        with self.lock:
            result=copy.deepcopy(self.results.get((container['runtime'],container.get('project') or '',container['name']),{}))
        # Expiry applies to a previously verified policy. Preserve a concrete
        # failure receipt so a persistent sampling/apply error is not rewritten
        # as a generic stale-sample error after 30 seconds.
        if result and result.get('state')=='enforced' and time.time()-result.get('observed_at',0)>30:
            result.update(state='unverified',error='本地保护采样已过期，不能确认当前状态',
                          failure_code='stale_sample',failure_stage='sampling')
        return result

    def alerts(self, container):
        status=self.status(container)
        if not status:
            return []
        base={'runtime':container['runtime'],'project':container.get('project') or '',
              'container_name':container['name'],'instance_id':status.get('instance_id',''),
              'admission':status}
        if status['state']!='enforced':
            # This is a protection-health state, not a security incident. It is
            # shown by the container's AdmissionStatus panel and must not inflate
            # or repeatedly notify through the active security-alert stream.
            return []
        result=[]
        if status.get('limited'):
            result.append({**base,'type':'tcp_concurrency_limited','severity':'warning','title':'TCP 并发已限制为 500',
                'message':f"当前 TCP 并发 {status.get('tcp_connections',0)}；新连接上限 500，本轮复查时间 {status.get('review_at')}，已续期 {status.get('extensions',0)} 次；已有连接自然回落。",
                'value':status.get('tcp_connections',0),'threshold':500})
        return result

_guard=None
_thread=None
_error=''


def status(container):
    if _guard is None:
        return {'state':'unavailable','error':_error} if _error else {}
    return _guard.status(container)


def alerts(container):
    return _guard.alerts(container) if _guard else []


def start(inventory, provider, emit, emit_status=None):
    global _thread
    if os.name!='posix' or any(os.getenv(k,'true').lower() in {'false','0','no','off'} for k in ('SECURITY_ADMISSION_ENABLED','SECURITY_MONITOR_ENABLED')):
        return
    if _thread and _thread.is_alive():
        return
    latest_targets={}
    def statuses():
        while True:
            if emit_status and _guard is not None:
                items=[]
                for container in list(latest_targets.values()):
                    value=_guard.status(container)
                    if value:items.append({'runtime':container['runtime'],'project':container.get('project') or '',
                        'container_name':container['name'],'instance_id':value.get('instance_id',''),'admission':value})
                try:
                    emit_status(items)
                except Exception:pass
            time.sleep(30)
    def notifications():
        while True:
            for key,container in list(latest_targets.items()):
                if _guard is None:continue
                for alert in _guard.alerts(container):
                    data=alert['admission']
                    signature=(key,alert['type'],data.get('review_at'),data.get('state'),data.get('failure_code'),data.get('failure_stage'))
                    now=time.time()
                    if now-_guard.notifications.get(signature,0)<300:continue
                    try:emit(container,alert)
                    except Exception:continue
                    _guard.notifications[signature]=now
                    _guard.notifications={k:v for k,v in _guard.notifications.items() if now-v<86400}
            time.sleep(2)
    def work():
        global _guard,_error
        try:_guard=Guard()
        except Exception:
            _error='本地恢复记录不可读取；未修改防火墙'
            return
        while True:
            started=time.monotonic()
            try:
                targets=[c for c in inventory() if c.get('runtime') in {'incus','podman'} and c.get('name') not in isolation.PROTECTED]
            except Exception:
                time.sleep(10);continue
            if len(targets)>1000:
                _error='容器数量超过保护容量';time.sleep(10);continue
            try:_guard.retire_exited()
            except Exception:pass
            # Collect the complete successful batch before changing rules, so
            # overlapping addresses on one bridge never become first-wins.
            snapshots=[]
            latest_targets.clear()
            latest_targets.update({(c['runtime'],c.get('project') or '',c['name']):dict(c) for c in targets})
            with ThreadPoolExecutor(max_workers=8,thread_name_prefix='admission-snapshot') as pool:
                futures={pool.submit(provider,c):c for c in targets}
                for future in as_completed(futures):
                    container=futures[future]
                    try:snapshots.append((container,future.result()))
                    except observation.UnsupportedNetwork as error:
                        try:_guard.withdraw_unsupported(container,error.instance_id)
                        except Exception:pass
                        _guard.failed(container,int(time.time()),error,'sampling')
                    except Exception as error:_guard.failed(container,int(time.time()),error,'sampling')
            conflicts=set()
            ownership={}
            for index,(_,snap) in enumerate(snapshots):
                for ip in snap['ips']:
                    for dev in snap.get('interfaces',[]):
                        slot=(dev,ip)
                        if slot in ownership:conflicts.update((index,ownership[slot]))
                        ownership[slot]=index
            for index,(container,snapshot) in enumerate(snapshots):
                now=int(time.time())
                latest_targets[(container['runtime'],container.get('project') or '',container['name'])]=dict(container)
                if index in conflicts:
                    try:_guard.withdraw_unsupported(container,snapshot['instance_id'])
                    except Exception:pass
                    _guard.failed(container,now,ValueError('ambiguous network ownership'),'ownership')
                    continue
                try:_guard.update(container,snapshot,now)
                except Exception as error:_guard.failed(container,now,error,'enforcement')
                # Network delivery runs in its own thread, never in packet or
                # sampling execution. A slow API cannot postpone protection.
            # Missing/failed snapshots preserve previous rules and their journal.
            _error=''
            time.sleep(max(0.1,10-(time.monotonic()-started)))
    _thread=threading.Thread(target=work,name='narwhal-admission-guard',daemon=True)
    _thread.start()
    threading.Thread(target=notifications,name='narwhal-admission-notices',daemon=True).start()
    if emit_status:threading.Thread(target=statuses,name='narwhal-admission-status',daemon=True).start()


def release_owned():
    """Explicit rollback/uninstall only, after stopping the owning service."""
    journal=isolation.Journal('/var/lib/narwhal-monitor/admission.json')
    records=journal.read()
    if not records:return
    tables={item['table']['name'] for item in json.loads(linux.command(['nft','-j','list','tables'])).get('nftables',[]) if item.get('table',{}).get('family')=='inet'}
    nft=linux.NFT()
    for record in records.values():
        table=record['table']
        if table in tables:nft.remove(table)
    journal.write({})


if __name__=='__main__':
    import sys
    if sys.argv[1:]!=['--release-all']:raise SystemExit('explicit --release-all required')
    release_owned()
