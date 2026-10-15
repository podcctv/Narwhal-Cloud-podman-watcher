"""Native-host cleanup scheduler. Policies are opt-in and bound to node identity."""
import copy
import json
import os
import re
import stat
import threading
import time
import uuid
from pathlib import Path
try:
    from client import disk_cleanup_worker as worker, network_quarantine as q
except ImportError:
    import disk_cleanup_worker as worker
    import network_quarantine as q

DEFAULT = {'enabled':False,'include_containers':True,'retention_days':14,'interval_hours':24}


def policy(value):
    if not isinstance(value,dict):return dict(DEFAULT)
    result={**DEFAULT,**{k:v for k,v in value.items() if k in DEFAULT}}
    if any(type(result[k]) is not bool for k in ('enabled','include_containers')):
        raise ValueError('boolean policy required')
    if type(result['retention_days']) is not int or not 14<=result['retention_days']<=90:
        raise ValueError('retention must be 14-90 days')
    if type(result['interval_hours']) is not int or not 6<=result['interval_hours']<=168:
        raise ValueError('interval must be 6-168 hours')
    return result


def available():
    return os.name=='posix' and os.geteuid()==0 and hasattr(os,'O_NOFOLLOW') and Path('/proc/self/fdinfo').is_dir() and Path('/opt/narwhal-monitor/client.env').is_file() and not any(Path(p).exists() for p in ('/.dockerenv','/run/.containerenv'))


class Controller:
    def __init__(self,path=None):
        self.journal=q.Journal(path or os.getenv('NARWHAL_DISK_CLEANUP_STATE','/var/lib/narwhal-monitor/disk-cleanup.json'))
        self.lock=threading.RLock();self.thread=None;self.config=dict(DEFAULT);self.node_id=''
        self.state=self.journal.read() or {'runs':[],'attempts':{}}
        self.state.setdefault('runs',[]);self.state.setdefault('attempts',{})
        if not isinstance(self.state['runs'],list) or len(self.state['runs'])>20 or not all(isinstance(r,dict) for r in self.state['runs']) or not isinstance(self.state['attempts'],dict):
            raise ValueError('invalid cleanup state; no automatic deletion')
        if not all(type(v) in (int,float) and v>=0 for v in self.state['attempts'].values()):raise ValueError('invalid cleanup timing state')
        # An interrupted cleanup is not re-executed on restart or reported successful.
        for run in self.state['runs']:
            if run.get('status')=='running':run.update(status='interrupted',finished_at=int(time.time()))

    def save(self):
        self.state['runs']=self.state['runs'][-20:]
        if len(self.state['attempts'])>1000:
            self.state['attempts']=dict(sorted(self.state['attempts'].items(),key=lambda x:x[1])[-1000:])
        self.journal.write(self.state)

    def configure(self,value,node_id):
        with self.lock:
            self.node_id=node_id
            self.config=policy(value) if isinstance(value,dict) and value.get('node_id')==node_id else dict(DEFAULT)

    def summary(self):
        with self.lock:
            try:
                fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);usage=worker.disk(fd);os.close(fd)
            except OSError:usage={}
            return {'available':available(),'policy':dict(self.config),'disk':usage,
                    'running':bool(self.thread and self.thread.is_alive()),'runs':copy.deepcopy(self.state['runs'])}

    def targets(self,containers):
        result=[{'runtime':'host','name':'__host__','project':'','id':'host'}]
        if self.config['include_containers']:
            for c in containers[:500]:
                if c.get('runtime') not in ('incus','podman') or c.get('name') in q.PROTECTED:continue
                name=str(c.get('name') or '')
                if not re.fullmatch(r'[A-Za-z0-9_.:@+-]{1,200}',name):continue
                result.append({k:c.get(k) or '' for k in ('runtime','runtime_bin','project','name','id','stable_id')})
        return result

    def key(self,target):
        identity=str(target.get('stable_id') or target.get('id') or '')
        # Podman discovery may use a short ID; full identity is still required by
        # the scan binding and driver before filesystem access, not by cooldown.
        if target['runtime']=='podman':identity=identity[:12]
        return json.dumps([target['runtime'],target.get('project',''),target['name'],identity],separators=(',',':'))

    def anchor(self,target,run_command):
        if target['runtime']=='host':
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            return fd,lambda:None,'host'
        runtime=target['runtime'];name=target['name'];project=target.get('project') or ''
        if runtime=='incus':
            api=q.IncusAPI(project or 'default')
            item=api.request('GET','/1.0/instances/'+name)[0]
            identity=str(item.get('config',{}).get('volatile.uuid') or '')
            expected=str(target.get('stable_id') or '')
            if not expected or expected!=identity:raise worker.UnsafeTarget('instance identity changed')
            expanded=item.get('expanded_config',{})
            if 'lxc.net' in str(expanded.get('raw.lxc','')) or 'lxc.network' in str(expanded.get('raw.lxc','')):
                raise worker.UnsafeTarget('custom namespace requires manual review')
            pid=int(api.request('GET','/1.0/instances/'+name+'/state')[0].get('pid') or 0)
        else:
            expected=str(target.get('stable_id') or target.get('id') or '')
            item=q.PodmanIsolation(run_command,target['runtime_bin'],name,expected).inspect()
            identity=str(item.get('Id') or item.get('ID') or '');pid=int(item.get('State',{}).get('Pid') or 0)
        q.target(runtime,project,name,identity)
        if pid<=1:raise worker.UnsafeTarget('container is not running')
        # Quarantined instances retain their logs and cached evidence, regardless of age.
        if any(json.loads(k)[-1]==identity for k in q.Journal().read()):
            raise worker.UnsafeTarget('network quarantine evidence retained')
        if os.stat('/proc/'+str(pid)+'/ns/pid').st_ino==os.stat('/proc/1/ns/pid').st_ino:
            raise worker.UnsafeTarget('shared host PID namespace')
        token=worker.start_ticks(pid)
        fd=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY)
        try:
            guest=os.fstat(fd);host=os.stat('/')
            if (guest.st_dev,guest.st_ino)==(host.st_dev,host.st_ino):raise worker.UnsafeTarget('host filesystem root refused')
            binding=[pid,token,guest.st_dev,guest.st_ino,worker.mount_id(fd)]
            if target.get('root_binding') and target['root_binding']!=binding:raise worker.UnsafeTarget('scan root identity changed')
            target['root_binding']=binding
            target['stable_id']=identity
            def validate():
                try:
                    if worker.start_ticks(pid)!=token:raise worker.UnsafeTarget('container restarted')
                except (OSError,IndexError):raise worker.UnsafeTarget('container disappeared') from None
            validate()
            return fd,validate,identity
        except BaseException:os.close(fd);raise

    def launch(self,targets,execute,run_command,action_id=0,plan_id='',automatic=False):
        import fcntl
        with self.lock:
            old=next((r for r in self.state['runs'] if action_id and r.get('action_id')==action_id),None)
            if old:return True,'cleanup action already accepted'
            if self.thread and self.thread.is_alive():return False,'another cleanup task is running'
            Path(self.journal.path).parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            lock_path=str(self.journal.path)+'.lock'
            lock_fd=os.open(lock_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            try:fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError:os.close(lock_fd);return False,'another Agent cleanup process holds the lock'
            settings=dict(self.config)
            run={'run_id':'action-'+str(action_id) if action_id else uuid.uuid4().hex,'action_id':action_id,
                 'node_id':self.node_id,'mode':'clean' if execute else 'scan','automatic':automatic,
                 'started_at':int(time.time()),'status':'running','targets':copy.deepcopy(targets),'items':[],'plan_id':plan_id}
            self.state['runs'].append(run)
            if execute:
                for t in targets:self.state['attempts'][self.key(t)]=time.time()
            try:self.save()
            except BaseException:os.close(lock_fd);raise
            def work():
                remaining_bytes=worker.MAX_BYTES;remaining_files=worker.MAX_FILES
                try:
                    busy=worker.open_files(time.monotonic()+15)
                    for index,original in enumerate(run['targets']):
                        target=copy.deepcopy(original)
                        item={'runtime':target['runtime'],'name':target['name'],'project':target.get('project','')}
                        try:
                            fd,validate,identity=self.anchor(target,run_command)
                            try:
                                check=validate
                                def validate_current():
                                    check()
                                    if automatic and (not self.config['enabled'] or self.node_id!=run['node_id']):raise worker.UnsafeTarget('automatic cleanup was disabled')
                                item.update(worker.sweep(fd,execute,target['runtime']!='host',settings['retention_days'],remaining_bytes,remaining_files,validate_current,busy))
                                item['instance_id']=identity
                            finally:os.close(fd)
                            remaining_bytes-=item['unlinked_bytes'];remaining_files-=item['deleted_files']
                        except (OSError,ValueError,q.QuarantineError,worker.UnsafeTarget):
                            item.update(status='skipped',reason='identity, mount, evidence or filesystem safety check unavailable')
                        with self.lock:run['targets'][index]=target;run['items'].append(item);self.save()
                    with self.lock:
                        states={i['status'] for i in run['items']}
                        run.update(status='partial' if states & {'skipped','partial'} else 'succeeded' if execute else 'scanned',finished_at=int(time.time()))
                        self.save()
                except Exception:
                    with self.lock:run.update(status='failed',finished_at=int(time.time()),error='cleanup worker could not complete safely');self.save()
                finally:os.close(lock_fd)
            self.thread=threading.Thread(target=work,name='narwhal-disk-cleanup',daemon=True)
            try:self.thread.start()
            except BaseException:
                os.close(lock_fd);run.update(status='failed',finished_at=int(time.time()));self.save();raise
            return True,'bounded cleanup worker accepted; await final receipt'

    def action(self,action,node_id,containers,run_command):
        if not available():return False,'native root host Agent required'
        p=action.get('params',{})
        if not node_id or p.get('expected_node_id')!=node_id:return False,'cleanup node identity mismatch'
        with self.lock:
            if action['action_type']=='disk_cleanup_execute':
                plan=next((r for r in self.state['runs'] if r['run_id']==p.get('plan_id')),None)
                if not p.get('confirmed') is True or not plan or plan['mode']!='scan' or plan['status'] not in ('scanned','partial') or plan['node_id']!=node_id or time.time()-plan['started_at']>900:
                    return False,'a completed fresh scan and confirmation are required'
                clean={(i['runtime'],i.get('project',''),i['name']) for i in plan['items'] if i['status']=='scanned'}
                targets=[t for t in plan['targets'] if (t['runtime'],t.get('project',''),t['name']) in clean]
                if not targets:return False,'no safely scanned targets'
            else:targets=self.targets(containers)[:5]
            return self.launch(targets,action['action_type']=='disk_cleanup_execute',run_command,int(action['id']),str(p.get('plan_id') or ''))

    def tick(self,containers,run_command,emit):
        if not available():return
        with self.lock:
            for run in self.state['runs']:
                if run.get('action_id') and run.get('node_id')==self.node_id and run['status']!='running' and not run.get('delivered'):
                    status='succeeded' if run['status'] in ('scanned','succeeded') else 'failed'
                    try:
                        emit(run['action_id'],status,json.dumps({'run_id':run['run_id'],'status':run['status'],'targets':len(run['items']),'deleted_files':sum(i.get('deleted_files',0) for i in run['items'])}),copy.deepcopy(run))
                        run['delivered']=True;self.save()
                    except Exception:pass
                    break  # At most one network receipt attempt per polling cycle.
            if not self.config['enabled'] or not self.node_id or self.thread and self.thread.is_alive():return
            due=[t for t in self.targets(containers) if time.time()-self.state['attempts'].get(self.key(t),0)>=self.config['interval_hours']*3600]
            if due:self.launch(due[:5],True,run_command,automatic=True)


_controller=None
def controller():
    global _controller
    if _controller is None:_controller=Controller()
    return _controller
