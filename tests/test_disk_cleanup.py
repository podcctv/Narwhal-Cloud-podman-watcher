import asyncio
import base64
import hashlib
import hmac
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
import httpx
from client import disk_cleanup as client, disk_cleanup_worker as worker
from server import app as server, disk_cleanup as api


class PolicyTests(unittest.TestCase):
    def test_defaults_match_and_disable_deletion(self):
        self.assertEqual(client.DEFAULT,api.DEFAULT);self.assertFalse(api.DEFAULT['enabled'])
    def test_policy_rejects_wrong_types_and_unsafe_retention(self):
        for bad in ({'enabled':'true'},{'retention_days':True},{'retention_days':13},{'interval_hours':5},{'interval_hours':169}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):client.policy(bad)
                with self.assertRaises(ValueError):api.policy(bad)
    def test_no_arbitrary_directories_or_shell_policy(self):
        with self.assertRaises(ValueError):api.policy({'paths':['/root'],'command':'rm'})


@unittest.skipUnless(os.name=='posix' and Path('/proc/self/fdinfo').is_dir(),'Linux FD safety tests')
class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        self.future=time.time()+30*worker.DAY
    def tearDown(self):os.close(self.fd);self.temp.cleanup()
    def file(self,path):
        p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'synthetic-owned-fixture'*100);return p
    def sweep(self,execute=False,**kw):return worker.sweep(self.fd,execute,now=self.future,busy=set(),**kw)
    def test_scan_is_read_only_and_counts_allowlisted_archives(self):
        old=self.file('var/log/syslog.1.gz');r=self.sweep()
        self.assertEqual(r['candidate_files'],1);self.assertTrue(old.exists());self.assertEqual(r['deleted_files'],0)
    def test_clean_preserves_business_active_security_backups(self):
        old=self.file('var/log/syslog.1.gz')
        safe=[self.file(p) for p in ('var/log/syslog','var/log/auth.log.1.gz','var/log/audit.log.9.gz','var/log/customer.db','root/backup.gz','var/lib/incus/storage-pools/data')]
        r=self.sweep(True);self.assertFalse(old.exists());self.assertEqual(r['deleted_files'],1)
        self.assertTrue(all(p.exists() for p in safe))
    def test_recent_file_is_retained_by_ctime_even_if_mtime_forged(self):
        old=self.file('var/log/syslog.1.gz');os.utime(old,(0,0))
        r=worker.sweep(self.fd,True,busy=set());self.assertEqual(r['deleted_files'],0);self.assertTrue(old.exists())
    def test_hardlinks_and_symlinks_are_never_followed(self):
        original=self.file('customer/data');folder=self.root/'var/log';folder.mkdir(parents=True)
        os.link(original,folder/'syslog.1.gz');os.symlink(original,folder/'syslog.2.gz')
        self.assertEqual(self.sweep(True)['deleted_files'],0);self.assertTrue(original.exists())
    def test_symlink_directory_is_refused(self):
        original=self.file('outside/syslog.1.gz');(self.root/'var').mkdir();os.symlink(self.root/'outside',self.root/'var/log')
        self.assertEqual(self.sweep(True)['deleted_files'],0);self.assertTrue(original.exists())
    def test_open_files_are_retained(self):
        p=self.file('var/log/syslog.1.gz');s=p.stat()
        r=worker.sweep(self.fd,True,now=self.future,busy={(s.st_dev,s.st_ino)})
        self.assertEqual(r['deleted_files'],0);self.assertTrue(p.exists())
    def test_quota_does_not_expand(self):
        p=self.file('var/log/syslog.1.gz');r=self.sweep(True,byte_budget=1)
        self.assertTrue(r['bounded']);self.assertTrue(p.exists());self.assertEqual(r['deleted_files'],0)
    def test_file_quota_and_new_targets_do_not_expand(self):
        self.file('var/log/syslog.1.gz');self.file('var/log/syslog.2.gz')
        r=self.sweep(True,file_budget=1);self.assertEqual(r['deleted_files'],1);self.assertTrue(r['bounded'])
    def test_identity_change_stops_and_preserves_partial_receipt(self):
        self.file('var/log/syslog.1.gz');self.file('var/log/syslog.2.gz')
        count=0
        def validate():
            nonlocal count
            count+=1
            if count>2:raise worker.UnsafeTarget('changed')
        r=self.sweep(True,validate=validate)
        self.assertEqual(r['status'],'partial');self.assertEqual(r['deleted_files'],1)
    def test_archive_journals_only_not_current_journal(self):
        old=self.file('var/log/journal/'+32*'a'+'/system@abc-def.journal')
        active=self.file('var/log/journal/'+32*'a'+'/system.journal')
        self.sweep(True);self.assertFalse(old.exists());self.assertTrue(active.exists())
    def test_guest_mount_check_is_fail_closed(self):
        self.file('var/log/syslog.1.gz')
        real=worker.mount_id
        def changed(fd):
            path=os.readlink('/proc/self/fd/'+str(fd))
            return real(fd)+1 if path.endswith('/var') else real(fd)
        with mock.patch.object(worker,'mount_id',side_effect=changed):
            r=self.sweep(True,guest=True)
        self.assertEqual(r['deleted_files'],0)


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.c=client.Controller(str(Path(self.temp.name)/'state.json'))
        self.c.configure({'node_id':'node',**client.DEFAULT},'node')
    def tearDown(self):self.temp.cleanup()
    def test_node_replacement_does_not_inherit_enabled_policy(self):
        self.c.configure({'node_id':'old','enabled':True},'new');self.assertFalse(self.c.config['enabled'])
    def test_default_never_runs_cleanup(self):
        with mock.patch.object(client,'available',return_value=True),mock.patch.object(self.c,'launch') as start:
            self.c.tick([],None,lambda *a:None);start.assert_not_called()
    def test_automatic_batches_and_rate_limits_targets(self):
        self.c.config.update(enabled=True)
        containers=[{'runtime':'podman','id':str(i),'name':'c'+str(i)} for i in range(9)]
        with mock.patch.object(client,'available',return_value=True),mock.patch.object(self.c,'launch') as start:
            self.c.tick(containers,None,lambda *a:None);self.assertEqual(len(start.call_args.args[0]),5)
            for t in start.call_args.args[0]:self.c.state['attempts'][self.c.key(t)]=time.time()
            self.c.tick(containers,None,lambda *a:None);self.assertEqual(len(start.call_args.args[0]),5)
            self.assertNotEqual(start.call_args.args[0][0]['name'],'__host__')
    def test_docker_and_management_services_excluded(self):
        self.assertEqual(len(self.c.targets([{'runtime':'docker','name':'business'}])),1)
        for name in client.q.PROTECTED:self.assertEqual(len(self.c.targets([{'runtime':'podman','name':name}])),1)
    def test_short_discovery_id_and_full_plan_share_cooldown(self):
        short={'runtime':'podman','name':'c','id':'a'*12}
        full={**short,'stable_id':'a'*64}
        self.assertEqual(self.c.key(short),self.c.key(full))
    def test_corrupt_state_fails_closed(self):
        self.c.journal.write({'runs':'not-a-list','attempts':{}})
        with self.assertRaises(ValueError):client.Controller(self.c.journal.path)
    def test_stale_plan_and_node_mismatch_refused(self):
        with mock.patch.object(client,'available',return_value=True):
            ok,_=self.c.action({'id':1,'action_type':'disk_cleanup_execute','params':{'expected_node_id':'bad'}},'node',[],None)
            self.assertFalse(ok)
            ok,_=self.c.action({'id':1,'action_type':'disk_cleanup_execute','params':{'expected_node_id':'node','confirmed':True,'plan_id':'missing'}},'node',[],None)
            self.assertFalse(ok)
    @unittest.skipUnless(os.name=='posix' and Path('/proc/self/fdinfo').is_dir(),'Linux worker lifecycle')
    def test_manual_scan_execute_and_duplicate_delivery_are_idempotent(self):
        root=Path(self.temp.name)/'fixture';(root/'var/log').mkdir(parents=True)
        archive=root/'var/log/syslog.1.gz';archive.write_bytes(b'synthetic-owned-archive'*100)
        active=root/'var/log/syslog';active.write_bytes(b'keep')
        fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);real=worker.sweep
        def sweep(*args,**kwargs):return real(*args,**kwargs,now=time.time()+30*worker.DAY)
        try:
            with mock.patch.object(client,'available',return_value=True),mock.patch.object(worker,'open_files',return_value=set()),mock.patch.object(worker,'sweep',side_effect=sweep),mock.patch.object(self.c,'anchor',side_effect=lambda t,r:(os.dup(fd),lambda:None,'host')):
                action={'id':1,'action_type':'disk_cleanup_scan','params':{'expected_node_id':'node'}}
                self.assertTrue(self.c.action(action,'node',[],None)[0]);self.c.thread.join(5)
                self.assertEqual(self.c.state['runs'][0]['status'],'scanned');self.assertTrue(archive.exists())
                self.assertTrue(self.c.action(action,'node',[],None)[0]);self.assertEqual(len(self.c.state['runs']),1)
                clean={'id':2,'action_type':'disk_cleanup_execute','params':{'expected_node_id':'node','confirmed':True,'plan_id':'action-1'}}
                self.assertTrue(self.c.action(clean,'node',[],None)[0]);self.c.thread.join(5)
                self.assertFalse(archive.exists());self.assertTrue(active.exists());self.assertEqual(self.c.state['runs'][-1]['status'],'succeeded')
                self.assertFalse(self.c.config['enabled'])
        finally:os.close(fd)
    def test_restart_marks_running_interrupted_not_success(self):
        self.c.state['runs']=[{'run_id':'action-1','status':'running'}];self.c.save()
        c=client.Controller(self.c.journal.path);self.assertEqual(c.state['runs'][0]['status'],'interrupted')
    def test_network_failure_does_not_emit_twenty_receipts_in_one_poll(self):
        self.c.state['runs']=[{'action_id':i,'node_id':'node','run_id':'action-'+str(i),'status':'scanned','items':[]} for i in range(1,10)]
        emit=mock.Mock(side_effect=RuntimeError())
        with mock.patch.object(client,'available',return_value=True):self.c.tick([],None,emit)
        self.assertEqual(emit.call_count,1)


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.now=int(time.time())
        self.p=mock.patch.multiple(server,DB_PATH=str(Path(self.temp.name)/'test.db'),DASHBOARD_USERNAME='admin',DASHBOARD_PASSWORD='test-only')
        self.p.start();server.init_db();self.c=server.db()
        self.c.execute("INSERT INTO hosts VALUES('h',?,'test','node','{}')",(self.now,))
        self.c.execute('INSERT INTO ops_hosts VALUES(?,?,?,?)',('node','h',self.now,json.dumps({'disk_cleanup':{'available':True}})));self.c.commit()
    def tearDown(self):self.c.close();self.p.stop();self.temp.cleanup()
    def call(self,method,path,body=None,auth=True):
        async def run():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app),base_url='http://test',auth=('admin','test-only') if auth else None) as c:return await c.request(method,path,json=body)
        return asyncio.run(run())
    def test_requires_auth_and_explicit_enable_confirmation(self):
        self.assertEqual(self.call('GET','/api/v1/ops/disk-cleanup',auth=False).status_code,401)
        r=self.call('POST','/api/v1/ops/disk-cleanup/policy',{'host_id':'h','node_id':'node','policy':{'enabled':True}});self.assertEqual(r.status_code,400)
    def test_scan_is_identity_bound_and_does_not_enable_auto(self):
        r=self.call('POST','/api/v1/ops/disk-cleanup/scan',{'host_id':'h','node_id':'node'})
        self.assertEqual(r.status_code,200)
        row=self.c.execute('SELECT params_json,action_type FROM security_actions').fetchone()
        self.assertEqual(json.loads(row[0])['expected_node_id'],'node');self.assertEqual(row[1],'disk_cleanup_scan')
        self.assertFalse(api.node_config(self.c,'node')['enabled'])
    def test_duplicate_scan_and_stale_node_refused(self):
        p={'host_id':'h','node_id':'node'}
        self.assertEqual(self.call('POST','/api/v1/ops/disk-cleanup/scan',p).status_code,200)
        self.assertEqual(self.call('POST','/api/v1/ops/disk-cleanup/scan',p).status_code,409)
        self.assertEqual(self.call('POST','/api/v1/ops/disk-cleanup/scan',{**p,'node_id':'other'}).status_code,409)
    def test_execute_requires_fresh_confirmed_safe_scan(self):
        p={'host_id':'h','node_id':'node','plan_id':'action-1','confirmed':True}
        self.assertEqual(self.call('POST','/api/v1/ops/disk-cleanup/execute',p).status_code,409)
    def test_history_rejects_foreign_nodes_and_arbitrary_data(self):
        value={'node_id':'other','run_id':'a'*32,'automatic':True,'mode':'clean','status':'succeeded','started_at':self.now,'items':[]}
        api.record(self.c,'h','node',value);self.assertIsNone(self.c.execute('SELECT 1 FROM ops_disk_cleanup_runs').fetchone())
        value.update(node_id='node',source='must-not-store',items=[{'runtime':'host','name':'__host__','source':'private','deleted_files':2}])
        api.record(self.c,'h','node',value)
        stored=json.loads(self.c.execute('SELECT payload FROM ops_disk_cleanup_runs').fetchone()[0]);self.assertNotIn('source',stored);self.assertNotIn('source',stored['items'][0])
    def test_unknown_policy_keys_rejected(self):
        r=self.call('POST','/api/v1/ops/disk-cleanup/policy',{'host_id':'h','node_id':'node','policy':{'paths':['/']},'confirmed':True})
        self.assertEqual(r.status_code,400)
    def test_operator_and_viewer_cannot_clean_or_enable_auto(self):
        from server import operations
        for role in ('viewer','operator'):
            self.c.execute('INSERT INTO ops_users VALUES(?,?,?,1,?)',(role,operations.password_hash('test-only'),role,self.now));self.c.commit()
            async def run():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app),base_url='http://test',auth=(role,'test-only')) as c:
                    return await c.post('/api/v1/ops/disk-cleanup/scan',json={'host_id':'h','node_id':'node'})
            self.assertEqual(asyncio.run(run()).status_code,403)
    def signed(self,path,body):
        raw=json.dumps(body).encode();ts=str(int(time.time()))
        headers={'X-Timestamp':ts,'X-Signature':hmac.new(server.SHARED_SECRET.encode(),raw+ts.encode(),hashlib.sha256).hexdigest(),'Content-Type':'application/json'}
        async def run():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app),base_url='http://test') as c:return await c.post(path,content=raw,headers=headers)
        return asyncio.run(run())
    def test_signed_poll_and_result_bind_to_exact_node(self):
        r=self.call('POST','/api/v1/ops/disk-cleanup/scan',{'host_id':'h','node_id':'node'});aid=r.json()['action_id']
        wrong=self.signed('/api/v1/actions/poll',{'host_id':'h','node_id':'other'})
        self.assertEqual(wrong.status_code,200);self.assertEqual(wrong.json()['actions'],[])
        correct=self.signed('/api/v1/actions/poll',{'host_id':'h','node_id':'node'})
        self.assertEqual(correct.json()['actions'][0]['params']['expected_node_id'],'node')
        self.assertFalse(correct.json()['operations']['disk_cleanup']['enabled'])
        run={'run_id':'action-'+str(aid),'action_id':aid,'node_id':'node','mode':'scan','status':'scanned','started_at':self.now,'items':[{'runtime':'host','name':'__host__','status':'scanned','candidate_files':0}]}
        result={'host_id':'h','node_id':'other','action_id':aid,'status':'succeeded','message':'fixture','cleanup_run':run}
        self.assertEqual(self.signed('/api/v1/actions/result',result).status_code,403)
        result['node_id']='node';self.assertEqual(self.signed('/api/v1/actions/result',result).status_code,200)
        self.assertEqual(self.c.execute('SELECT status FROM security_actions WHERE id=?',(aid,)).fetchone()[0],'succeeded')
        self.assertEqual(json.loads(self.c.execute('SELECT payload FROM ops_disk_cleanup_runs').fetchone()[0])['status'],'scanned')
        clean=self.call('POST','/api/v1/ops/disk-cleanup/execute',{'host_id':'h','node_id':'node','plan_id':run['run_id'],'confirmed':True})
        self.assertEqual(clean.status_code,200)


if __name__=='__main__':unittest.main()
