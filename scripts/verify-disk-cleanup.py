#!/usr/bin/env python3
"""Opt-in native cleanup proof using ONLY a new owned container and synthetic files.

The worker clock advances only for the owned fixture to exercise age rules;
production never accepts a caller-supplied clock/root/path. No image download.
"""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',action='store_true');p.add_argument('--image',required=True)
    p.add_argument('--source',default=str(Path(__file__).resolve().parents[1]))
    args=p.parse_args()
    if not args.run or os.geteuid()!=0:raise RuntimeError('--run and native root host required')
    sys.path.insert(0,args.source)
    from client import disk_cleanup as cleanup, disk_cleanup_worker as worker
    binary=shutil.which('podman')
    if not binary:raise RuntimeError('Podman required for owned fixture')
    def command(argv,check=True):
        r=subprocess.run(argv,input='',capture_output=True,text=True,timeout=45)
        if check and r.returncode:raise RuntimeError('owned cleanup lab operation failed: '+str(argv[:3]))
        return r
    command([binary,'image','exists',args.image])
    suffix=uuid.uuid4().hex[:12];name='nw-disk-cleanup-'+suffix;identity='';fd=None
    program="""
from pathlib import Path
import os,time
for name in ('/var/log/syslog.1.gz','/var/log/syslog.2.gz','/var/log/syslog','/var/log/auth.log.1.gz','/root/backup.gz','/data/customer.db','/var/cache/apt/archives/narwhal-fixture_1.deb'):
 p=Path(name);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'owned-synthetic-evidence-only'*100)
os.symlink('/data/customer.db','/var/log/syslog.3.gz')
os.link('/data/customer.db','/var/log/syslog.4.gz')
held=open('/var/log/syslog.2.gz','rb')
Path('/tmp/narwhal-fixture-ready').touch()
time.sleep(240)
"""
    with tempfile.TemporaryDirectory(prefix='narwhal-disk-owned-',dir='/tmp') as directory:
        root=Path(directory);bind=root/'bind';bind.mkdir();external=bind/'syslog.1.gz';external.write_bytes(b'owned-bind-must-not-change')
        expected_external=hashlib.sha256(external.read_bytes()).hexdigest()
        c=cleanup.Controller(str(root/'state.json'))
        try:
            identity=command([binary,'run','-d','--pull=never','--name',name,'--network','none',
                '--memory','64m','--pids-limit','24','--label','narwhal.cleanup.fixture='+suffix,
                '--mount','type=bind,src='+str(bind)+',destination=/var/log/nginx',
                '--entrypoint','python',args.image,'-c',program]).stdout.strip()
            if not len(identity)==64:raise RuntimeError('invalid owned container identity')
            for _ in range(40):
                if command([binary,'exec',identity,'test','-f','/tmp/narwhal-fixture-ready'],False).returncode==0:break
                time.sleep(.25)
            else:raise RuntimeError('owned fixture not ready')
            def runner(argv):
                r=command(argv,False);return r.returncode==0,r.stdout
            target={'runtime':'podman','runtime_bin':binary,'project':'','name':name,'id':identity}
            fd,validate,got=c.anchor(target,runner)
            assert got==identity
            initial_pid=target['root_binding'][0]
            def exists(relative):
                try:os.stat(relative,dir_fd=fd,follow_symlinks=False);return True
                except FileNotFoundError:return False
            def digest(relative):
                file=os.open(relative,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
                try:
                    h=hashlib.sha256()
                    for chunk in iter(lambda:os.read(file,65536),b''):h.update(chunk)
                    return h.hexdigest()
                finally:os.close(file)
            protected=['var/log/syslog','var/log/auth.log.1.gz','root/backup.gz','data/customer.db','var/log/syslog.2.gz','var/log/syslog.4.gz']
            before={path:digest(path) for path in protected}
            busy=worker.open_files(time.monotonic()+15)
            future=time.time()+30*worker.DAY
            scanned=worker.sweep(fd,False,True,validate=validate,busy=busy,now=future)
            assert scanned['candidate_files']==2 and scanned['deleted_files']==0 and exists('var/log/syslog.1.gz')
            cleaned=worker.sweep(fd,True,True,validate=validate,busy=busy,now=future)
            assert cleaned['deleted_files']==2 and not exists('var/log/syslog.1.gz') and not exists('var/cache/apt/archives/narwhal-fixture_1.deb')
            assert all(digest(path)==value for path,value in before.items())
            assert exists('var/log/syslog.3.gz') and hashlib.sha256(external.read_bytes()).hexdigest()==expected_external
            validate();assert target['root_binding'][0]==initial_pid
            assert not c.config['enabled'] and not c.journal.read(),'no production automatic policy or journal mutation'
            print(json.dumps({'result':'passed','native_guest_root_fd':True,'scan_deleted_nothing':True,
                'cleaned_only_owned_archive_and_package':True,'active_open_file_retained':True,
                'security_log_database_backup_preserved':True,'symlink_hardlink_bind_mount_preserved':True,
                'same_running_pid':True,'automatic_deletion_remained_disabled':True}),flush=True)
        finally:
            if fd is not None:os.close(fd)
            if identity:
                owned=command([binary,'inspect','--format','{{index .Config.Labels "narwhal.cleanup.fixture"}}',identity],False)
                if owned.returncode==0:
                    if owned.stdout.strip()!=suffix:raise RuntimeError('owned cleanup identity changed; retained')
                    command([binary,'rm','-f',identity])
                print('owned temporary cleanup container removed',flush=True)


if __name__=='__main__':main()
