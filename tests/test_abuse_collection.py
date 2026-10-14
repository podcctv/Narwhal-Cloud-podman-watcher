import base64
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from client import abuse_collection as collector


def sample(pid=22, ticks='123', executable='/usr/bin/python3.12', cwd='/root', argv=None):
    argv = argv or ['python3', '1.py']
    encoded = [base64.b64encode(v).decode() for v in (executable.encode(), cwd.encode(), b'\0'.join(v.encode() for v in argv)+b'\0')]
    return '@@NW_ABUSE_V1@@\n' + '\t'.join([str(pid), ticks, *encoded]) + '\n@@NW_END@@:20:1\n'


class AbuseCollectionTests(unittest.TestCase):
    def test_bounded_process_parser_and_entrypoint(self):
        process = collector.parse_processes(sample())[0]
        self.assertEqual(process['pid'], 22)
        self.assertEqual(process['start_ticks'], '123')
        self.assertEqual(collector.python_entrypoint(process), (None, '/root/1.py'))
        self.assertEqual(collector.python_entrypoint({**process, 'argv': ['python3', '-c', 'print(1)']}), ('print(1)', None))
        self.assertEqual(collector.python_entrypoint({**process, 'argv': ['python3', '-m', 'customer_module']}), (None, None))

    def test_only_running_entrypoint_read_never_customer_history(self):
        calls = []
        def execute(container, command):
            calls.append(command)
            if '@@NW_ABUSE_V1@@' in command:
                return True, sample(argv=['python3', '1.py', 'verify_history.json'])
            return True, base64.b64encode(b'print("example")').decode()
        result = collector.collect({}, execute, [{'pid': 22, 'direction': 'outbound'}])
        self.assertEqual(result[0]['source'], 'print("example")')
        self.assertEqual(len(calls), 2)
        self.assertNotIn('verify_history.json', calls[1])
        self.assertNotIn('eval', calls[1])

    def test_no_source_read_without_owned_outbound_and_source_limit(self):
        calls = []
        def execute(container, command):
            calls.append(command)
            return (True, sample()) if '@@NW_ABUSE_V1@@' in command else (True, base64.b64encode(b'x'*65537).decode())
        self.assertNotIn('source', collector.collect({}, execute, [])[0])
        self.assertEqual(len(calls), 1)
        self.assertNotIn('source', collector.collect({}, execute, [{'pid': 22, 'direction': 'outbound'}])[0])

    def test_incarnation_reverified_and_bad_collector_never_clean(self):
        with self.assertRaises(Exception):
            collector.parse_processes('bad data')
        with self.assertRaises(Exception):
            collector.verify_live_processes({}, lambda c, cmd: (True, sample(ticks='different')), [{'pid': 22, 'start_ticks': '123'}])
        collector.verify_live_processes({}, lambda c, cmd: (True, sample()), [{'pid': 22, 'start_ticks': '123'}])

    def test_custom_socket_owners_prioritized_without_shell_injection(self):
        script = collector.process_script([{'pid': 567, 'direction': 'outbound'},
                                          {'pid': '22; touch /tmp/not-allowed', 'direction': 'outbound'}])
        self.assertIn('for d in /proc/567 /proc/[0-9]*;', script)
        self.assertNotIn('not-allowed', script)
        self.assertIn('case "$p" in 567)', script)
        self.assertEqual(len(collector.parse_processes(sample()+sample())), 1)

    def test_native_pid_one_metadata_without_any_guest_tools(self):
        process={'host_pid':123,'pid':1,'start_ticks':'456','argv':['python3','-c','print(1)'],
                 'executable':'/usr/bin/python3','cwd':'/'}
        with mock.patch.object(collector,'host_metadata',return_value=process):
            result=collector.collect_host([{'host_pid':123,'pid':1}],
                [{'pid':1,'direction':'outbound'}],{},lambda c,cmd: (False,''))
            self.assertEqual(result[0]['source'],'print(1)')
            collector.verify_host_processes(result,[{'pid':1,'start_ticks':'456'}])
        with mock.patch.object(collector,'host_metadata',side_effect=OSError('unavailable')):
            with self.assertRaises(Exception):collector.collect_host([{'host_pid':123,'pid':1}],[],{},lambda c,cmd:(False,''))

    def test_native_namespace_membership_includes_exec_process_not_just_descendants(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'target-ns').touch();(root/'other-ns').touch()
            for host,pid,ns in ((100,1,'target-ns'),(101,2,'target-ns'),(200,1,'other-ns')):
                base=root/str(host);(base/'ns').mkdir(parents=True)
                os.link(root/ns,base/'ns/pid')
                (base/'status').write_text(f'PPid:\t0\nNSpid:\t{host} {pid}\n')
                (base/'comm').write_text('synthetic-python')
            processes=collector.scoped_host_processes(100,str(root))
            self.assertEqual([(p['host_pid'],p['pid']) for p in processes],[(100,1),(101,2)])
            with self.assertRaises(Exception):collector.scoped_host_processes(100,str(root),scan_limit=2)

    @unittest.skipUnless(os.name=='posix','kernel proc and no-follow directory descriptors require Linux')
    def test_native_running_entrypoint_bounded_and_never_reads_history_or_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'app.py'
            source.write_text("import time;from pathlib import Path;Path('ready').touch();time.sleep(30)")
            (Path(folder)/'verify_history.json').write_text('synthetic-private-record-do-not-read')
            child=subprocess.Popen([sys.executable,str(source),'verify_history.json'],cwd=folder,
                                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                for _ in range(40):
                    if (Path(folder)/'ready').exists():break
                    time.sleep(.025)
                self.assertTrue((Path(folder)/'ready').exists())
                process=collector.host_metadata(child.pid)
                self.assertEqual(collector.read_host_entrypoint(process),source.read_text())
                self.assertNotIn('synthetic-private-record',collector.read_host_entrypoint(process))
                linked=Path(folder)/'linked.py';linked.symlink_to(source)
                with self.assertRaises(OSError):collector.read_host_entrypoint({**process,'argv':[sys.executable,str(linked)]})
                self.assertIsNone(collector.read_host_entrypoint({**process,'argv':[sys.executable,'../app.py']}))
                source.write_text('x'*65537)
                self.assertIsNone(collector.read_host_entrypoint(process))
                collector.verify_host_processes([process],[{'pid':process['pid'],'start_ticks':process['start_ticks']}])
            finally:
                child.terminate();child.wait(timeout=3)

    @unittest.skipUnless(os.name == 'posix', 'real proc collector requires Linux')
    def test_real_linux_proc_collector_prioritizes_child_and_checks_incarnation(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(20)'])
        try:
            script = collector.process_script([{'pid': child.pid, 'direction': 'outbound'}])
            result = subprocess.run(['/bin/sh', '-c', script], capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 0)
            item = next(p for p in collector.parse_processes(result.stdout) if p['pid'] == child.pid)
            self.assertTrue(item['start_ticks'].isdigit())
            self.assertEqual(item['argv'][1], '-c')
            collector.verify_live_processes({}, lambda c, cmd: (True, subprocess.check_output(['/bin/sh','-c',cmd],text=True)), [item])
        finally:
            child.terminate()
            child.wait(timeout=3)


if __name__ == '__main__':
    unittest.main()

