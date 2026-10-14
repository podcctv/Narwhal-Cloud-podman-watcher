import base64
import unittest
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


if __name__ == '__main__':
    unittest.main()

