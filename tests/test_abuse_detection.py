import json
import unittest
from client import abuse_detection as abuse


IDENTITY = '''
import requests
from concurrent.futures import ThreadPoolExecutor
def generate_id_card(i):
    return str(i).zfill(18)
with ThreadPoolExecutor(max_workers=100) as pool:
    for i in range(100000):
        requests.post('https://example.org/patient/bind/add', json={'idcard': generate_id_card(i)})
'''
CREDENTIALS = '''
import requests as r
import itertools
users = ['example']
with open('passwords.txt') as f:
    passwords = f.read().splitlines()
for user, pwd in itertools.product(users, passwords):
    r.post('https://example.org/login', json={'username': user, 'password': pwd})
'''


def flow(pid=22, ip='8.8.8.8', port=443, state='established', direction='outbound'):
    return {'pid': pid, 'remote_ip': ip, 'remote': f'{ip}:{port}', 'state': state,
            'proto': 'tcp', 'direction': direction}


class AbuseDetectionTests(unittest.TestCase):
    def test_identity_enumeration_requires_live_owned_connections(self):
        p = {'pid': 22, 'start_ticks': '12345', 'source': IDENTITY, 'argv': ['python3', '1.py'], 'target_ips': {'example.org': ['8.8.8.8']}}
        self.assertEqual(abuse.source_evidence(IDENTITY)['kinds'], ['identity_enumeration'])
        self.assertEqual(abuse.evaluate_process(p, []), [])
        self.assertEqual(abuse.evaluate_process(p, [flow(pid=23)]), [])
        self.assertEqual(abuse.evaluate_process(p, [flow(direction='inbound')]), [])
        self.assertEqual(abuse.evaluate_process(p, [flow(ip='10.0.0.2')]), [])
        findings = abuse.evaluate_process(p, [flow()])
        self.assertEqual(findings[0]['kind'], 'identity_enumeration')
        self.assertEqual(findings[0]['confidence'], 'high')
        self.assertNotIn('source', findings[0])
        self.assertNotIn('idcard', json.dumps(findings))
        self.assertEqual(abuse.evaluate_process({**p, 'target_ips': {'example.org': ['1.1.1.1']}}, [flow()]), [])
        self.assertEqual(abuse.evaluate_process({**p, 'target_ips': {}}, [flow()]), [])

    def test_credential_dictionary_and_aliases(self):
        self.assertEqual(abuse.source_evidence(CREDENTIALS)['kinds'], ['credential_stuffing'])
        session = CREDENTIALS.replace('import requests as r', 'import requests as r\ns=r.Session()').replace('r.post(', 's.post(')
        self.assertEqual(abuse.source_evidence(session)['kinds'], ['credential_stuffing'])

    def test_named_worker_count_and_named_url_match_screenshot_shape(self):
        source = IDENTITY.replace('max_workers=100', 'max_workers=MAX_WORKERS').replace("'https://example.org/patient/bind/add'", 'TARGET_URL')
        source = "MAX_WORKERS = 100\nBASE_URL='https://example.org'\nTARGET_URL=BASE_URL+'/patient/bind/add'\n" + source
        result = abuse.source_evidence(source)
        self.assertEqual(result['kinds'], ['identity_enumeration'])
        self.assertEqual(result['features']['concurrency'], 100)
        self.assertEqual(result['target_hosts'], ['example.org'])
        self.assertEqual(abuse.source_evidence(source+'\nMAX_WORKERS=int(input())\n')['kinds'], [])

    def test_dictionary_login_bruteforce_not_customer_import(self):
        single = '''
import requests
with open('passwords.txt') as f:
    passwords=f.read().splitlines()
for pwd in passwords:
    requests.post('https://example.org/login',json={'username':'example','password':pwd})
'''
        self.assertEqual(abuse.source_evidence(single)['kinds'], ['authentication_bruteforce'])
        self.assertEqual(abuse.source_evidence(single.replace('/login', '/customers/import'))['kinds'], [])

    def test_concurrency_python_telegram_and_customer_login_are_not_proof(self):
        innocent = '''
import requests
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=100) as pool:
    for i in range(1000):
        requests.post('https://example.org/api', json={'username': 'customer', 'password': 'not-retained'})
'''
        self.assertEqual(abuse.source_evidence(innocent)['kinds'], [])
        self.assertEqual(abuse.tool_evidence(['python3', 'telegram-bot.py', '100']), [])
        self.assertEqual(abuse.source_evidence(IDENTITY.replace('generate_id_card', 'read_customer_id'))['kinds'], [])

    def test_dead_branches_comments_and_local_test_not_promoted(self):
        dead = 'if False:\n' + ''.join('    '+line+'\n' for line in IDENTITY.splitlines())
        self.assertEqual(abuse.source_evidence(dead)['kinds'], [])
        self.assertEqual(abuse.source_evidence('# '+repr(IDENTITY))['kinds'], [])
        dormant = 'def unused_attack():\n' + ''.join('    '+line+'\n' for line in IDENTITY.splitlines()) + '\nimport requests\nrequests.get("https://example.org/health")\n'
        self.assertEqual(abuse.source_evidence(dormant)['kinds'], [])
        nested = 'def main():\n    def unused_attack():\n' + ''.join('        '+line+'\n' for line in IDENTITY.splitlines()) + '\n    return 1\nmain()\n'
        self.assertEqual(abuse.source_evidence(nested)['kinds'], [])
        for endpoint in ('http://localhost/api', 'http://127.0.0.1/api', 'http://10.0.0.1/api', 'http://service.internal/api'):
            self.assertEqual(abuse.source_evidence(IDENTITY.replace('https://example.org/patient/bind/add', endpoint))['kinds'], [])

    def test_no_source_or_credentials_or_personal_records_in_evidence(self):
        source = IDENTITY + "\npassword='example-secret'\nrecord='example-private-record'\n"
        result = json.dumps(abuse.source_evidence(source))
        self.assertNotIn('example-secret', result)
        self.assertNotIn('example-private-record', result)
        self.assertNotIn('/patient/bind/add', result)
        self.assertFalse(abuse.source_evidence('x'*70000)['available'])
        self.assertFalse(abuse.source_evidence('for !!')['available'])

    def test_active_tools_include_lateral_but_not_loopback_or_passive_targets(self):
        for name in ('nmap', 'masscan', 'zmap', 'rustscan'):
            self.assertEqual(abuse.tool_evidence([name, '8.8.8.8'])[0]['kind'], 'outbound_scan')
        for name in ('hydra', 'medusa', 'ncrack', 'patator'):
            self.assertEqual(abuse.tool_evidence([name, '8.8.8.8'])[0]['kind'], 'authentication_bruteforce')
        self.assertEqual(abuse.tool_evidence(['nmap','10.0.0.0/8'])[0]['private_target_count'], 1)
        for argv in (['nmap', '--help'], ['nmap', '-sL', '8.8.8.8'], ['nmap', '127.0.0.1'], ['nmap', '0.0.0.0/0'], ['echo', 'nmap 8.8.8.8']):
            self.assertEqual(abuse.tool_evidence(argv), [])
        self.assertEqual(abuse.tool_evidence(['nmap', '--exclude', '8.8.8.8', '127.0.0.1']), [])
        self.assertEqual(abuse.tool_evidence(['hydra', '-p', '8.8.8.8', '127.0.0.1', 'ssh']), [])
        self.assertTrue(abuse.tool_evidence(['medusa', '-h', '8.8.8.8', '-u', 'example']))
        self.assertTrue(abuse.tool_evidence(['patator', 'ssh_login', 'host=8.8.8.8', 'user=example', 'password=FILE0']))
        self.assertEqual(abuse.tool_evidence(['patator', 'ssh_login', 'host=127.0.0.1', 'password=8.8.8.8']), [])
        fake = {'pid': 22, 'start_ticks': '123', 'argv': ['nmap', '8.8.8.8'], 'executable': '/bin/sleep'}
        self.assertEqual(abuse.evaluate_process(fake, []), [])
        fake['executable'] = '/usr/bin/nmap'
        self.assertEqual(abuse.evaluate_process(fake, [])[0]['kind'], 'outbound_scan')

    def test_network_scan_is_directional_process_scoped_and_not_tls_proxy_fanout(self):
        vertical = [flow(port=n, state='syn_sent') for n in range(1, 40)]
        result = abuse.network_evidence(vertical)
        self.assertEqual(result[0]['vertical_ports'], 39)
        self.assertEqual(result[0]['confidence'], 'corroboration_required')
        self.assertEqual(abuse.network_evidence([flow(port=n, direction='inbound', state='syn_sent') for n in range(1, 40)]), [])
        self.assertEqual(abuse.network_evidence([flow(pid=n+2, port=n, state='syn_sent') for n in range(1, 40)]), [])
        public = [f'8.8.4.{i}' for i in range(1, 70)]
        self.assertEqual(abuse.network_evidence([flow(ip=ip, state='syn_sent') for ip in public]), [])
        self.assertEqual(abuse.network_evidence([flow(ip=ip, port=22, state='syn_sent') for ip in public])[0]['horizontal_targets'], 69)
        self.assertEqual(abuse.network_evidence([flow(ip=ip, port=22, state='established') for ip in public]), [])
        lateral = [flow(ip='10.0.0.2', port=n, state='syn_sent') for n in range(1,40)]
        self.assertEqual(abuse.network_evidence(lateral)[0]['private_target_count'], 1)

    def test_missing_process_incarnation_never_qualifies(self):
        self.assertEqual(abuse.evaluate_process({'pid': 22, 'argv': ['nmap', '8.8.8.8']}, []), [])


if __name__ == '__main__':
    unittest.main()

