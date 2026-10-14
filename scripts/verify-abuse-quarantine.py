#!/usr/bin/env python3
"""Opt-in real Podman canary. Only creates/removes its own random lab resources.

No scan, credential attack or request to an external target. Reuses an existing
image with Python, verifies IPv4/IPv6 inbound/outbound, restoration and disk data.
Run as root on a Linux Podman host, with --run and --image <existing-image>.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='explicitly create a temporary lab')
    parser.add_argument('--image', required=True)
    parser.add_argument('--module', default=str(Path(__file__).resolve().parents[1]/'client/network_quarantine.py'))
    args = parser.parse_args()
    if not args.run:
        parser.error('--run required; no resources created')
    spec = importlib.util.spec_from_file_location('quarantine_canary_module', args.module)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def command(argv, check=True):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=45)
        if check and result.returncode:
            # Only our fixed lab operations are logged, never container config.
            raise RuntimeError('lab operation failed: '+str(argv[:3])+' '+result.stderr[:400])
        return result

    command(['podman', 'image', 'exists', args.image])  # Never pull an image.
    suffix = uuid.uuid4().hex[:12]
    network, victim, sibling = ['narwhal-quarantine-lab-'+suffix+'-'+part for part in ('net', 'victim', 'peer')]
    created = []
    network_created = False
    evidence = [{'kind': 'outbound_scan', 'confidence': 'high', 'pid': 22,
                 'start_ticks': '123', 'basis': 'controlled_synthetic_lab',
                 'features': {'corroborating_samples': 2}}]
    checknames = []
    server = "from http.server import HTTPServer,SimpleHTTPRequestHandler;import socket;classcode='class Server(HTTPServer):\\n address_family=socket.AF_INET6';exec(classcode);Server(('::',8080),SimpleHTTPRequestHandler).serve_forever()"
    # The in-container code contains only test constants; no tenant paths/data.
    fetch = "import sys,urllib.request;u=sys.argv[1];o=urllib.request.build_opener(urllib.request.ProxyHandler({}));r=o.open(u,timeout=2);assert r.status==200;print('ok')"

    def inspect(name):
        return json.loads(command(['podman', 'inspect', name]).stdout)[0]

    def addresses(name):
        item = inspect(name)['NetworkSettings']['Networks'][network]
        return item['IPAddress'], item['GlobalIPv6Address']

    def probe(source, ip):
        url = 'http://'+('['+ip+']' if ':' in ip else ip)+':8080/'
        return command(['podman', 'exec', source, 'python', '-c', fetch, url], check=False).returncode == 0

    def mark(name, condition):
        if not condition:
            raise AssertionError(name)
        checknames.append(name)
        print('PASS '+name, flush=True)

    try:
        command(['podman', 'network', 'create', '--ipv6', network])
        network_created = True
        for name in (victim, sibling):
            command(['podman', 'run', '-d', '--pull=never', '--name', name, '--network', network,
                     '--read-only', '--tmpfs', '/tmp:rw,size=8m', '--workdir', '/tmp',
                     '--memory', '64m', '--pids-limit', '32', '--entrypoint', 'python', args.image, '-c', server])
            created.append(name)
        a4, a6 = addresses(victim)
        b4, b6 = addresses(sibling)
        for _ in range(20):
            if probe(victim, b4) and probe(sibling, a4):
                break
            time.sleep(.25)
        for label, source, address in [('ingress_ipv4', sibling, a4), ('ingress_ipv6', sibling, a6),
                                        ('egress_ipv4', victim, b4), ('egress_ipv6', victim, b6)]:
            mark('baseline_'+label, probe(source, address))
        marker = 'only-the-quarantine-canary-'+suffix
        command(['podman', 'exec', victim, 'python', '-c', "from pathlib import Path;import sys;Path('/tmp/canary-evidence').write_text(sys.argv[1])", marker])
        def disk_digest():
            output = command(['podman', 'exec', victim, 'python', '-c', "from pathlib import Path;import hashlib;print(hashlib.sha256(Path('/tmp/canary-evidence').read_bytes()).hexdigest())"]).stdout.strip()
            return output
        expected = hashlib.sha256(marker.encode()).hexdigest()
        identity = inspect(victim)['Id']
        def runner(argv):
            result = command(argv, check=False)
            return result.returncode == 0, result.stdout
        driver = module.PodmanIsolation(runner, 'podman', victim, identity)
        with tempfile.TemporaryDirectory(prefix='narwhal-quarantine-canary-') as directory:
            journal = module.Journal(str(Path(directory)/'state.json'))
            key = module.target('podman', '', victim, identity)
            module.quarantine(journal, key, driver, evidence)
            for label, source, address in [('ingress_ipv4', sibling, a4), ('ingress_ipv6', sibling, a6),
                                            ('egress_ipv4', victim, b4), ('egress_ipv6', victim, b6)]:
                mark('isolated_'+label, not probe(source, address))
            mark('sibling_ipv4_unchanged', probe(sibling, b4))
            mark('sibling_ipv6_unchanged', probe(sibling, b6))
            mark('container_still_running', inspect(victim)['State']['Running'])
            mark('disk_data_unchanged_during_isolation', disk_digest() == expected)
            module.quarantine(journal, key, driver, evidence)  # Durable repeat, not auto-release.
            mark('repeat_stays_isolated', not probe(victim, b4))
            module.release(journal, key, driver)
            for label, source, address in [('ingress_ipv4', sibling, a4), ('ingress_ipv6', sibling, a6),
                                            ('egress_ipv4', victim, b4), ('egress_ipv6', victim, b6)]:
                mark('restored_'+label, probe(source, address))
            mark('disk_data_unchanged_after_restore', disk_digest() == expected)
            mark('recovery_record_cleared', journal.read() == {})
        print(json.dumps({'result': 'passed', 'checks': checknames, 'synthetic_only': True}), flush=True)
    finally:
        # Only exact names successfully created by this invocation; never a glob.
        for name in reversed(created):
            command(['podman', 'rm', '-f', name], check=False)
        if network_created:
            command(['podman', 'network', 'rm', network], check=False)


if __name__ == '__main__':
    main()
