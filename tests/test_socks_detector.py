import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest
from unittest import mock

from client import socks_detector as detector, agent


class DirectionTests(unittest.TestCase):
    def test_outbound_socks_is_not_a_listener(self):
        cfg = {'inbounds': [{'protocol': 'vless', 'port': 443}],
               'outbounds': [{'protocol': 'socks', 'settings': {'servers': [{'users': [{'user': 'x', 'pass': 'password'}]}]}}]}
        result = detector.parse_config(json.dumps(cfg), 'xray')
        self.assertTrue(result['parsed'])
        self.assertEqual(result['endpoints'], [])
        self.assertFalse(result['single_purpose'])

    def test_xray_auth_is_scoped_to_the_socks_inbound(self):
        cfg = {'inbounds': [{'protocol': 'vless', 'port': 443, 'settings': {'auth': 'noauth'}},
               {'protocol': 'socks', 'port': 1080, 'settings': {'auth': 'password',
                    'users': [{'user': 'test', 'pass': 'strong-test-value-42681'}]}}]}
        result = detector.parse_config(json.dumps(cfg), 'xray')
        self.assertEqual(result['endpoints'][0]['auth_state'], 'configured')
        self.assertEqual(result['endpoints'][0]['port'], 1080)
        self.assertFalse(result['single_purpose'])
        self.assertNotIn('strong-test-value', json.dumps(result))

    def test_xray_accounts_compatibility_and_weak_password(self):
        for field in ('users', 'accounts'):
            cfg = {'inbounds': [{'protocol':'socks','port':1080,'settings':{
                'auth':'password',field:[{'user':'test','pass':'password'}]}}]}
            self.assertEqual(detector.parse_config(json.dumps(cfg),'xray')['endpoints'][0]['auth_state'], 'weak_password')

    def test_sing_box_socks_and_mixed_but_not_other_auth_fields(self):
        for kind in ('socks', 'mixed'):
            cfg = {'inbounds': [{'type':kind,'listen':'127.0.0.1','listen_port':1080,'users':[]}],
                   'outbounds':[{'type':'socks','username':'test','password':'password'}]}
            result = detector.parse_config(json.dumps(cfg),'sing-box')
            self.assertEqual(result['endpoints'][0]['auth_state'], 'no_auth')
            self.assertNotIn('password',json.dumps(result))

    def test_empty_password_auth_accounts_are_not_proof_of_noauth(self):
        result = detector.parse_config(json.dumps({'inbounds':[{'protocol':'socks','port':1080,
            'settings':{'auth':'password','users':[]}}]}),'xray')
        self.assertEqual(result['endpoints'][0]['auth_state'],'unknown')

    def test_jsonc_comments_and_urls(self):
        cfg = '{/* comment */"inbounds": [], "outbounds":[{"protocol":"socks","tag":"https://example.test"}]} // tail'
        result=detector.parse_config(cfg,'xray')
        self.assertTrue(result['parsed']); self.assertEqual(result['endpoints'],[])

    def test_inbound_protocol_inventory_contains_only_safe_labels(self):
        cfg = json.dumps({
            'inbounds': [
                {'protocol': 'vless', 'port': 443, 'settings': {'clients': [{'id': 'private-id'}]}},
                {'protocol': 'trojan', 'port': 8443, 'network': 'tcp', 'settings': {'password': 'never-report-this'}},
            ],
            'outbounds': [{'protocol': 'socks', 'settings': {'servers': [{'address': 'secret.example'}]}}],
        })
        result = detector.parse_inbound_protocols(cfg, 'xray')
        self.assertTrue(result['parsed'])
        self.assertEqual(
            result['endpoints'],
            [
                {'protocol': 'vless', 'port': 443, 'listen': '*', 'transports': ['tcp']},
                {'protocol': 'trojan', 'port': 8443, 'listen': '*', 'transports': ['tcp']},
            ],
        )
        self.assertNotIn('private-id', json.dumps(result))
        self.assertNotIn('never-report-this', json.dumps(result))
        self.assertNotIn('secret.example', json.dumps(result))

    def test_sing_box_inbound_protocol_inventory_uses_live_listener_fields(self):
        result = detector.parse_inbound_protocols(json.dumps({
            'inbounds': [{'type': 'hysteria2', 'listen': '0.0.0.0', 'listen_port': 443}],
            'outbounds': [{'type': 'wireguard', 'server': 'private.example'}],
        }), 'sing-box')
        self.assertEqual(result['endpoints'], [
            {'protocol': 'hysteria2', 'port': 443, 'listen': '0.0.0.0'},
        ])

    def test_xray_stream_methods_map_to_socket_layer_protocols(self):
        methods = {
            'raw': 'tcp', 'xhttp': 'tcp', 'grpc': 'tcp',
            'websocket': 'tcp', 'httpupgrade': 'tcp',
            'mkcp': 'udp', 'hysteria': 'udp',
        }
        for method, transport in methods.items():
            with self.subTest(method=method):
                result = detector.parse_inbound_protocols(json.dumps({
                    'inbounds': [{
                        'protocol': 'vmess', 'port': 443,
                        'streamSettings': {'method': method},
                    }],
                }), 'xray')
                self.assertEqual(result['endpoints'][0]['transports'], [transport])

    def test_xray_xhttp_h3_and_mixed_alpn_are_handled_conservatively(self):
        for alpn, expected in ((['h3'], ['udp']), (['h2'], ['tcp']), (['h2', 'h3'], None)):
            with self.subTest(alpn=alpn):
                result = detector.parse_inbound_protocols(json.dumps({
                    'inbounds': [{
                        'protocol': 'vmess', 'port': 443,
                        'streamSettings': {
                            'method': 'xhttp', 'security': 'tls',
                            'tlsSettings': {'alpn': alpn},
                        },
                    }],
                }), 'xray')
                if expected is None:
                    self.assertNotIn('transports', result['endpoints'][0])
                else:
                    self.assertEqual(result['endpoints'][0]['transports'], expected)

    def test_xray_masque_transport_is_not_guessed_without_alpn_evidence(self):
        result = detector.parse_inbound_protocols(json.dumps({
            'inbounds': [{
                'protocol': 'masque', 'port': 443,
                'streamSettings': {
                    'method': 'masque', 'security': 'tls',
                    'tlsSettings': {'alpn': ['h2', 'h3']},
                },
            }],
        }), 'xray')
        self.assertNotIn('transports', result['endpoints'][0])

    def test_legacy_xray_network_aliases_map_to_socket_layer_protocols(self):
        for network, transport in (('ws', 'tcp'), ('grpc', 'tcp'), ('kcp', 'udp'), ('tcp', 'tcp')):
            with self.subTest(network=network):
                result = detector.parse_inbound_protocols(json.dumps({
                    'inbounds': [{'protocol': 'vmess', 'port': 443, 'network': network}],
                }), 'xray')
                self.assertEqual(result['endpoints'][0]['transports'], [transport])

    def test_unknown_xray_stream_method_stays_unattributed(self):
        result = detector.parse_inbound_protocols(json.dumps({
            'inbounds': [{
                'protocol': 'vmess', 'port': 443,
                'streamSettings': {'method': 'future-transport'},
            }],
        }), 'xray')
        self.assertNotIn('transports', result['endpoints'][0])

    def test_vmess_transport_mapping_correlates_to_exact_live_socket(self):
        config = detector.parse_inbound_protocols(json.dumps({
            'inbounds': [{
                'protocol': 'vmess', 'port': 443,
                'streamSettings': {'method': 'websocket'},
            }],
        }), 'xray')
        configured = [{
            'pid': 120000, 'process': 'xray', **config['endpoints'][0],
        }]
        inventory, _ = agent._build_service_inventory(
            {
                'connection_metrics': {'valid': True},
                'listening_ports': [443],
                'listening_endpoints': ['0.0.0.0:443'],
                'udp_listening_ports': [443],
            },
            {
                'communication_detail_available': True,
                'communication_snapshot_truncated': False,
                'service_listeners': [{
                    'process': 'xray', 'pid': 120000, 'proto': 'tcp',
                    'local': '0.0.0.0:443', 'port': 443,
                    'source': 'ss_process_owner',
                }],
            },
            configured,
        )
        tcp = next(item for item in inventory if item['proto'] == 'tcp' and item['port'] == 443)
        udp = next(item for item in inventory if item['proto'] == 'udp' and item['port'] == 443)
        self.assertEqual(tcp['application_protocols'], ['vmess'])
        self.assertNotIn('application_protocols', udp)

    def test_bad_or_oversized_input_is_unverified_not_negative_proof(self):
        for raw in ('{','[]','{"inbounds":{}}','{"inbounds":[5]}',' '*262145):
            self.assertFalse(detector.parse_config(raw,'xray')['parsed'])

    def test_real_executable_and_explicit_path_only(self):
        output='1 S supervise-daemo supervise-daemon xray --start\n12 S xray /usr/bin/xray run -config /opt/proxy/test.json\n'
        self.assertEqual(detector.process_configs(output),[{'pid':12,'process':'xray','paths':['/opt/proxy/test.json'],'config_dirs':[],'additional_configs':False}])

    def test_supported_config_directory_is_returned_for_bounded_scan(self):
        output='12 S xray /usr/bin/xray run -config /etc/xray/config.json -confdir /etc/xray/conf.d'
        result = detector.process_configs(output)[0]
        self.assertEqual(result['config_dirs'], ['/etc/xray/conf.d'])
        self.assertFalse(result['additional_configs'])

    def test_unreadable_or_truncated_config_paths_make_inventory_incomplete(self):
        toml = detector.process_configs('12 S xray /usr/bin/xray run -c /etc/xray/config.toml')[0]
        self.assertEqual(toml['paths'], [])
        self.assertTrue(toml['additional_configs'])
        paths = ' '.join(f'-c /etc/xray/{index}.json' for index in range(5))
        truncated = detector.process_configs(f'12 S xray /usr/bin/xray run {paths}')[0]
        self.assertEqual(len(truncated['paths']), 5)
        self.assertFalse(truncated['additional_configs'])

    def test_invalid_and_non_integer_ports_remain_unverified(self):
        for port in (float('inf'),1080.5,True,{},'1080-1085',70000):
            result=detector.parse_config(json.dumps({'inbounds':[{'protocol':'socks','port':port}]}),'xray')
            self.assertFalse(result['parsed'])

    def test_outbound_only_gost_cli_does_not_infer_noauth(self):
        facts=agent._socks_process_evidence('12 S gost /usr/bin/gost -L http://:443 -F socks5://:1080','')
        self.assertEqual(facts['auth_mode'],'unknown')
        self.assertFalse(facts['process_matches'][0]['listener_declared'])


class ExposureTests(unittest.TestCase):
    def test_loopback_is_not_exposed_by_unrelated_port_mapping(self):
        l={'local':'127.0.0.1:1080'}
        self.assertFalse(detector.exposed(l,[{'target':'tcp:10.0.0.2:1080','listen':'tcp:0.0.0.0:8080'}]))
        self.assertFalse(detector.exposed(l,[{'target':'tcp:127.0.0.1:443','listen':'tcp:0.0.0.0:8080'}]))

    def test_explicit_loopback_proxy_forward_is_exposed(self):
        self.assertTrue(detector.exposed({'local':'127.0.0.1:1080'},
            [{'connect':'tcp:127.0.0.1:1080','listen':'tcp:0.0.0.0:8080'}]))

    def test_ipv6_loopback_and_wildcards(self):
        self.assertFalse(detector.exposed({'local':'[::1]:1080'},[]))
        self.assertFalse(detector.exposed({'local':'[::ffff:127.0.0.1]:1080'},[]))
        for address in ('*:1080','[::]:1080','0.0.0.0:1080','10.0.0.2:1080'):
            self.assertTrue(detector.exposed({'local':address},[]))


class LiveEvidenceTests(unittest.TestCase):
    def setUp(self):
        agent._socks_probe_cache.clear()
        self.socks={'detected':True,'process_matches':[{'pid':12,'process':'xray','config_scoped':True,'action_safe':False}],
            'inbound_endpoints':[{'pid':12,'process':'xray','port':1080,'listen':'*','auth_state':'no_auth','action_safe':False}]}
        self.listeners=[{'pid':12,'process':'xray','port':443,'proto':'tcp','local':'*:443'},
            {'pid':12,'process':'xray','port':1080,'proto':'tcp','local':'*:1080'}]

    def refine(self, result='no_auth'):
        with mock.patch.object(agent,'_probe_socks_listener',return_value={'mode':result,'reason':'test'}) as probe:
            agent._refine_socks_listener_evidence(self.socks,self.listeners,[],'incus','fixture','default',222)
        return probe

    def test_mixed_engine_keeps_non_socks_listener_and_process_running(self):
        probe=self.refine()
        self.assertEqual(probe.call_count,1)
        self.assertEqual(self.socks['listening_ports'],[1080])
        self.assertEqual(self.socks['auth_mode'],'no_auth')
        self.assertFalse(self.socks['process_matches'][0]['action_safe'])
        container={'runtime':'incus','name':'fixture','security':{'socks_proxy':self.socks}}
        with mock.patch.object(agent,'stop_unauthenticated_socks') as stop:
            result=agent.enforce_socks_auth_policy(container,[])
        stop.assert_not_called(); self.assertFalse(result['attempted'])

    def test_loopback_dependency_is_not_stopped_even_by_previous_policy(self):
        self.listeners=self.listeners[1:]
        self.listeners[0]['local']='127.0.0.1:1080'
        self.socks['inbound_endpoints'][0]['listen']='127.0.0.1'
        self.assertEqual(self.refine().call_count,0)
        self.assertTrue(self.socks['internal_only'])
        container={'runtime':'incus','name':'fixture','security':{'socks_proxy':self.socks}}
        with mock.patch.object(agent,'stop_unauthenticated_socks') as stop:
            result=agent.enforce_socks_auth_policy(container,[])
        stop.assert_not_called(); self.assertEqual(result['reason'],'internal_loopback_dependency')

    def test_handshake_required_is_not_proof_of_strong_password(self):
        self.socks['inbound_endpoints'][0]['auth_state']='unknown'
        self.refine('auth_required')
        self.assertEqual(self.socks['auth_mode'],'unknown')
        self.assertFalse(self.socks['process_matches'][0]['action_safe'])

    def test_timeout_is_unknown_and_not_automatically_stopped(self):
        self.refine('unknown')
        self.assertEqual(self.socks['auth_mode'],'unknown')
        self.assertFalse(self.socks['process_matches'][0]['action_safe'])

    def test_dedicated_confirmed_public_proxy_can_be_stopped(self):
        self.socks['inbound_endpoints'][0]['action_safe']=True
        self.listeners=self.listeners[1:]
        self.refine()
        container={'runtime':'incus','name':'fixture','security':{'socks_proxy':self.socks}}
        with mock.patch.object(agent,'stop_unauthenticated_socks',return_value=(True,'fixture stopped')) as stop:
            result=agent.enforce_socks_auth_policy(container,[])
        self.assertTrue(result['attempted']); self.assertEqual(stop.call_args[0][0]['params']['process_pids'],[12])

    def test_extra_live_listener_overrides_stale_single_purpose_config(self):
        self.socks['inbound_endpoints'][0]['action_safe']=True
        self.refine()
        self.assertFalse(self.socks['process_matches'][0]['action_safe'])

    def test_extra_udp_listener_also_prevents_whole_engine_stop(self):
        self.socks['inbound_endpoints'][0]['action_safe']=True
        self.listeners[0]['proto']='udp'
        self.refine()
        self.assertFalse(self.socks['process_matches'][0]['action_safe'])

    def test_config_loopback_cannot_authenticate_wildcard_listener(self):
        self.socks['inbound_endpoints'][0]['listen']='127.0.0.1'
        self.assertEqual(self.refine().call_count,0)
        self.assertFalse(self.socks['detected'])

    def test_failed_probe_backoff_and_bounded_cache(self):
        key=('incus','default','fixture')
        listener=self.listeners[1]
        with mock.patch.object(agent.shutil,'which',return_value='/usr/bin/nsenter'), \
             mock.patch.object(agent.subprocess,'run',return_value=mock.Mock(returncode=0,stdout='unknown')) as run:
            for now in (100.,131.,162.,193.):
                with mock.patch.object(agent.time,'monotonic',return_value=now):
                    last=agent._probe_socks_listener(222,key,listener)
        self.assertEqual(run.call_count,3)
        self.assertEqual(last['reason'],'probe_cooldown')

    def test_probe_never_connects_in_host_namespace_when_namespace_missing(self):
        with mock.patch.object(agent.subprocess,'run') as run:
            result=agent._probe_socks_listener(0,('fixture',),self.listeners[1])
        run.assert_not_called(); self.assertEqual(result['mode'],'unknown')

    def test_real_greeting_only_no_credentials_or_connect_payload(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1',0)); server.listen(1)
            received=[]
            def accept():
                with server.accept()[0] as peer:
                    peer.settimeout(2); received.append(peer.recv(128))
                    peer.sendall(b'\x05'); peer.sendall(b'\x02')
                    received.append(peer.recv(128))
            thread=threading.Thread(target=accept); thread.start()
            result=subprocess.run([sys.executable,'-c',detector.PROBE_CODE,
                json.dumps(['127.0.0.1',server.getsockname()[1]])],capture_output=True,text=True,timeout=5)
            thread.join(timeout=3)
        self.assertEqual(result.stdout.strip(),'auth_required')
        self.assertEqual(received,[b'\x05\x02\x00\x02',b''])

    def test_packaging_and_installers_include_detector(self):
        root=Path(__file__).resolve().parents[1]
        dockerfile=(root/'client/Dockerfile').read_text(encoding='utf-8')
        installer=(root/'scripts/install-client.sh').read_text(encoding='utf-8')
        updater=(root/'scripts/managed-client-update.sh').read_text(encoding='utf-8')
        self.assertIn('COPY socks_detector.py .',dockerfile)
        self.assertIn('COPY host_security_audit.py .',dockerfile)
        self.assertIn('COPY vmess_guard.py .',dockerfile)
        self.assertIn('COPY manual_bandwidth.py .',dockerfile)
        self.assertIn('client/socks_detector.py',installer)
        self.assertIn('client/host_security_audit.py',installer)
        self.assertIn('client/vmess_guard.py',installer)
        self.assertIn('client/manual_bandwidth.py',installer)
        self.assertEqual(updater.count('vmess_guard manual_bandwidth; do'),2)
        self.assertIn('"$stage/client/manual_bandwidth.py"',updater)
        self.assertIn('"$snapshot/manual_bandwidth.py"',updater)


if __name__=='__main__': unittest.main()
