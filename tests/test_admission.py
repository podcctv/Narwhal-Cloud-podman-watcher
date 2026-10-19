import copy
import asyncio
import hashlib
import hmac
import os
import shutil
import subprocess
import json
import socket
import struct
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock
from client import admission_policy as p, admission_linux as linux, admission_guard as guard, pasarguard_guard as pasar
from server import admission_api
from fastapi import HTTPException
from fastapi import FastAPI
from starlette.requests import Request


def flow(n):return ('10.9.0.2',443,'192.0.2.1',10000+n)


class PolicyTests(unittest.TestCase):
    def sample(self,state,count,now,inbound=()):
        return state.observe({flow(i) for i in range(count)},list(inbound),set(inbound),now,epoch='boot:net:pid')

    def limited(self):
        state=p.Policy()
        for stamp in range(1000,1121,10):self.sample(state,1001,stamp)
        self.assertTrue(state.data['limited'])
        return state

    def test_strict_trigger_and_gap(self):
        state=p.Policy()
        for stamp in range(1000,1301,10):self.sample(state,1000,stamp)
        self.assertFalse(state.data.get('limited',False))
        self.sample(state,1001,1310)
        state.observe([],[],[],1320,valid=False)
        for stamp in range(1330,1441,10):self.sample(state,1001,stamp)
        self.assertFalse(state.data.get('limited',False))
        self.sample(state,1001,1450)
        self.assertTrue(state.data['limited'])

    def test_renew_exact500_once_and_minimum_period(self):
        state=self.limited();deadline=state.data['review_at']
        for stamp in range(1130,deadline+1,10):self.sample(state,500,stamp)
        self.assertEqual(state.data['extensions'],1)
        self.assertEqual(state.data['review_at'],deadline+1800)
        self.sample(state,500,deadline+10)
        self.assertEqual(state.data['extensions'],1)
        for stamp in range(deadline+20,deadline+1801,10):self.sample(state,499,stamp)
        self.assertFalse(state.data['limited'])

    def test_missing_restart_out_of_order_cannot_release(self):
        state=self.limited();deadline=state.data['review_at']
        restored=p.Policy(copy.deepcopy(state.data))
        self.sample(restored,0,deadline)
        self.assertTrue(restored.data['limited'])
        self.sample(restored,0,deadline-10)
        self.assertEqual(restored.data['sampled_at'],deadline)
        for stamp in range(deadline+10,deadline+121,10):self.sample(restored,0,stamp)
        self.assertFalse(restored.data['limited'])

    def test_combined_five_and_persistent_first_order(self):
        state=p.Policy();sources=['192.0.2.1','2001:db8::1','192.0.2.2','2001:db8::2','192.0.2.3','2001:db8::3']
        self.sample(state,1,1000,sources)
        self.assertEqual([x['ip'] for x in state.data['sources']],sources[:5])
        self.assertFalse(state.admit_source(sources[5],1001)[0])
        self.assertTrue(state.admit_source('::ffff:192.0.2.1',1002)[0])
        restored=p.Policy(copy.deepcopy(state.data))
        self.sample(restored,1,1010,list(reversed(sources)))
        self.assertEqual([x['ip'] for x in restored.data['sources']],sources[:5])
        self.sample(restored,1,1020,sources[1:5])
        self.assertTrue(restored.admit_source(sources[5],1021)[0])
        self.assertEqual(restored.data['sources'][-1]['ip'],sources[5])

    def test_pending_reservations_prevent_burst_and_stale_admission(self):
        state=self.limited();self.sample(state,499,1130)
        self.assertTrue(state.admit_tcp(flow(9000),1131))
        self.assertTrue(state.admit_tcp(flow(9000),1132))
        self.assertFalse(state.admit_tcp(flow(9001),1132))
        self.assertFalse(state.admit_tcp(flow(9002),1161))

    def test_denial_counters_bounded(self):
        state=p.Policy();state.seed([f'192.0.2.{n}' for n in range(1,6)],1000)
        for n in range(1,101):state.admit_source(f'198.51.100.{n}',1001)
        self.assertEqual(len(state.data['blocked']),32)
        self.assertEqual(state.data['blocked_packets'],100)


class LinuxTests(unittest.TestCase):
    def test_failed_write_then_restart_retries_desired_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal=guard.isolation.Journal(str(Path(tmp)/'state.json'))
            nft=mock.Mock();nft.digests={}
            table=''
            def live(name):
                nft.digests[name]='unchanged-kernel-definition'
                return {'192.0.2.1'}
            nft.live.side_effect=live
            g=guard.Guard(journal=journal,nft=nft,queues=mock.Mock())
            c={'runtime':'incus','project':'default','name':'test'}
            snap={'instance_id':'a'*36,'ips':['10.9.0.2'],'interfaces':['br-test'],'epoch':'boot:net:pid','flows':{flow(i) for i in range(1001)},'inbound':['192.0.2.1']}
            g.update(c,snap,1000)
            next(iter(g.states.values())).data['above_since']=890
            nft.apply.side_effect=RuntimeError('simulated atomic write failure')
            with self.assertRaises(RuntimeError):g.update(c,snap,1010)
            g.failed(c,1010)
            nft.apply.side_effect=None
            restored=guard.Guard(journal=journal,nft=nft,queues=mock.Mock())
            result=restored.update(c,snap,1020)
            self.assertTrue(result['limited'])
            self.assertEqual(result['state'],'enforced')
            self.assertTrue(nft.apply.call_args.args[4])

    def test_rules_forward_scope_and_no_bypass(self):
        text=linux.rules('nwguard_'+'a'*16,['10.9.0.2','2001:db8::2'],20000,[],True,interfaces=['br-test'])
        self.assertIn('oifname { "br-test" } ip daddr',text)
        self.assertIn('iifname { "br-test" } ip6 saddr',text)
        for forbidden in ('flush ruleset','hook input','hook output','bypass','reject with tcp reset'):
            self.assertNotIn(forbidden,text)
        with self.assertRaises(ValueError):linux.rules('nwguard_'+'a'*16,['10.9.0.2'],20000,[])

    def test_packet_parser(self):
        raw=bytearray(24);raw[0]=0x45;raw[9]=6
        raw[12:16]=socket.inet_aton('192.0.2.1');raw[16:20]=socket.inet_aton('10.9.0.2');raw[20:24]=struct.pack('!HH',123,443)
        self.assertEqual(linux.packet(raw),('192.0.2.1','10.9.0.2',6,123,443))
        raw[6]=1
        with self.assertRaises(ValueError):linux.packet(raw)

    def test_failed_sample_breaks_duration(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal=guard.isolation.Journal(str(Path(tmp)/'state.json'))
            g=guard.Guard(journal=journal,nft=mock.Mock(),queues=mock.Mock())
            c={'runtime':'incus','project':'default','name':'test'}
            snap={'instance_id':'a'*36,'ips':['10.9.0.2'],'interfaces':['br-test'],'epoch':'boot:net:pid','flows':{flow(i) for i in range(1001)},'inbound':['192.0.2.1']}
            g.nft.live.return_value={'192.0.2.1'}
            g.update(c,snap,1000)
            g.failed(c,1010)
            self.assertEqual(next(iter(g.states.values())).data['above_since'],0)
            self.assertEqual(g.status(c)['state'],'unverified')

    def test_tcp_cap_does_not_hide_sixth_source_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            nft=mock.Mock();nft.digests={}
            g=guard.Guard(journal=guard.isolation.Journal(str(Path(tmp)/'state.json')),nft=nft,queues=mock.Mock())
            c={'runtime':'incus','project':'default','name':'test'}
            now=int(time.time());sources=[f'192.0.2.{n}' for n in range(1,6)]
            nft.live.return_value=set(sources)
            snap={'instance_id':'a'*36,'ips':['10.9.0.2'],'interfaces':['br-test'],'epoch':'boot:net:pid','flows':{flow(i) for i in range(500)},'inbound':sources}
            g.update(c,snap,now)
            state=next(iter(g.states.values()));state.data['limited']=True
            raw=bytearray(24);raw[0]=0x45;raw[9]=6
            raw[12:16]=socket.inet_aton('198.51.100.6');raw[16:20]=socket.inet_aton('10.9.0.2');raw[20:24]=struct.pack('!HH',123,443)
            queue=next(iter(g.records.values()))['queue']
            self.assertFalse(g.decision(queue,raw))
            self.assertIn('198.51.100.6',state.data['blocked'])
            self.assertEqual(len(state.data['sources']),5)


class PasarTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('go'),'Go ELF identity integration')
    def test_actual_stripped_go_build_info_not_generic_main(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'main'
            fixture=Path(__file__).parent/'fixtures'/'pasarguard-identity'
            subprocess.run(['go','build','-trimpath','-ldflags=-s -w -buildid=','-o',str(binary),'./cmd/node'],cwd=fixture,
                env={**os.environ,'GOOS':'linux','GOARCH':'amd64','CGO_ENABLED':'0'},check=True,capture_output=True,timeout=90)
            self.assertEqual(pasar.go_module(binary),'github.com/pasarguard/node/cmd/node')
    def test_exact_images_and_digest(self):
        for image in ('pasarguard/node','pasarguard/node:latest','pasarguard/node@sha256:abc','ghcr.io/pasarguard/node:v1@sha256:abc'):
            self.assertTrue(pasar.image_match(image),image)
        for image in ('main','node','xray','evil/pasarguard/node','pasarguard/node-backup','example.com/pasarguard/node'):
            self.assertFalse(pasar.image_match(image),image)

    def test_no_generic_process_kill_or_outer_delete(self):
        text=pasar.cleanup_script({'pid':42,'start_ticks':'123','executable':'/app/main','unit':'pg-node.service'})
        self.assertIn('expected=123',text)
        self.assertIn('readlink /proc/$p/exe',text)
        for forbidden in ('pkill','killall','rm -rf','compose down','incus delete'):
            self.assertNotIn(forbidden,text)
        with self.assertRaises(ValueError):pasar.cleanup_script({'pid':1,'start_ticks':'123','executable':'/app/main'})


class ReceiptTests(unittest.TestCase):
    def test_bounded_evidence_and_no_secret(self):
        value={'type':'inbound_source_blocked','runtime':'podman','container_name':'customer','instance_id':'a'*64,
            'admission':{'state':'enforced','observed_at':int(time.time()),'sources':[{'ip':'192.0.2.1','first_seen':1000}],'password':'NEVER-SEND','blocked':{'2001:db8::1':{'packets':2,'last_seen':1000}}}}
        result=admission_api.normalized_alert(value)
        self.assertNotIn('NEVER-SEND',json.dumps(result))
        self.assertEqual(result['admission']['source_limit'],5)
        value['admission']['observed_at']=1000
        with self.assertRaises(HTTPException):admission_api.normalized_alert(value)
        value['runtime']='docker'
        with self.assertRaises(HTTPException):admission_api.normalized_alert(value)


class APITests(unittest.TestCase):
    def setUp(self):
        from server import app as server
        self.server=server
        self.tmp=tempfile.TemporaryDirectory()
        self.patch=mock.patch.multiple(server,DB_PATH=str(Path(self.tmp.name)/'monitor.db'),SHARED_SECRET='fixture-secret')
        self.patch.start();server.init_db()
        with closing(server.db()) as conn:
            conn.execute("INSERT INTO hosts VALUES('fixture',?,'test','node','{}')",(int(time.time()),))
            conn.commit()
        app=FastAPI()
        admission_api.attach(app,server.db,server.verify_signature,server.signed_json_response,server.process_security_alerts,mock.Mock(),mock.Mock())
        self.routes={r.path:r.endpoint for r in app.routes if r.path.startswith('/api/v1/admission/')}

    def tearDown(self):
        self.patch.stop();self.tmp.cleanup()

    def call(self,route,payload):
        body=json.dumps(payload).encode();stamp=str(int(time.time()))
        signature=hmac.new(b'fixture-secret',body+stamp.encode(),hashlib.sha256).hexdigest()
        async def receive():return {'type':'http.request','body':body,'more_body':False}
        request=Request({'type':'http','method':'POST','path':'/','headers':[]},receive)
        return asyncio.run(self.routes[route](request,stamp,signature))

    def value(self):
        return {'runtime':'incus','project':'default','container_name':'customer','instance_id':'a'*36,
                'type':'inbound_source_blocked','admission':{'state':'enforced','observed_at':int(time.time()),'sources':[], 'blocked':{}}}

    def test_wrong_node_rejected_and_status_upserts_not_appends(self):
        payload={'host_id':'fixture','node_id':'another','items':[self.value()]}
        with self.assertRaises(HTTPException):self.call('/api/v1/admission/status',payload)
        payload['node_id']='node'
        for _ in range(3):self.call('/api/v1/admission/status',payload)
        with closing(self.server.db()) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM admission_states').fetchone()[0],1)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM security_alerts').fetchone()[0],0)

    def test_events_deduplicate_and_delivery_failure_keeps_receipt(self):
        payload={'host_id':'fixture','node_id':'node','alert':self.value()}
        for _ in range(2):self.call('/api/v1/admission/events',payload)
        with closing(self.server.db()) as conn:
            row=conn.execute('SELECT * FROM security_alerts').fetchall()
            self.assertEqual(len(row),1)
            self.assertEqual(row[0]['occurrence_count'],2)


if __name__=='__main__':unittest.main()
