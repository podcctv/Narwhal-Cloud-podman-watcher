"""Public probe boundaries and persistent, atomic resource protection."""
import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from fastapi import HTTPException
from fastapi.testclient import TestClient
os.environ["TCPING_TAIWAN_HOST"] = "taiwan-target.invalid"
from server import app as server, tcping, operations
from client import tcp_probe

# Other test modules may import server.tcping before this module is loaded.
tcping.TAIWAN_HOST = "taiwan-target.invalid"


def raw_directory():
    return {"UpdatedAt": "2026-09-15T12:27:24Z",
            "ProvinceNodes": [{"province": p, "carriers": {c: f"p{i}-{c}-v4.ip.zstaticcdn.com:80" for c in sorted(tcping.CARRIERS)}} for i, p in enumerate(sorted(tcping.PROVINCES))],
            "CityNodes": [{"province": "北京", "city": f"合成城市{i}", "carrier": "mobile", "endpoint": f"bj-city{i}-cm-v4.ip.zstaticcdn.com:443"} for i in range(223)]}


class ProbeStateTests(unittest.TestCase):
    def setUp(self):
        self.connections = []
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name)/"probe.db")
        self.now = int(time.time())
        self.source = str(uuid.uuid4())
        self.node = str(uuid.uuid4())
        c = self.db()
        c.execute("CREATE TABLE hosts(host_id TEXT PRIMARY KEY,node_id TEXT,last_seen INTEGER,config_json TEXT)")
        operations.initialize(c)
        tcping.initialize(c)
        directory = tcping.normalize_directory(raw_directory())
        c.execute("INSERT INTO tcp_directories VALUES(?,?,?)", (directory["generation"], tcping.encoded(directory), self.now))
        c.execute("UPDATE tcp_settings SET value='true' WHERE key='enabled'")
        self.add_source(c, self.source, self.node)
        c.commit()
        c.close()

    def tearDown(self):
        for connection in self.connections:
            try:
                connection.close()
            except sqlite3.ProgrammingError:
                pass  # Worker-thread connections close in admit() itself.
        self.temp.cleanup()

    def db(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        self.connections.append(c)
        return c

    def add_source(self, c, source_id, node_id):
        host = "internal-host-" + source_id
        c.execute("INSERT INTO hosts(host_id,node_id,last_seen,config_json) VALUES(?,?,?,?)", (host, node_id, self.now, "{}"))
        c.execute("INSERT INTO ops_hosts VALUES(?,?,?,?)", (node_id, host, self.now, json.dumps({"capabilities": [tcping.CAPABILITY]})))
        c.execute("INSERT INTO tcp_sources(id,host_id,node_id,name,enabled) VALUES(?,?,?,'Synthetic VPS',1)", (source_id, host, node_id))

    def admit(self, scope="province", source=None, now=None):
        c = self.db()
        try:
            return tcping.admit(c, source or self.source, scope, now or self.now)
        finally:
            c.close()

    def lease(self):
        c = self.db()
        c.execute("BEGIN IMMEDIATE")
        job = tcping.lease_jobs(c, "internal-host-"+self.source, self.node, self.now)["job"]
        c.commit()
        c.close()
        return job

    def batch(self, lease, rows=None, sequence=0, done=False, outcome=""):
        return {"job_id": lease["id"], "host_id": "internal-host-"+self.source, "node_id": self.node,
                "lease": lease["lease"], "generation": lease["generation"], "target_hash": lease["target_hash"],
                "sequence": sequence, "rows": rows or [], "done": done, "outcome": outcome}

    def report(self, p, now=None):
        c = self.db()
        try:
            return tcping.report(c, p, now or self.now)
        finally:
            c.close()

    def test_directory_counts_endpoint_allowlist_and_client_agree(self):
        d = tcping.normalize_directory(raw_directory())
        self.assertEqual(d["counts"], {"province_groups":31,"province_nodes":93,"city_nodes":223,"total":316,"unique_endpoints":316})
        tcp_probe.validate_targets(d["nodes"])
        for bad in ("127.0.0.1:80", "evil.example:443", "bj-cm-v4.ip.zstaticcdn.com.evil.test:80", "bj-cm-v4.ip.zstaticcdn.com:22", "bj-cm-v4.ip.zstaticcdn.com:80;id"):
            r = raw_directory()
            r["ProvinceNodes"][0]["carriers"]["mobile"] = bad
            with self.assertRaises(ValueError):
                tcping.normalize_directory(r)
        r = raw_directory()
        r["CityNodes"].append(r["CityNodes"][0])
        with self.assertRaises(ValueError):
            tcping.normalize_directory(r)

    def test_twenty_concurrent_requests_share_one_persistent_job(self):
        with ThreadPoolExecutor(max_workers=20) as pool:
            outcomes = list(pool.map(lambda _: self.admit(), range(20)))
        self.assertEqual(len({r["job"]["id"] for r in outcomes}), 1)
        self.assertEqual(sum(not r["reused"] for r in outcomes), 1)
        self.assertEqual(self.admit("all")["reused"], "running")
        c = self.db()
        self.assertEqual(c.execute("SELECT COUNT(*) FROM tcp_jobs").fetchone()[0], 1)
        c.close()

    def test_startup_repairs_renamed_default_source_without_resetting_identity(self):
        c = self.db()
        old = "internal-host-"+self.source
        new = "[Hytron2.0][AdguardVPN+Hurricane Electric + 公益家宽]船新上线"
        c.execute("UPDATE tcp_sources SET name=host_id,region='香港',purchase_url='https://example.com/plan' WHERE id=?", (self.source,))
        c.execute("INSERT INTO tcp_cooldowns VALUES(?,?)", (self.node,self.now+900))
        c.execute("UPDATE hosts SET host_id=? WHERE node_id=?", (new,self.node))
        c.commit()
        tcping.initialize(c)
        source = c.execute("SELECT * FROM tcp_sources WHERE id=?", (self.source,)).fetchone()
        self.assertEqual((source['host_id'],source['name'],source['node_id'],source['revision']), (new,new,self.node,1))
        self.assertEqual((source['region'],source['purchase_url'],source['enabled']), ('香港','https://example.com/plan',1))
        self.assertEqual(tcping.source_item(c,source,self.now)['status'], 'ready')
        self.assertEqual(c.execute('SELECT next_at FROM tcp_cooldowns WHERE node_id=?',(self.node,)).fetchone()[0],self.now+900)
        tcping.initialize(c)
        self.assertEqual(c.execute('SELECT count(*) FROM tcp_sources').fetchone()[0],1)
        c.close()

    def test_startup_preserves_custom_public_name_and_rejects_other_node(self):
        c = self.db()
        old = "internal-host-"+self.source
        c.execute("UPDATE hosts SET host_id='renamed-host' WHERE node_id=?", (self.node,))
        c.execute("INSERT INTO hosts(host_id,node_id,last_seen,config_json) VALUES(?,?,?,?)",(old,'replacement-node',self.now,'{}'))
        c.commit()
        tcping.initialize(c)
        source = c.execute('SELECT * FROM tcp_sources WHERE id=?',(self.source,)).fetchone()
        self.assertEqual((source['host_id'],source['name'],source['node_id']),('renamed-host','Synthetic VPS',self.node))
        c.execute('DELETE FROM hosts WHERE node_id=?',(self.node,));c.commit()
        tcping.initialize(c)
        source = c.execute('SELECT * FROM tcp_sources WHERE id=?',(self.source,)).fetchone()
        self.assertEqual(tcping.host_state(c,source,self.now),'identity_changed')
        self.assertEqual(source['node_id'],self.node)
        c.close()

    def test_rename_cancels_old_active_leases_but_keeps_results_and_cooldown(self):
        job = self.admit()['job']
        lease = self.lease()
        row = {'target_id':lease['targets'][0]['id'],'ip':'1.1.1.1','samples_ms':[1.0,2.0],'error':''}
        self.report(self.batch(lease,[row]))
        c = self.db()
        before = c.execute('SELECT next_at FROM tcp_cooldowns WHERE node_id=?',(self.node,)).fetchone()[0]
        c.execute("UPDATE hosts SET host_id='renamed-host' WHERE node_id=?",(self.node,));c.commit()
        tcping.initialize(c);c.commit()
        result = tcping.get_job(c,job['id'])
        self.assertEqual((result['status'],result['completed']),('cancelled',1))
        self.assertIn('改名',result['message'])
        self.assertEqual(c.execute('SELECT next_at FROM tcp_cooldowns WHERE node_id=?',(self.node,)).fetchone()[0],before)
        c.close()
        with self.assertRaises(HTTPException) as error:
            self.report(self.batch(lease,sequence=1))
        self.assertEqual(error.exception.status_code,409)
        with self.assertRaises(HTTPException) as error:
            self.admit()
        self.assertEqual(error.exception.status_code,429)

    def test_owner_taiwan_target_is_fixed_counted_and_not_upstream(self):
        result = tcping.configured_directory(raw_directory())
        self.assertEqual(result["counts"]["province_groups"], 31)
        self.assertEqual(result["counts"]["province_nodes"], 93)
        self.assertEqual(result["counts"]["city_nodes"], 223)
        self.assertEqual(result["counts"]["total"], 317)
        self.assertEqual(result["counts"]["unique_endpoints"], 317)
        self.assertEqual(result["counts"]["province_targets"], 94)
        self.assertEqual(result["counts"]["zstatic_total"], 316)
        taiwan = result["nodes"][-1]
        self.assertEqual((taiwan["province"], taiwan["host"], taiwan["port"]), ("台湾", tcping.TAIWAN_HOST, 36901))
        tcp_probe.validate_targets(result["nodes"])
        for changes in ({"host":"127.0.0.1"}, {"port":22}, {"province":"北京"}, {"carrier":"mobile"}):
            bad = {**taiwan, **changes}
            bad["id"] = tcp_probe.digest({k:v for k,v in bad.items() if k != "id"})[:20]
            with self.assertRaises(ValueError):
                tcp_probe.validate_targets([bad])
        self.assertTrue(tcp_probe.allowed_host(tcping.TAIWAN_HOST))
        self.assertFalse(tcp_probe.allowed_host("127.0.0.1"))

    def test_taiwan_migration_preserves_cache_age_and_old_job_targets(self):
        old = self.admit()["job"]
        c = self.db()
        base = tcping.normalize_directory(raw_directory())
        targeted = tcping.configured_directory(raw_directory())
        c.execute("DELETE FROM tcp_directories")
        c.execute("INSERT INTO tcp_directories VALUES(?,?,?)", (targeted["generation"], tcping.encoded(targeted), self.now-300000))
        c.execute("INSERT INTO tcp_directories VALUES(?,?,?)", (base["generation"], tcping.encoded(base), self.now-200000))
        tcping.initialize(c)
        c.commit()
        current = tcping.directory(c)
        self.assertEqual(current["counts"]["total"], 317)
        self.assertEqual(current["fetched_at"], self.now-200000)
        self.assertTrue(current["stale"])
        self.assertEqual(len(tcping.get_job(c,old["id"])["nodes"]), 93)
        tcping.initialize(c)
        c.commit()
        self.assertEqual(c.execute("SELECT count(*) FROM tcp_directories").fetchone()[0], 2)
        c.close()

    def test_cooldown_survives_new_connection_and_scope_switch(self):
        job = self.admit()["job"]
        c = self.db()
        c.execute("UPDATE tcp_jobs SET status='failed',finished_at=? WHERE id=?", (self.now, job["id"]))
        c.commit()
        c.close()
        with self.assertRaises(HTTPException) as caught:
            self.admit("city")
        self.assertEqual(caught.exception.status_code, 429)
        self.assertEqual(caught.exception.detail["latest_job_id"], job["id"])
        self.assertEqual(caught.exception.headers["Retry-After"], "900")

    def test_lease_bound_to_node_and_public_dto_has_no_internal_identity(self):
        public = self.admit()["job"]
        self.assertEqual(len(public["nodes"]), 93)
        self.assertFalse({"lease","node_id","host_id","source_revision"} & public.keys())
        c = self.db()
        wrong = tcping.lease_jobs(c, "internal-host-"+self.source, "different-node", self.now)
        self.assertIsNone(wrong["job"])
        c.close()
        lease = self.lease()
        self.assertEqual(lease["node_id"], self.node)
        p = self.batch(lease)
        for key in ("lease", "node_id", "host_id", "generation", "target_hash"):
            bad = dict(p, **{key:"wrong"})
            with self.assertRaises(HTTPException):
                self.report(bad)

    def test_batch_replay_conflicts_terminal_and_complete_cache(self):
        job = self.admit()["job"]
        lease = self.lease()
        rows = [{"target_id": t["id"], "ip": "1.1.1.1", "samples_ms": [10.0, 20.0], "error": ""} for t in lease["targets"]]
        start = self.batch(lease)
        self.report(start)
        self.assertTrue(self.report(start)["duplicate"])
        with self.assertRaises(HTTPException):
            self.report(dict(start, rows=rows[:1]))
        for i in range(0, len(rows), 32):
            self.report(self.batch(lease, rows[i:i+32], i//32+1))
        final = self.batch(lease, sequence=5, done=True, outcome="complete")
        self.report(final)
        self.assertTrue(self.report(final)["duplicate"])
        with self.assertRaises(HTTPException):
            self.report(self.batch(lease, sequence=6))
        c = self.db()
        result = tcping.get_job(c, job["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["completed"], 93)
        self.assertEqual(result["nodes"][0]["result"]["median_ms"], 15.0)
        c.close()
        self.assertEqual(self.admit()["reused"], "cache")

    def test_bad_results_never_mutate_valid_job(self):
        self.admit()
        lease = self.lease()
        valid = {"target_id":lease["targets"][0]["id"], "ip":"1.1.1.1", "samples_ms":[1,2], "error":""}
        cases = [dict(valid, ip="127.0.0.1"), dict(valid, samples_ms=[True]), dict(valid, samples_ms=[float("nan")]),
                 dict(valid, error={}), dict(valid, samples_ms=[1,2,3]), dict(valid, target_id="not-selected"),
                 dict(valid, samples_ms=[None,1]), dict(valid, samples_ms=[], error="")]
        for value in cases:
            with self.assertRaises(HTTPException):
                self.report(self.batch(lease, [value], sequence=1))
        c = self.db()
        self.assertEqual(c.execute("SELECT COUNT(*) FROM tcp_results").fetchone()[0], 0)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM tcp_batches").fetchone()[0], 0)
        c.close()
        with self.assertRaises(HTTPException):
            self.report(dict(self.batch(lease), job_id=[]))

    def test_deadline_partial_and_last_good_directory_preserved(self):
        job = self.admit()["job"]
        lease = self.lease()
        row = {"target_id":lease["targets"][0]["id"],"ip":"","samples_ms":[],"error":"dns_error"}
        self.report(self.batch(lease, [row]))
        c = self.db()
        c.execute("UPDATE tcp_directories SET fetched_at=?", (self.now-200000,))
        tcping.expire(c, self.now+211)
        c.commit()
        result = tcping.get_job(c, job["id"])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["completed"], 1)
        self.assertIsNone(result["nodes"][1]["result"])
        self.assertTrue(tcping.directory(c)["stale"])
        c.close()
        with self.assertRaises(HTTPException):
            self.report(self.batch(lease, sequence=1), self.now+211)

    def test_global_active_budget_is_not_bypassed_by_another_source(self):
        self.admit()
        c = self.db()
        second, third = str(uuid.uuid4()), str(uuid.uuid4())
        self.add_source(c, second, str(uuid.uuid4()))
        self.add_source(c, third, str(uuid.uuid4()))
        c.commit(); c.close()
        self.admit(source=second)
        with self.assertRaises(HTTPException) as caught:
            self.admit(source=third)
        self.assertEqual(caught.exception.status_code, 429)

    def test_all_scopes_include_every_catalog_entry(self):
        first = self.admit("all")["job"]
        self.assertEqual(len(first["nodes"]), 316)
        self.assertEqual(first["samples"], 1)
        c = self.db()
        second = str(uuid.uuid4())
        self.add_source(c, second, str(uuid.uuid4()))
        c.commit(); c.close()
        city = self.admit("city", source=second)["job"]
        self.assertEqual(len(city["nodes"]), 223)
        self.assertEqual(city["samples"], 1)

    def test_hour_budget_remains_after_jobs_finish(self):
        for i in range(20):
            source = self.source
            if i:
                c = self.db()
                source = str(uuid.uuid4())
                self.add_source(c, source, str(uuid.uuid4()))
                c.commit(); c.close()
            job = self.admit(source=source)["job"]
            c = self.db()
            c.execute("UPDATE tcp_jobs SET status='cancelled',finished_at=? WHERE id=?", (self.now, job["id"]))
            c.commit(); c.close()
        c = self.db()
        extra = str(uuid.uuid4())
        self.add_source(c, extra, str(uuid.uuid4()))
        c.commit(); c.close()
        with self.assertRaises(HTTPException) as caught:
            self.admit(source=extra)
        self.assertEqual(caught.exception.status_code, 429)

    def test_withdrawal_and_identity_change_fail_closed(self):
        self.admit()
        lease = self.lease()
        c = self.db()
        c.execute("UPDATE hosts SET node_id='replaced'")
        c.commit(); c.close()
        with self.assertRaises(HTTPException):
            self.admit()
        with self.assertRaises(HTTPException):
            self.report(self.batch(lease))
        c = self.db()
        c.execute("UPDATE tcp_sources SET enabled=0")
        c.commit(); c.close()
        with self.assertRaises(HTTPException):
            self.report(self.batch(lease))
        c = self.db()
        with self.assertRaises(HTTPException):
            tcping.get_job(c, lease["id"])
        c.close()

    def test_purchase_link_is_navigation_only_and_rejects_credentials(self):
        url = "https://dash.fuckip.me/deploy?machine_id=" + str(uuid.uuid4())
        self.assertEqual(tcping.purchase_url(url), url)
        self.assertEqual(tcping.purchase_url(""), "")
        for url in ("javascript:alert(1)", "http://example.com", "https://user:pass@example.com", "https://example.com/?api_key=secret", "https://127.0.0.1/", "https://example.com/\n"):
            with self.assertRaises(HTTPException):
                tcping.purchase_url(url)

    def test_public_product_checkout_uses_available_plan_and_hides_sold_out_link(self):
        machine_id, plan_id = str(uuid.uuid4()), str(uuid.uuid4())

        def fetch(remaining):
            payload = {"code": 0, "data": {"id": machine_id, "name": "CloudCone LA",
                "region": "US", "status": "online", "vm_type": "incus", "plans": [
                    {"id": plan_id, "name": "1 GB", "status": "active", "remaining": remaining},
                    {"id": str(uuid.uuid4()), "name": "retired", "status": "inactive", "remaining": 99}]}}
            response = mock.MagicMock()
            response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
            with mock.patch.object(tcping.urllib.request, "urlopen", return_value=response):
                return tcping.fetch_public_product(machine_id)

        available = fetch(3)
        self.assertEqual((available["sale_status"], available["remaining"], available["virtualization_type"]), ("available", 3, "incus"))
        self.assertEqual(available["purchase_url"], f"https://dash.fuckip.me/deploy?machine_id={machine_id}&plan_id={plan_id}&region=US")
        sold_out = fetch(0)
        self.assertEqual((sold_out["sale_status"], sold_out["remaining"], sold_out["purchase_url"]), ("sold_out", 0, ""))

    def test_product_mapping_mismatch_fails_closed(self):
        product = {"product_id": str(uuid.uuid4()), "product_name": "商品 A", "virtualization_type": "podman",
                   "sale_status": "available", "remaining": 2, "purchase_url": "https://dash.fuckip.me/deploy?plan_id=wrong"}
        matched = tcping.verified_public_product(product, "  商品   A ")
        self.assertEqual(matched["mapping_state"], "verified")
        self.assertEqual(matched["purchase_url"], product["purchase_url"])
        mismatched = tcping.verified_public_product(product, "来源 B")
        self.assertEqual(mismatched["mapping_state"], "mismatch")
        self.assertEqual((mismatched["sale_status"], mismatched["remaining"], mismatched["purchase_url"], mismatched["virtualization_type"]),
                         ("unknown", None, "", ""))
        unverified = tcping.verified_public_product({**product, "product_name": ""}, "来源 B")
        self.assertEqual((unverified["mapping_state"], unverified["purchase_url"]), ("unverified", ""))


class ProbeHttpTests(ProbeStateTests):
    def setUp(self):
        self.connections = []
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name)/"monitor.db")
        self.now = int(time.time())
        self.source, self.node = str(uuid.uuid4()), str(uuid.uuid4())
        self.patch = mock.patch.multiple(server, DB_PATH=self.path, DASHBOARD_USERNAME="synthetic-admin", DASHBOARD_PASSWORD="synthetic-password", SHARED_SECRET="synthetic-shared")
        self.patch.start()
        server.init_db()
        c = server.db()
        d = tcping.normalize_directory(raw_directory())
        c.execute("INSERT INTO tcp_directories VALUES(?,?,?)", (d["generation"],tcping.encoded(d),self.now))
        c.execute("UPDATE tcp_settings SET value='true' WHERE key='enabled'")
        host = "internal-host-"+self.source
        c.execute("INSERT INTO hosts(host_id,node_id,last_seen) VALUES(?,?,?)", (host,self.node,self.now))
        c.execute("INSERT INTO ops_hosts VALUES(?,?,?,?)", (self.node,host,self.now,json.dumps({"capabilities":[tcping.CAPABILITY]})))
        c.execute("INSERT INTO tcp_sources(id,host_id,node_id,name,enabled) VALUES(?,?,?,'Synthetic VPS',1)", (self.source,host,self.node))
        c.commit(); c.close()
        self.client = TestClient(server.app, base_url="https://testserver",follow_redirects=False)

    def tearDown(self):
        self.client.close()
        self.patch.stop()
        for connection in self.connections:
            try:
                connection.close()
            except sqlite3.ProgrammingError:
                pass  # Worker-thread connections close in admit() itself.
        self.temp.cleanup()

    def test_signed_host_report_synchronizes_public_name_and_private_editing(self):
        old = 'internal-host-'+self.source
        new = '[Hytron2.0][AdguardVPN+Hurricane Electric + 公益家宽]船新上线'
        c = server.db()
        c.execute('UPDATE tcp_sources SET name=host_id WHERE id=?',(self.source,));c.commit();c.close()
        payload = {'host_id':new,'node_id':self.node,'agent_version':'1.7.23','timestamp':self.now,'containers':[], 'security':{'alerts':[]}}
        body = json.dumps(payload).encode();ts = str(self.now)
        signature = hmac.new(b'synthetic-shared',body+ts.encode(),hashlib.sha256).hexdigest()
        response = self.client.post('/api/v1/report',content=body,headers={'X-Timestamp':ts,'X-Signature':signature})
        self.assertEqual(response.status_code,200,response.text)
        sources = self.client.get(tcping.PUBLIC+'/sources').json()['items']
        source = next(s for s in sources if s['id']==self.source)
        self.assertEqual((source['name'],source['status']),(new,'ready'))
        self.assertNotIn('node_id',source)
        auth = ('synthetic-admin','synthetic-password')
        data = self.client.get('/api/v1/tcping/manage',auth=auth).json()
        private = next(s for s in data['sources'] if s['id']==self.source)
        self.assertEqual(private['host_id'],new)
        save = self.client.post('/api/v1/tcping/sources',auth=auth,json={'id':self.source,'host_id':new,'name':new,'region':'香港','purchase_url':'','enabled':True})
        self.assertEqual(save.status_code,200,save.text)
        self.assertNotIn(old,self.client.get(tcping.PUBLIC+'/sources').text)

    def test_public_pages_isolated_private_apis_unchanged(self):
        self.assertEqual(self.client.get("/tcping").status_code,200)
        self.assertEqual(self.client.get("/tcping/manage").status_code,303)
        c = self.db()
        d = tcping.configured_directory(raw_directory())
        c.execute("INSERT OR REPLACE INTO tcp_directories VALUES(?,?,?)", (d["generation"],tcping.encoded(d),self.now))
        c.commit(); c.close()
        with mock.patch.object(tcping,"refresh_directory"):
            directory_response = self.client.get(tcping.PUBLIC+"/directory")
        self.assertEqual(directory_response.json()["counts"]["total"],317)
        self.assertNotIn(tcping.TAIWAN_HOST, directory_response.text)
        self.assertEqual(next(n for n in directory_response.json()["nodes"] if n["carrier"] == "custom")["host"], tcping.PUBLIC_TAIWAN_TARGET_LABEL)
        self.assertEqual(directory_response.json()["custom_targets"][0]["host"], tcping.PUBLIC_TAIWAN_TARGET_LABEL)
        sources = self.client.get(tcping.PUBLIC+"/sources")
        self.assertEqual(sources.status_code,200)
        self.assertNotIn("node_id", sources.text)
        self.assertNotIn("internal-host", sources.text)
        for path in ("/api/v1/latest","/api/v1/commerce/overview","/api/v1/tcping/manage",tcping.PUBLIC+"/sources/admin"):
            self.assertEqual(self.client.get(path).status_code,401)
        self.assertEqual(self.client.post(tcping.PUBLIC+"/directory",json={}).status_code,401)
        self.assertEqual(self.client.post(tcping.PUBLIC+"/jobs",json={"source_id":self.source,"scope":"province"},headers={"Origin":"https://evil.test"}).status_code,403)
        created = self.client.post(tcping.PUBLIC+"/jobs",json={"source_id":self.source,"scope":"province"})
        self.assertEqual(created.status_code,200,created.text)
        self.assertNotIn("lease",created.text)
        self.assertNotIn(tcping.TAIWAN_HOST, created.text)
        job_id = created.json()["job"]["id"]
        public_job = self.client.get(tcping.PUBLIC+"/jobs/"+job_id)
        self.assertEqual(public_job.status_code,200)
        self.assertNotIn(tcping.TAIWAN_HOST, public_job.text)
        self.assertEqual(next(n for n in public_job.json()["nodes"] if n["carrier"] == "custom")["host"], tcping.PUBLIC_TAIWAN_TARGET_LABEL)
        c = self.db()
        raw_job = c.execute("SELECT targets FROM tcp_jobs WHERE id=?", (job_id,)).fetchone()
        self.assertEqual(next(n for n in json.loads(raw_job[0]) if n["carrier"] == "custom")["host"], tcping.TAIWAN_HOST)
        lease = tcping.lease_jobs(c, "internal-host-"+self.source, self.node, self.now)["job"]
        self.assertEqual(next(n for n in lease["targets"] if n["carrier"] == "custom")["host"], tcping.TAIWAN_HOST)
        c.commit(); c.close()

    def test_public_source_catalog_exposes_only_name_verified_checkout(self):
        machine_id, plan_id = str(uuid.uuid4()), str(uuid.uuid4())
        source_url = f"https://dash.fuckip.me/deploy?machine_id={machine_id}"
        checkout_url = f"https://dash.fuckip.me/deploy?machine_id={machine_id}&plan_id={plan_id}&region=US"
        c = self.db()
        c.execute("UPDATE tcp_sources SET purchase_url=? WHERE id=?", (source_url, self.source))
        c.commit(); c.close()
        product = {"product_id": machine_id, "product_name": "Synthetic VPS", "virtualization_type": "incus",
                   "sale_status": "available", "remaining": 3, "purchase_url": checkout_url,
                   "catalog_updated_at": self.now, "catalog_stale": False}
        with mock.patch.object(tcping, "schedule_public_products"), \
                mock.patch.object(tcping, "public_product_item", return_value=product):
            response = self.client.get(tcping.PUBLIC + "/sources")
        self.assertEqual(response.status_code, 200)
        item = next(x for x in response.json()["items"] if x["id"] == self.source)
        self.assertEqual(item["product"]["mapping_state"], "verified")
        self.assertEqual((item["product"]["sale_status"], item["product"]["remaining"],
                          item["product"]["virtualization_type"], item["product"]["purchase_url"]),
                         ("available", 3, "incus", checkout_url))

        c = self.db()
        c.execute("UPDATE tcp_sources SET name='Different Source' WHERE id=?", (self.source,))
        c.commit(); c.close()
        with mock.patch.object(tcping, "schedule_public_products"), \
                mock.patch.object(tcping, "public_product_item", return_value=product):
            response = self.client.get(tcping.PUBLIC + "/sources")
        item = next(x for x in response.json()["items"] if x["id"] == self.source)
        self.assertEqual(item["product"]["mapping_state"], "mismatch")
        self.assertEqual((item["product"]["sale_status"], item["product"]["remaining"],
                          item["product"]["virtualization_type"], item["product"]["purchase_url"]),
                         ("unknown", None, "", ""))

    def test_result_endpoint_requires_signed_node_and_lease(self):
        self.admit()
        lease = self.lease()
        body = json.dumps(self.batch(lease)).encode()
        route = "/api/v1/tcp-probe/report"
        self.assertEqual(self.client.post(route,content=body).status_code,401)
        ts = str(int(time.time()))
        sig = hmac.new(b"synthetic-shared",body+ts.encode(),hashlib.sha256).hexdigest()
        result = self.client.post(route,content=body,headers={"X-Timestamp":ts,"X-Signature":sig})
        self.assertEqual(result.status_code,200,result.text)
        self.assertIn("x-narwhal-response-signature",result.headers)


class ProbeWorkerTests(unittest.TestCase):
    @unittest.skipUnless(os.name=="posix","Linux full worker subprocess integration")
    def test_full_317_target_parent_worker_batches_without_network(self):
        from threading import Thread
        targets = tcping.configured_directory(raw_directory())["nodes"]
        module_dir = str(Path(tcp_probe.__file__).resolve().parent)
        # Exercise concurrent subprocess allocation, not only socket-free fake
        # rows: glibc arenas previously exhausted RLIMIT_AS on ARM64/Python 3.14.
        resolver_code = "import sys,json;print(json.dumps({'target_id':sys.argv[1],'ip':'1.1.1.1','samples_ms':[1.0],'error':''}))"
        child_code = (
            "import sys,json,subprocess;sys.path.insert(0,"+repr(module_dir)+");import tcp_probe;"
            "tcp_probe.probe=lambda t,s:json.loads(subprocess.check_output([sys.executable,'-c',"+repr(resolver_code)+",t['id']],timeout=3));"
            "tcp_probe.worker(json.load(sys.stdin))"
        )
        original = subprocess.Popen
        processes, batches = [], []
        def launch(args, **kwargs):
            if args[-1] == "worker":
                self.assertEqual(set(kwargs["env"]), {"PATH","LANG","PYTHONDONTWRITEBYTECODE","MALLOC_ARENA_MAX"})
                self.assertEqual(kwargs["env"]["MALLOC_ARENA_MAX"], "2")
                args = [sys.executable,"-u","-c",child_code]
            child = original(args,**kwargs)
            processes.append(child)
            return child
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(os.environ,{"NARWHAL_TCP_STATE":temp}):
            job = {"id":str(uuid.uuid4()),"lease":"x"*43,"generation":"synthetic-test","target_hash":tcp_probe.digest(targets),
                   "targets":targets,"samples":1,"deadline_at":int(time.time())+60}
            fd = tcp_probe.claim(job["id"])
            with mock.patch.object(tcp_probe.subprocess,"Popen",side_effect=launch):
                thread = Thread(target=tcp_probe.run_job,args=(job,"synthetic-host","synthetic-node",lambda path,p:batches.append(p),fd),daemon=True)
                thread.start(); thread.join(timeout=45)
                self.assertFalse(thread.is_alive())
            self.assertEqual(batches[-1]["outcome"],"complete")
            self.assertEqual(sum(len(b["rows"]) for b in batches),317)
            self.assertTrue(all(len(b["rows"])<=32 for b in batches))
            self.assertTrue(all(p.poll()==0 for p in processes))

    def test_private_dns_is_rejected_and_resolver_has_hard_timeout(self):
        for ip in ("127.0.0.1","10.0.0.1","169.254.169.254","224.0.0.1","::1"):
            self.assertFalse(tcp_probe.safe_ip(ip))
        with mock.patch.object(tcp_probe.subprocess,"run",return_value=subprocess.CompletedProcess([],0,b'["127.0.0.1"]')) as run:
            self.assertEqual(tcp_probe.resolve("bj-cm-v4.ip.zstaticcdn.com"),([],"blocked_dns"))
            self.assertEqual(run.call_args.kwargs["timeout"],2.5)
        with mock.patch.object(tcp_probe.subprocess,"run",side_effect=subprocess.TimeoutExpired([],2.5)):
            self.assertEqual(tcp_probe.resolve("bj-cm-v4.ip.zstaticcdn.com"),([],"dns_error"))

    def test_tcp_timer_excludes_resolution_and_no_http_payload(self):
        target=tcping.normalize_directory(raw_directory())["nodes"][0]
        sock=mock.MagicMock()
        sock.__enter__.return_value=sock
        with mock.patch.object(tcp_probe,"resolve",return_value=(["1.1.1.1"],"")), mock.patch.object(tcp_probe.socket,"socket",return_value=sock), mock.patch.object(tcp_probe.time,"perf_counter",side_effect=[10,10.005]):
            result=tcp_probe.probe(target,1)
        self.assertEqual(result["samples_ms"],[5.0])
        sock.connect.assert_called_once_with(("1.1.1.1",target["port"]))
        sock.send.assert_not_called()
        sock.sendall.assert_not_called()

    @unittest.skipUnless(os.name=="posix","Linux OS worker locking")
    def test_os_lock_and_cooldown_survive_agent_restart(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(os.environ,{"NARWHAL_TCP_STATE":temp}):
            job=str(uuid.uuid4())
            fd=tcp_probe.claim(job)
            self.assertIsNotNone(fd)
            with self.assertRaises(OSError):
                tcp_probe.claim(str(uuid.uuid4()))
            os.close(fd)
            self.assertIsNone(tcp_probe.claim(job))
            self.assertIsNone(tcp_probe.claim(str(uuid.uuid4())))

    @unittest.skipUnless(os.name=="posix","Linux process-group cleanup")
    def test_deadline_kills_worker_process_group(self):
        process=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"],start_new_session=True)
        try:
            tcp_probe.kill_worker(process)
            self.assertNotEqual(process.wait(timeout=3),0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


if __name__=="__main__":
    unittest.main()
