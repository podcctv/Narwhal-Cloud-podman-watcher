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
from server import app as server, tcping, operations
from client import tcp_probe


def raw_directory():
    return {"UpdatedAt": "2026-09-15T12:27:24Z",
            "ProvinceNodes": [{"province": p, "carriers": {c: f"p{i}-{c}-v4.ip.zstaticcdn.com:80" for c in sorted(tcping.CARRIERS)}} for i, p in enumerate(sorted(tcping.PROVINCES))],
            "CityNodes": [{"province": "北京", "city": f"合成城市{i}", "carrier": "mobile", "endpoint": f"bj-city{i}-cm-v4.ip.zstaticcdn.com:443"} for i in range(223)]}


class ProbeStateTests(unittest.TestCase):
    def setUp(self):
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
        self.temp.cleanup()

    def db(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
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


class ProbeHttpTests(ProbeStateTests):
    def setUp(self):
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
        self.temp.cleanup()

    def test_public_pages_isolated_private_apis_unchanged(self):
        self.assertEqual(self.client.get("/tcping").status_code,200)
        self.assertEqual(self.client.get("/tcping/manage").status_code,303)
        with mock.patch.object(tcping,"refresh_directory"):
            self.assertEqual(self.client.get(tcping.PUBLIC+"/directory").json()["counts"]["total"],316)
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
