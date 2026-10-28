import json
import sqlite3
import unittest
from unittest import mock
from server import fleet_updates as fleet
from server import operations as ops


class FleetTests(unittest.TestCase):
    def setUp(self):
        self.c=sqlite3.connect(':memory:'); self.c.row_factory=sqlite3.Row
        self.c.executescript("CREATE TABLE hosts(host_id TEXT PRIMARY KEY,last_seen INTEGER,agent_version TEXT,node_id TEXT,payload TEXT); CREATE TABLE security_actions(id INTEGER PRIMARY KEY,alert_id INTEGER,host_id TEXT,runtime TEXT,project TEXT,container_name TEXT,action_type TEXT,params_json TEXT,status TEXT,requested_by TEXT,created_at INTEGER,updated_at INTEGER,result_message TEXT);")
        ops.initialize(self.c)
        for host,last,version in [('canary',1000,'1.7.46'),('old',1000,'1.7.41'),('offline',0,'1.7.41')]:
            self.c.execute('INSERT INTO hosts VALUES(?,?,?,?,?)',(host,last,version,host,'{}'))
            self.c.execute('INSERT INTO ops_hosts VALUES(?,?,?,?)',(host,host,last,json.dumps({'managed_upgrade':True,'health':[{'source':'network_counters','status':'healthy'},{'source':'security','status':'healthy'}],'services':[]})))
        self.c.commit()

    def tearDown(self):
        self.c.close()

    def tick(self,at=1000):
        self.c.execute("UPDATE hosts SET last_seen=? WHERE host_id IN ('canary','old') AND last_seen<>1130",(at,)); self.c.commit()
        fleet.reconcile(self.c,'1.7.47','a'*40,at)

    def actions(self):
        return self.c.execute('SELECT * FROM security_actions ORDER BY id').fetchall()

    def verify(self):
        self.c.execute("UPDATE ops_hosts SET ts=1130 WHERE host_id='canary'")
        self.c.execute("UPDATE ops_upgrade_nodes SET status='verified' WHERE host_id='canary'")
        self.c.execute("UPDATE hosts SET agent_version='1.7.47',last_seen=1130 WHERE host_id='canary'")
        self.c.execute("UPDATE security_actions SET status='succeeded',updated_at=1010")
        self.c.commit()

    def test_canary_soak_idempotence_and_offline_return(self):
        self.tick(); self.tick()
        self.assertEqual([a['host_id'] for a in self.actions()],['canary'])
        self.verify(); self.tick(1129)
        self.assertEqual(len(self.actions()),1)
        self.tick(1130)
        self.assertEqual([a['host_id'] for a in self.actions()],['canary','old'])
        self.c.execute("UPDATE hosts SET last_seen=1200 WHERE host_id='offline'"); self.c.commit()
        self.tick(1200)
        self.assertEqual([a['host_id'] for a in self.actions()],['canary','old','offline'])

    def test_failure_backoff_attempt_budget_and_no_full_rollout(self):
        self.tick()
        at=1001
        for _ in range(3):
            self.c.execute("UPDATE security_actions SET status='failed'"); self.c.commit()
            self.tick(at)
            count=len(self.actions()); self.tick(at+299)
            self.assertEqual(len(self.actions()),count)
            at+=3000; self.tick(at)
        self.assertEqual(len(self.actions()),3)
        self.assertTrue(all(a['host_id']=='canary' for a in self.actions()))

    def test_pause_rollback_hold_and_enrollment_replacement(self):
        fleet.save(self.c,{'enabled':False,'holds':[]}); self.c.commit(); self.tick()
        self.assertFalse(self.actions())
        fleet.save(self.c,{'enabled':True,'holds':['canary']}); self.c.commit(); self.tick()
        self.assertEqual(self.actions()[0]['host_id'],'old')
        self.c.execute("UPDATE security_actions SET status='failed'"); self.c.commit(); self.tick(1001)
        self.c.execute("UPDATE hosts SET node_id='replacement' WHERE host_id='old'")
        self.c.execute("UPDATE ops_hosts SET node='replacement' WHERE host_id='old'"); self.c.commit()
        self.tick(1500)
        self.assertEqual(len(self.actions()),1)

    def test_publication_requires_build_sha_main_and_version(self):
        with mock.patch.dict('os.environ',{'NARWHAL_REVISION':'a'*40}),mock.patch.object(fleet.urllib.request,'urlopen') as url:
            response=url.return_value.__enter__.return_value
            response.read.side_effect=[json.dumps({'object':{'sha':'a'*40}}).encode(),b'1.7.47\n']
            self.assertEqual(fleet.resolve('1.7.47'),'a'*40)
            self.assertTrue(
                url.call_args_list[0].args[0].full_url.endswith('/git/ref/heads/main')
            )
            response.read.side_effect=[json.dumps({'object':{'sha':'b'*40}}).encode()]
            with self.assertRaises(ValueError): fleet.resolve('1.7.47')
        with mock.patch.dict('os.environ',{'NARWHAL_REVISION':'unknown'}):
            with self.assertRaises(ValueError): fleet.resolve('1.7.47')

    def test_unhealthy_canary_does_not_promote(self):
        self.tick(); self.verify()
        self.c.execute("UPDATE ops_hosts SET payload=? WHERE host_id='canary'",(json.dumps({'managed_upgrade':True,'health':[{'source':'security','status':'failed'}]}),)); self.c.commit()
        self.tick(1130)
        self.assertEqual(len(self.actions()),1)

    def test_confirmed_probe_only_canary_can_promote_without_container_security_scope(self):
        self.tick(); self.verify()
        payload={
            'managed_upgrade':True,
            'health':[{'source':'network_counters','status':'idle'},{'source':'security','status':'not_applicable'}],
            'runtime_inventory':{'state':'empty','runtimes':[],'container_count':0},
            'services':[],
        }
        self.c.execute("UPDATE ops_hosts SET payload=? WHERE host_id='canary'",(json.dumps(payload),)); self.c.commit()
        self.tick(1130)
        self.assertEqual(self.c.execute("SELECT status FROM ops_upgrades").fetchone()[0],'rollout')
        self.assertEqual([a['host_id'] for a in self.actions()],['canary','old'])

    def test_automatic_campaign_replaces_offline_canary_without_bypassing_soak(self):
        self.tick()
        original = self.actions()[0]
        self.assertEqual(original['host_id'], 'canary')

        # The first node has stopped reporting; another node has fresh host
        # and operations samples. Once the original action times out, it must
        # no longer hold the other eligible nodes behind the canary gate.
        now = 2801
        self.c.execute("UPDATE hosts SET last_seen=? WHERE host_id='old'", (now,))
        self.c.execute("UPDATE ops_hosts SET ts=? WHERE host_id='old'", (now,))
        self.c.commit()
        fleet.reconcile(self.c, '1.7.47', 'a'*40, now)

        campaign = self.c.execute('SELECT * FROM ops_upgrades ORDER BY id DESC LIMIT 1').fetchone()
        metadata = json.loads(campaign['payload'])
        self.assertEqual(campaign['status'], 'canary')
        self.assertEqual(metadata['canary'], 'old')
        self.assertEqual(metadata['canary_history'][-1]['from'], 'canary')
        self.assertEqual(metadata['canary_history'][-1]['to'], 'old')
        self.assertEqual(len(self.actions()), 2)
        self.assertEqual(self.actions()[1]['host_id'], 'old')
        self.assertEqual(self.actions()[1]['status'], 'queued')
        self.assertEqual(self.c.execute("SELECT status FROM ops_upgrade_nodes WHERE campaign=? AND host_id='canary'", (campaign['id'],)).fetchone()[0], 'failed')

        # A new canary still must report the target build and pass its soak
        # checks before rollout actions are sent to the rest of the fleet.
        self.assertEqual(sum(a['status'] == 'queued' for a in self.actions()), 1)

    def test_new_automatic_campaign_reclaims_actions_from_superseded_campaign(self):
        self.tick()
        previous = self.c.execute('SELECT id FROM ops_upgrades').fetchone()['id']
        first_action = self.actions()[0]['id']
        self.c.execute("UPDATE security_actions SET status='dispatched' WHERE id=?", (first_action,))
        self.c.execute("UPDATE ops_upgrade_nodes SET status='dispatched' WHERE campaign=? AND host_id='canary'", (previous,))

        stale_action_ids = [first_action]
        for host in ('old', 'offline'):
            cursor = self.c.execute(
                "INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at,result_message) VALUES(0,?,'host','','__host__','managed_upgrade','{}','dispatched','automatic-fleet',1000,1000,'')",
                (host,),
            )
            action_id = cursor.lastrowid
            stale_action_ids.append(action_id)
            node = self.c.execute('SELECT 1 FROM ops_upgrade_nodes WHERE campaign=? AND host_id=?', (previous, host)).fetchone()
            if node:
                self.c.execute("UPDATE ops_upgrade_nodes SET action_id=?,status='dispatched' WHERE campaign=? AND host_id=?", (action_id, previous, host))
            else:
                self.c.execute('INSERT INTO ops_upgrade_nodes VALUES(?,?,?,?,?)', (previous, host, action_id, 'dispatched', '1.7.41'))
        self.c.commit()
        self.assertEqual(self.c.execute("SELECT COUNT(*) FROM security_actions WHERE status IN ('queued','dispatched','running')").fetchone()[0], 3)

        fleet.reconcile(self.c, '1.7.48', 'b'*40, 1010)

        rows = self.c.execute('SELECT status,result_message FROM security_actions WHERE id IN (?,?,?) ORDER BY id', stale_action_ids).fetchall()
        self.assertTrue(all(row['status'] == 'failed' for row in rows))
        self.assertTrue(all('较新版本取代' in row['result_message'] for row in rows))
        old_nodes = self.c.execute('SELECT status FROM ops_upgrade_nodes WHERE campaign=?', (previous,)).fetchall()
        self.assertTrue(all(row['status'] == 'superseded' for row in old_nodes))
        self.assertEqual(self.c.execute("SELECT COUNT(*) FROM security_actions WHERE status IN ('queued','dispatched','running')").fetchone()[0], 1)
        self.assertEqual(self.actions()[-1]['host_id'], 'canary')
        self.assertEqual(self.actions()[-1]['status'], 'queued')

    def test_reclaim_only_old_running_actions_from_terminal_campaign_nodes(self):
        paused = self.c.execute(
            "INSERT INTO ops_upgrades(version,revision,status,created_at,payload) VALUES('1.7.40',?,'paused',1000,'{}')",
            ('c'*40,),
        ).lastrowid
        active = self.c.execute(
            "INSERT INTO ops_upgrades(version,revision,status,created_at,payload) VALUES('1.7.46',?,'rollout',1000,'{}')",
            ('d'*40,),
        ).lastrowid

        def action(host, created):
            return self.c.execute(
                "INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at,result_message) VALUES(0,?,'host','','__host__','managed_upgrade','{}','running','automatic-fleet',?,?, '')",
                (host, created, created),
            ).lastrowid

        stale = action('stale', 1000)
        fresh = action('fresh', 2500)
        active_action = action('active', 1000)
        self.c.execute("INSERT INTO ops_upgrade_nodes VALUES(?,?,?,?,?)", (paused, 'stale', stale, 'failed', '1.7.39'))
        self.c.execute("INSERT INTO ops_upgrade_nodes VALUES(?,?,?,?,?)", (paused, 'fresh', fresh, 'failed', '1.7.39'))
        self.c.execute("INSERT INTO ops_upgrade_nodes VALUES(?,?,?,?,?)", (active, 'active', active_action, 'failed', '1.7.45'))
        self.c.commit()

        fleet.reclaim_superseded_actions(self.c, 3000)

        stale_row = self.c.execute('SELECT status,result_message FROM security_actions WHERE id=?', (stale,)).fetchone()
        self.assertEqual(stale_row['status'], 'failed')
        self.assertIn('释放调度名额', stale_row['result_message'])
        self.assertEqual(self.c.execute('SELECT status FROM security_actions WHERE id=?', (fresh,)).fetchone()[0], 'running')
        self.assertEqual(self.c.execute('SELECT status FROM security_actions WHERE id=?', (active_action,)).fetchone()[0], 'running')
