import json
import unittest
from unittest import mock
from server import buyer_notifications as buyer, connection_policy as policy
from tests import test_buyer_notifications as fixtures


class ProtectionFirstTests(unittest.TestCase):
    setUp=fixtures.BuyerTests.setUp
    tearDown=fixtures.BuyerTests.tearDown
    mapping=fixtures.BuyerTests.mapping

    def sample(self, stamp, count=2001, epoch='boot:ns:pid', callback=None):
        c={'name':'c1','runtime':'incus','project':'default','conn_count':count,
            'security':{'connection_metrics':{'schema':1,'valid':True,'source':'container_proc_net','epoch':epoch,
                'sampled_at':stamp,'total':count,'tcp_total':count,'tcp_established':count,'tcp_pending':0,'tcp_time_wait':0,'udp_sockets':0}}}
        with fixtures.server.db() as conn:
            policy.observe(conn,'host',stamp,[c],1000,2000,300,360,now=stamp,before_stop=callback or buyer.connection_stop_gate)
        return c['connection_policy']

    def count_actions(self):
        with fixtures.server.db() as conn:
            return conn.execute("SELECT COUNT(*) FROM security_actions WHERE action_type='stop_container'").fetchone()[0]

    def ready(self):
        self.mapping()
        self.sample(self.now-300)
        result=self.sample(self.now)
        self.assertEqual(result['status'],'queued')
        self.assertEqual(self.count_actions(),1)

    def test_stop_precedes_delivery_and_deduplicates(self):
        self.ready()
        def send(*args):
            self.assertEqual(self.count_actions(),1)
            self.assertEqual(args[3],'user')
            self.assertIn('超过 2000',args[5])
            self.assertIn('已下发',args[5])
            return 'succeeded',200
        buyer.work_user_notices(fixtures.server.db,self.now,send)
        self.sample(self.now+60)
        self.assertEqual(self.count_actions(),1)
        with fixtures.server.db() as conn:
            params=json.loads(conn.execute("SELECT params_json FROM security_actions WHERE action_type='stop_container'").fetchone()[0])
            self.assertTrue(params['notice_best_effort'])
            self.assertFalse(params.get('notice_required'))
            self.assertEqual(params['threshold'],2000)
            self.assertEqual(params['required_duration_seconds'],300)

    def test_boundary_and_missing_mapping(self):
        for stamp in (self.now-300,self.now): self.sample(stamp,2000)
        self.assertEqual(self.count_actions(),0)
        self.sample(self.now+10)
        p=self.sample(self.now+310)
        self.assertEqual(p['notification_status'],'blocked')
        self.assertEqual(self.count_actions(),1)

    def test_timeout_does_not_block_stop(self):
        self.ready()
        send=mock.Mock(side_effect=TimeoutError())
        buyer.work_user_notices(fixtures.server.db,self.now,send)
        buyer.work_user_notices(fixtures.server.db,self.now+30,send)
        self.sample(self.now+60)
        self.assertEqual(send.call_count,1)
        self.assertEqual(self.count_actions(),1)

    def test_late_notice_cannot_create_another_stop(self):
        self.ready()
        self.sample(self.now+10,2000)
        with fixtures.server.db() as conn: conn.execute("UPDATE security_actions SET status='failed'")
        sender=mock.Mock(return_value=('succeeded',200))
        buyer.work_user_notices(fixtures.server.db,self.now+400,sender)
        self.assertEqual(sender.call_count,1)
        self.assertEqual(self.count_actions(),1)

    def test_notice_exception_only_rolls_back_notice(self):
        self.sample(self.now-300)
        def broken(conn,*args):
            conn.execute("INSERT INTO buyer_cooldowns VALUES('broken',123)")
            raise RuntimeError('queue failure')
        result=self.sample(self.now,callback=broken)
        self.assertEqual(result['notification_status'],'failed')
        self.assertEqual(self.count_actions(),1)
        with fixtures.server.db() as conn:
            self.assertIsNone(conn.execute("SELECT 1 FROM buyer_cooldowns WHERE machine_id='broken'").fetchone())

    def test_guard_notice_bypasses_ordinary_cooldown(self):
        self.ready()
        with fixtures.server.db() as conn: conn.execute('INSERT INTO buyer_cooldowns VALUES(?,?)',(fixtures.MACHINE,self.now+86400))
        send=mock.Mock(return_value=('succeeded',200))
        buyer.work_user_notices(fixtures.server.db,self.now,send)
        self.assertEqual(send.call_count,1)
        self.assertEqual(self.count_actions(),1)


if __name__ == '__main__': unittest.main()
