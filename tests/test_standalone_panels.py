"""Installed management panels are attention-only, never proof of weak authentication."""
import unittest
from unittest import mock
from client import agent, socks_detector as detector, security_banner as banner
from server import buyer_notifications as buyer, investigation
from tests import test_buyer_notifications as fixtures


class PanelInventoryTests(unittest.TestCase):
    def test_exact_executable_aliases_no_command_text_false_positive(self):
        output='210 S sui /usr/local/s-ui/sui\n211 S x-ui /usr/local/x-ui/x-ui\n212 S sh sh -c /usr/local/s-ui/sui\n213 S vim vim /etc/x-ui/config\n214 Z sui /usr/local/s-ui/sui\n'
        found=detector.standalone_panels(output)
        self.assertEqual([(p['pid'],p['panel']) for p in found],[(210,'S-ui'),(211,'X-ui')])
        self.assertTrue(all(not p['auto_stop_eligible'] for p in found))
        self.assertNotIn('/usr/local',str(found))
        self.assertEqual(detector.standalone_panels('215 S sui /usr/bin/x-ui'),[])

    def test_inventory_is_not_misclassified_as_airport_pairing(self):
        def read(cmd, **kwargs):
            return '210 S sui /usr/local/s-ui/sui\n' if 'ps -eo pid=' in cmd[-1] else ''
        with mock.patch.object(agent,'run',side_effect=read):
            result=agent.collect_panel_pairing_indicators('fixture','incus','default')
        self.assertFalse(result['detected'])
        self.assertEqual(result['standalone_panels'][0]['panel'],'S-ui')
        self.assertFalse(result['socks_proxy']['detected'])

    def test_panel_alone_creates_warning_without_stopping_or_claiming_weak_password(self):
        panel={'pid':210,'process':'sui','panel':'S-ui','auth_assessment':'not_assessed','auto_stop_eligible':False,
            'service_listeners':[{'pid':210,'process':'sui','port':9443,'local':'*:9443','proto':'tcp'}]}
        c={'name':'fixture','runtime':'incus','project':'default','security':{
            'panel_pairing':{'detected':False,'standalone_panels':[panel]},'socks_proxy':{'detected':False},
            'listening_ports':[22,9443],'service_listeners':[{'pid':240,'process':'sshd','port':22}]}}
        with mock.patch.object(agent,'remediate_panel_pairing') as stop_panel, \
             mock.patch.object(agent,'stop_unauthenticated_socks') as stop_socks, \
             mock.patch.object(agent,'update_container_motd_alerts'):
            result=agent.collect_security_summary([c],60)
        alert=next(a for a in result['alerts'] if a['type']=='standalone_proxy_panel')
        self.assertEqual(alert['severity'],'warning')
        self.assertEqual(alert['panel_auth_status'],'not_assessed')
        self.assertFalse(alert['auto_stop_eligible'])
        self.assertEqual([p['port'] for p in alert['service_listeners']],[9443])
        self.assertNotIn('22',alert['message'])
        stop_panel.assert_not_called();stop_socks.assert_not_called()
        self.assertEqual(investigation.category(alert['type']),'security_attention')


class PanelNoticeTests(unittest.TestCase):
    setUp=fixtures.BuyerTests.setUp
    tearDown=fixtures.BuyerTests.tearDown
    ingest=fixtures.BuyerTests.ingest
    mapping=fixtures.BuyerTests.mapping

    def test_admin_only_until_manual_notify(self):
        self.alert.update(type='standalone_proxy_panel',standalone_panels=[{'panel':'S-ui','process':'sui','pid':210}],
            service_listeners=[{'pid':210,'process':'sui','port':9443,'local':'*:9443'}])
        self.mapping();self.ingest()
        with fixtures.server.db() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM buyer_outbox').fetchone()[0],0)
            alert_id=conn.execute('SELECT id FROM security_alerts').fetchone()[0]
            value=buyer.notice_preview(conn,alert_id)
            self.assertIn('不代表已确认弱密码',value['message'])
            receipt=buyer.queue_user_notice(conn,alert_id,{'request_id':'a'*32,'confirm':True,'preview_token':value['preview_token']},'admin')
            self.assertEqual(receipt['telegram'],'queued')
            self.assertEqual(receipt['banner'],'queued')
            self.assertNotIn('standalone_proxy_panel',fixtures.server._ACTIONABLE_ALERT_TYPES)


class PanelBannerTests(unittest.TestCase):
    setUp=fixtures.BannerTests.setUp
    tearDown=fixtures.BannerTests.tearDown

    def test_panel_inventory_does_not_auto_inject_customer_banner(self):
        notice={'type':'standalone_proxy_panel','severity':'warning','message':'仅安装提醒'}
        with mock.patch.object(banner,'install_shell',return_value=(True,True)) as install,mock.patch.object(banner,'write_proc',return_value=True):
            banner.update(self.c,[notice],set(),lambda *_:(True,''),[],'1.7.40')
        self.assertFalse(any(e.get('type')=='standalone_proxy_panel' for e in install.call_args[0][1]))


if __name__ == '__main__': unittest.main()
