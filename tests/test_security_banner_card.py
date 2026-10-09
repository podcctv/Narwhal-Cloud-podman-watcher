import base64
import gzip
import os
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from client import security_banner as banner
from client import agent


class CardTests(unittest.TestCase):
    def test_historical_alert_is_past_tense_and_has_relative_age(self):
        entry = {'type': 'connections', 'title': '容器连接数过高', 'state': 'verified',
                 'time_epoch': 1791509400, 'recovered_at_epoch': 1791510000,
                 'detail': '容器当前连接数 533 超过告警阈值 500', 'metrics': 'value=533 / threshold=500'}
        text = banner.render('c', [entry], sampled_at=1791509400+25*60, width=100)
        self.assertIn('历史告警 · 已恢复', text)
        self.assertIn('最近发生：25分钟前', text)
        self.assertIn('当时情况：容器当时连接数 533', text)
        self.assertNotIn('当前连接数', text)
        self.assertIn('发生时间（北京时间）', text)
        self.assertEqual(entry['detail'], '容器当前连接数 533 超过告警阈值 500')
        self.assertEqual(banner.relative_age(1000, 1020), '刚刚')
        self.assertEqual(banner.relative_age(1000, 1000+72*60), '1小时12分钟前')
        self.assertEqual(banner.relative_age(1000, 1000+51*3600), '2天3小时前')
        self.assertEqual(banner.relative_age(1000, 999), '时间待核实')
        self.assertEqual(banner.relative_age(None, 1000), '时间待核实')
        self.assertEqual(banner.relative_age(1000, 1000+72*60, True), '1h 12m ago')
        legacy = {'state': 'verified', 'timestamp': '2026-10-09 01:30:00 UTC'}
        self.assertEqual(banner.observed_epoch(legacy), 1791509400)

    def test_legacy_recovery_is_retained_without_inventing_recovery_time(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {
                'SECURITY_MOTD_STATE_FILE': str(Path(directory)/'state.json')}), \
                mock.patch.object(banner, 'install_shell', return_value=(True, True)), \
                mock.patch.object(banner, 'write_proc', return_value=False):
            banner.incidents.clear(); banner._loaded_path = ''; banner._checks.clear()
            c = {'name': 'c', 'runtime': 'incus', 'pid': 99}
            key = '["incus", "", "c", ""]'
            banner.incidents[key] = [{'type': 'connections', 'title': '高连接数', 'state': 'verified', 'event_id': 'NW-legacy',
                                      'time_epoch': 1000, 'detail': '738 条'}]
            def update(at):
                with mock.patch.object(banner.time, 'time', return_value=at):
                    banner.update(c, [], set(), mock.Mock(return_value=(True, '')), [], 'test')
            update(90000)
            entry = banner.incidents[key][0]
            self.assertNotIn('recovered_at_epoch', entry)
            self.assertEqual(entry['retained_from_epoch'], 90000)
            text = banner.render('c', [entry], width=100)
            self.assertIn('已恢复', text)
            self.assertNotIn('恢复（北京时间）', text)
            banner.incidents.clear(); banner._loaded_path = ''
            update(90000+7*86400)
            self.assertTrue(banner.incidents)
            update(90000+7*86400+1)
            self.assertFalse(banner.incidents)
        banner.incidents.clear(); banner._loaded_path = ''

    def test_customer_card_uses_beijing_time_and_hides_internal_fields(self):
        entry = {'title': 'Hysteria 2 高并发', 'detail': 'UDP 连接 64，远端 IP 2，阈值 50。',
                 'state': 'active', 'severity': 'warning', 'time_epoch': 1791509400,
                 'metrics': 'value=64 / threshold=50', 'event_id': 'NW-87',
                 'action': 'Detected; not remediated'}
        text = banner.render('internal-uuid', [entry], version='1.7.11', sampled_at=1791509400, width=100)
        self.assertIn('2026-10-09 09:30:00', text)
        self.assertEqual(text.count('2026-10-09 09:30:00'), 1)
        self.assertIn('北京时间', text)
        self.assertIn('UDP 连接 64', text)
        for internal in ('internal-uuid', 'Watcher', 'NW-87', 'value=', 'threshold=',
                         'Detected;', '执行成功不等于复查通过', 'UTC'):
            self.assertNotIn(internal, text)
        self.assertEqual(banner.beijing_time(legacy='2026-10-08 23:00:00 UTC'), '2026-10-09 07:00:00')
        with mock.patch.dict(os.environ, {'TZ': 'America/New_York'}):
            self.assertEqual(banner.beijing_time(0), '1970-01-01 08:00:00')

    def test_numeric_evidence_not_in_description_is_customer_friendly(self):
        text = banner.render('c', [{'detail': '连接数量偏高', 'metrics': 'value=738 / threshold=500 / duration_seconds=720'}], width=100)
        self.assertIn('观测值：738；参考阈值：500；持续秒数：720', text)
        self.assertNotIn('value=', text)

    def test_first_clean_sample_is_not_claimed_as_recovered(self):
        text = banner.render('c', [{'state': 'resolved', 'title': '高连接数'}])
        self.assertIn('待复查', text)
        self.assertNotIn('目前容器无异常', text)
        self.assertNotIn('已恢复', text)

    def test_recovery_retained_for_seven_days_after_recovery_across_restart(self):
        for configured in ('24', '168', 'invalid'):
            with self.subTest(configured=configured), tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {
                    'SECURITY_MOTD_STATE_FILE': str(Path(directory)/'state.json'),
                    'SECURITY_MOTD_ALERT_RETENTION_HOURS': configured}), \
                    mock.patch.object(banner, 'install_shell', return_value=(True, True)), \
                    mock.patch.object(banner, 'write_proc', return_value=False):
                banner.incidents.clear(); banner._loaded_path = ''; banner._checks.clear()
                c = {'name': 'c', 'runtime': 'incus', 'pid': 99}
                alert = {'type': 'connections', 'title': '高连接数', 'severity': 'warning', 'message': '738 条'}
                def update(at, alerts):
                    with mock.patch.object(banner.time, 'time', return_value=at):
                        banner.update(c, alerts, set(), mock.Mock(return_value=(True, '')), [], 'test')
                start = 1791509400
                update(start, [alert])
                update(start+3600, [])
                self.assertEqual(next(iter(banner.incidents.values()))[0]['state'], 'resolved')
                recovery = start+3660
                update(recovery, [])
                self.assertTrue(next(iter(banner.incidents.values()))[0]['historical'])
                banner.incidents.clear(); banner._loaded_path = ''
                update(recovery+7*86400, [])
                entry = next(iter(banner.incidents.values()))[0]
                self.assertEqual(entry['recovered_at_epoch'], recovery)
                text = banner.render('c', [entry], width=100)
                self.assertIn('历史告警 · 已恢复', text)
                self.assertIn('已恢复', text)
                self.assertIn('738 条', text)
                update(recovery+7*86400+1, [])
                self.assertFalse(banner.incidents)
        banner.incidents.clear(); banner._loaded_path = ''

    def test_same_type_recurrence_preserves_latest_history_with_three_current_risks(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {
                'SECURITY_MOTD_STATE_FILE': str(Path(directory)/'state.json')}), \
                mock.patch.object(banner, 'install_shell', return_value=(True, True)), \
                mock.patch.object(banner, 'write_proc', return_value=False):
            banner.incidents.clear(); banner._loaded_path = ''; banner._checks.clear()
            c = {'name': 'c', 'runtime': 'incus', 'pid': 99}
            alerts = [{'type': typ, 'severity': 'warning', 'message': typ} for typ in ('connections', 'cpu', 'memory')]
            def update(at, events):
                with mock.patch.object(banner.time, 'time', return_value=at):
                    banner.update(c, events, set(), mock.Mock(return_value=(True, '')), [], 'test')
            update(1000, alerts[:1]); update(1010, []); update(1020, [])
            history_id = next(iter(banner.incidents.values()))[0]['event_id']
            update(1030, alerts)
            entries = next(iter(banner.incidents.values()))
            self.assertEqual(len(entries), 4)
            history = [e for e in entries if e.get('historical')]
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]['event_id'], history_id)
            self.assertEqual(len([e for e in entries if e['state'] == 'active']), 3)
            text = banner.render('c', entries, width=100)
            self.assertIn('历史告警 · 已恢复', text)
            self.assertIn('风险存在', text)
            script = banner.shell_renderer('c', entries, 'test', 1030)
            self.assertLess(len(script.encode()), 65536)
            banner.incidents.clear(); banner._loaded_path = ''
            banner.load_state()
            self.assertEqual(len(next(iter(banner.incidents.values()))), 4)
        banner.incidents.clear(); banner._loaded_path = ''

    def test_banner_exec_routes_to_container_runtime_not_host_default(self):
        with mock.patch.object(agent, 'get_runtime_bins', return_value={'podman': 'podman', 'incus': 'incus'}), \
                mock.patch.object(agent.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout='ok')) as execute:
            c = {'name': 'incus-vm', 'runtime': 'incus', 'project': 'buyers'}
            self.assertEqual(agent._checked_banner_exec(c, 'true'), (True, 'ok'))
            self.assertEqual(execute.call_args.args[0], ['incus', '--project', 'buyers', 'exec', 'incus-vm', '--', 'sh', '-lc', 'true'])
            execute.reset_mock()
            c['runtime_bin'] = 'podman'
            self.assertEqual(agent._checked_banner_exec(c, 'true'), (False, ''))
            execute.assert_not_called()
            c.pop('runtime_bin')
            with mock.patch.object(agent, 'get_runtime_bins', return_value={'podman': 'podman'}):
                self.assertEqual(agent._checked_banner_exec(c, 'true'), (False, ''))
                execute.assert_not_called()

    def test_all_rows_have_identical_terminal_width_with_color(self):
        entries = [{'title': '连接数偏高', 'detail': '738 条 / 阈值 500 条 · 持续 12 分钟',
                    'state': 'active', 'severity': 'warning', 'metrics': 'value=738 / threshold=500',
                    'event_id': 'NW-1', 'action': '待复查'}]
        for width in (12, 16, 24, 32, 40, 52, 68, 80, 100):
            for color in (False, True):
                text = banner.render('e62962e3-b79a-4b0c-9809-4c63bd92b573', entries,
                                     width=width, color=color, sampled_at=1)
                for line in text.splitlines():
                    plain = re.sub(r'\x1b\[[0-9;]*m', '', line)
                    self.assertEqual(banner.cell_width(plain), width)
                    self.assertIn(plain[0], '╭│├╰')
                    self.assertIn(plain[-1], '╮│┤╯')

    def test_normal_stale_and_severity_are_truthful(self):
        self.assertIn('目前容器无异常', banner.render('c', []))
        stale = banner.render('c', [], stale=True)
        self.assertNotIn('目前容器无异常', stale)
        self.assertIn('当前状态未知', stale)
        entries = [{'state': 'active', 'severity': 'critical', 'detail': 'test'}]
        self.assertIn('\x1b[31m', banner.render('c', entries, color=True))
        entries[0]['state'] = 'awaiting_report'
        self.assertNotIn('\x1b[31m', banner.render('c', entries, color=True))
        self.assertIn('已执行，待复查', banner.render('c', entries))

    def test_font_rows_are_placed_at_same_offset(self):
        text = banner.render('c', [], width=68, color=False)
        rows = text.splitlines()[2:7]
        # The F stem must stay at the same column in all four stem rows.
        self.assertEqual(len(set(r.index('|') for r in rows[1:])), 1)

    def test_untrusted_fields_cannot_inject_shell_or_ansi(self):
        text = banner.shell_renderer('$(touch /tmp/pwned)\nNARWHAL_CARD_DATA',
                                     [{'detail': 'token=hidden\x1b[31m\nNARWHAL_CARD_DATA'}], 'test', 1)
        encoded = text.split("\n'\n", 1)[1].split('\nNARWHAL_CARD_DATA', 1)[0]
        payload = gzip.decompress(base64.b64decode(encoded)).decode()
        self.assertNotIn('token=hidden', payload)
        self.assertNotIn('\nNARWHAL_CARD_DATA\n', payload)
        self.assertLess(len(text.encode()), 65536)

    def test_hook_preserves_original_and_guards_noninteractive(self):
        original = 'return\n# user customization\n'
        rc = banner.merge_shell(original, banner.shell_hook())
        self.assertTrue(rc.endswith(original))
        self.assertEqual(banner.merge_shell(rc, banner.shell_hook()), rc)
        self.assertIn('[ -t 1 ]', rc)
        self.assertIn('case $-', rc)
        with self.assertRaises(ValueError):
            banner.merge_shell(banner.SHELL_START + '\nbroken', banner.shell_hook())

    def test_update_installs_default_and_keeps_numeric_evidence(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {'SECURITY_MOTD_STATE_FILE': str(Path(directory)/'state.json')}):
            banner.incidents.clear(); banner._loaded_path = ''; banner._checks.clear()
            c = {'name': 'c', 'runtime': 'podman', 'pid': 99}
            with mock.patch.object(banner, 'install_shell', return_value=(True, True)) as install, mock.patch.object(banner, 'write_proc', return_value=False):
                banner.update(c, [{'type': 'memory', 'severity': 'warning', 'message': '92%', 'observation': {'value': 92, 'threshold': 90}}], set(), mock.Mock(return_value=(True,'')), [], 'test')
                self.assertIn('value=92', install.call_args.args[1][0]['metrics'])
                self.assertEqual(c['security']['motd_delivery']['shell_delivery'], 'installed')
            banner.incidents.clear()


@unittest.skipUnless(os.name == 'posix', 'PTY requires POSIX')
class ShellTests(unittest.TestCase):
    def test_history_age_is_computed_at_login_and_keeps_closed_card_width(self):
        epoch = 1791509400
        entry = {'state': 'verified', 'historical': True, 'title': '连接数过高',
                 'detail': '当前连接数 533 超过阈值 500', 'time_epoch': epoch}
        script = banner.shell_renderer('c', [entry], 'test', epoch+60)
        for seconds, expected in ((25*60, '25分钟前'), (72*60, '1小时12分钟前'), (51*3600, '2天3小时前')):
            current = f'date() {{ echo {epoch+seconds}; }};\n' + script
            output = self.output(current, 100, {'NO_COLOR': ''})
            self.assertIn('历史告警 · 已恢复', output)
            self.assertIn('最近发生：'+expected, output)
            self.assertNotIn('@@AGE', output)
            self.assertTrue(all(banner.cell_width(line) == 100 for line in output.splitlines()))
            self.assertIn('当前状态未知', output)  # Age advances even when the sample expires.
        current = f'date() {{ echo {epoch+72*60}; }};\n' + script
        for width in (12, 16, 24, 32, 40, 52, 68, 80, 100):
            for env in ({'NO_COLOR': ''}, {}):
                output = self.output(current, width, env)
                self.assertNotIn('@@AGE', output)
                self.assertTrue(all(banner.cell_width(re.sub(r'\x1b\[[0-9;]*m', '', line)) == width for line in output.splitlines()))
        future = f'date() {{ echo {epoch-1}; }};\n' + script
        self.assertIn('时间待核实', self.output(future, 100))
        with mock.patch.dict(os.environ, {'SECURITY_MOTD_LANGUAGE': 'en'}):
            english = f'date() {{ echo {epoch+72*60}; }};\n' + banner.shell_renderer('c', [entry], 'test', epoch)
        self.assertIn('Last occurred: 1h 12m ago', self.output(english, 100))

    def test_installer_preserves_user_rc_and_refuses_unowned_paths(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'etc/profile.d').mkdir(parents=True)
            (root/'root').mkdir()
            rc = root/'root/.bashrc'
            original = '# custom\nreturn\n'
            rc.write_text(original)
            rc.chmod(0o600)
            def execute(c, command):
                command = command.replace('/etc/', str(root/'etc')+'/').replace('/root', str(root/'root'))
                result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True)
                return result.returncode == 0, result.stdout
            args = ({'name': 'test'}, [], execute, 'test', 1)
            self.assertEqual(banner.install_shell(*args), (True, True))
            self.assertEqual(banner.install_shell(*args), (True, False))
            self.assertTrue(rc.read_text().endswith(original))
            self.assertEqual(rc.stat().st_mode & 0o777, 0o600)
            renderer = root/'etc/narwhal-banner.sh'
            renderer.write_text('user-owned\n')
            self.assertEqual(banner.install_shell(*args), (False, False))
            self.assertEqual(renderer.read_text(), 'user-owned\n')

    def output(self, script, width, env=None, pipe_input=False):
        import fcntl
        import pty
        import struct
        import subprocess
        import termios
        import errno
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 40, width, 0, 0))
        proc = subprocess.Popen(['/bin/sh', '-c', script], stdin=subprocess.DEVNULL if pipe_input else slave, stdout=slave, stderr=slave,
                                env={**os.environ, 'TERM': 'xterm-256color', **(env or {})})
        os.close(slave)
        chunks = []
        try:
            while True:
                try:
                    chunk = os.read(master, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO: break
                    raise
                if not chunk: break
                chunks.append(chunk)
        finally:
            os.close(master)
        self.assertEqual(proc.wait(timeout=10), 0)
        return b''.join(chunks).decode().replace('\r\n', '\n')

    def test_live_shell_width_color_stale_and_noninteractive(self):
        import subprocess
        script = banner.shell_renderer('test', [], 'test', int(time.time()))
        for cols, expected in ((40, 40), (67, 52), (68, 68), (120, 100)):
            output = self.output(script, cols, {'NO_COLOR': ''})
            self.assertNotIn('\x1b', output)
            self.assertIn('目前容器无异常', output)
            self.assertTrue(all(banner.cell_width(line) == expected for line in output.splitlines()))
        self.assertIn('\x1b[32m', self.output(script, 80))
        piped = self.output(script, 40, {'NO_COLOR': ''}, pipe_input=True)
        self.assertTrue(all(banner.cell_width(line) == 40 for line in piped.splitlines()))
        # Some container seccomp/PTY stacks reject the window-size ioctl.
        unavailable = 'stty() { return 1; };\n' + script
        fallback = self.output(unavailable, 80, {'COLUMNS': '40', 'NO_COLOR': ''})
        self.assertTrue(all(banner.cell_width(line) == 40 for line in fallback.splitlines()))
        invalid = self.output(unavailable, 80, {'COLUMNS': 'invalid', 'NO_COLOR': ''})
        self.assertTrue(all(banner.cell_width(line) == 80 for line in invalid.splitlines()))
        stale = banner.shell_renderer('test', [], 'test', int(time.time())-901)
        self.assertIn('当前状态未知', self.output(stale, 80))
        self.assertEqual(subprocess.check_output(['/bin/sh', '-c', script]), b'')
