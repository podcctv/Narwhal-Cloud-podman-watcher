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


class CardTests(unittest.TestCase):
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
