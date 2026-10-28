import hashlib
import json
import unittest
from unittest import mock

from client import socks_detector
from client import vmess_guard
from client import security_banner
from client import agent
from server import buyer_notifications


class VmessPlanTests(unittest.TestCase):
    def setUp(self):
        self.process_clock = mock.patch.object(
            agent, '_protocol_process_start_epoch_lower_bound', return_value=1793140000.0,
        )
        self.process_clock.start()
        self.addCleanup(self.process_clock.stop)
        self.config = [{
            "pid": 120,
            "process": "xray",
            "protocol": "vmess",
            "port": 443,
            "listen": "0.0.0.0",
            "transports": ["tcp"],
        }]
        self.listener = {
            "pid": 120,
            "process": "xray",
            "proto": "tcp",
            "local": "0.0.0.0:443",
            "port": 443,
            "application_protocols": ["vmess"],
            "application_protocol_evidence": "config_matches_live_pid_and_port",
        }

    def test_only_config_and_live_listener_match_is_eligible(self):
        result = vmess_guard.plan("incus", self.config, [self.listener], [], "complete")
        self.assertEqual(result["state"], "candidate")
        self.assertEqual(result["blocked_endpoints"], [{
            "proto": "tcp", "port": 443, "pid": 120, "process": "xray",
        }])

    def test_vless_inbound_is_never_a_vmess_block_target(self):
        vless = [{**self.config[0], "protocol": "vless"}]
        listener = {
            **self.listener,
            "application_protocols": ["vless"],
        }
        result = vmess_guard.plan("incus", vless, [listener], [], "complete")
        self.assertFalse(result["detected"])
        self.assertEqual(result["blocked_endpoints"], [])
        self.assertTrue(result["release_eligible"])

    def test_shared_vmess_and_vless_config_is_never_blocked(self):
        configured = [self.config[0], {**self.config[0], "protocol": "vless"}]
        result = vmess_guard.plan("incus", configured, [self.listener], [], "complete")
        self.assertEqual(result["blocked_endpoints"], [])
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["pending_endpoints"][0]["reason"], "shared_configured_port")

    def test_truncated_listener_inventory_never_becomes_a_block_target(self):
        result = vmess_guard.plan("podman", self.config, [self.listener], [], "partial")
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["blocked_endpoints"], [])
        self.assertEqual(result["pending_endpoints"][0]["reason"], "configuration_scan_incomplete")

    def test_complete_vmess_process_can_be_blocked_when_unrelated_config_scan_is_partial(self):
        result = vmess_guard.plan(
            "incus", self.config, [self.listener], [], "partial",
            process_scan_states=[
                {"pid": 120, "process": "xray", "state": "complete", "start_ticks": "900"},
                {"pid": 121, "process": "v2ray", "state": "partial", "start_ticks": "901"},
            ],
            listener_inventory_complete=True,
        )
        self.assertEqual(result["state"], "candidate")
        self.assertEqual(result["blocked_endpoints"][0]["port"], 443)

    def test_partial_config_for_same_vmess_process_prevents_block(self):
        result = vmess_guard.plan(
            "incus", self.config, [self.listener], [], "partial",
            process_scan_states=[{"pid": 120, "process": "xray", "state": "partial", "start_ticks": "900"}],
            listener_inventory_complete=True,
        )
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["blocked_endpoints"], [])
        self.assertEqual(result["pending_endpoints"][0]["reason"], "configuration_scan_incomplete")

    def test_scoped_complete_state_without_process_generation_is_not_a_block_basis(self):
        result = vmess_guard.plan(
            "incus", self.config, [self.listener], [], "complete",
            process_scan_states=[{"pid": 120, "process": "xray", "state": "complete"}],
            listener_inventory_complete=True,
        )
        self.assertEqual(result["blocked_endpoints"], [])
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["pending_endpoints"][0]["reason"], "process_start_generation_unavailable")

    def test_process_scan_failure_reason_is_preserved_for_operator_diagnosis(self):
        result = vmess_guard.plan(
            "incus", self.config, [self.listener], [], "partial",
            process_scan_states=[{
                "pid": 120, "process": "xray", "state": "partial", "start_ticks": "900",
                "reason": "config_process_clock_unavailable",
            }],
            listener_inventory_complete=True,
        )
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["blocked_endpoints"], [])
        self.assertEqual(result["pending_endpoints"][0]["reason"], "config_process_clock_unavailable")

    def test_incomplete_listener_inventory_prevents_per_process_block(self):
        result = vmess_guard.plan(
            "incus", self.config, [self.listener], [], "complete",
            process_scan_states=[{"pid": 120, "process": "xray", "state": "complete"}],
            listener_inventory_complete=False,
        )
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["blocked_endpoints"], [])
        self.assertEqual(result["pending_endpoints"][0]["reason"], "listener_inventory_incomplete")

    def test_unknown_or_shared_listener_owner_is_not_blocked(self):
        shared = {**self.listener, "pid": 121, "process": "other", "application_protocols": ["vless"]}
        result = vmess_guard.plan("incus", self.config, [self.listener, shared], [], "complete")
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["blocked_endpoints"], [])
        self.assertEqual(result["pending_endpoints"][0]["reason"], "shared_live_listener")

    def test_loopback_only_listener_is_not_mistaken_for_public_service(self):
        listener = {**self.listener, "local": "127.0.0.1:443"}
        result = vmess_guard.plan("podman", self.config, [listener], [], "complete")
        self.assertEqual(result["state"], "internal_only")
        self.assertEqual(result["blocked_endpoints"], [])

    def test_runtime_scope_is_limited_to_incus_and_podman(self):
        result = vmess_guard.plan("docker", self.config, [self.listener], [], "complete")
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["reason"], "runtime_not_supported")
        self.assertEqual(result["blocked_endpoints"], [])

    def test_release_requires_a_complete_absence_scan(self):
        complete = vmess_guard.plan("incus", [], [], [], "complete")
        incomplete = vmess_guard.plan("incus", [], [], [], "partial")
        self.assertTrue(complete["release_eligible"])
        self.assertFalse(incomplete["release_eligible"])
        self.assertEqual(incomplete["state"], "unverified")
        unsupported = vmess_guard.plan("docker", [], [], [], "complete")
        self.assertFalse(unsupported["release_eligible"])

    def test_absence_does_not_release_if_explicit_listener_inventory_is_incomplete(self):
        result = vmess_guard.plan(
            "incus", [], [], [], "complete", process_scan_states=[],
            listener_inventory_complete=False,
        )
        self.assertFalse(result["release_eligible"])
        self.assertEqual(result["state"], "unverified")

    def test_nft_failure_diagnostics_are_categorized_without_leaking_raw_output(self):
        denied = mock.Mock(stdout="", stderr="Operation not permitted at /secret/container/path")
        unsupported = mock.Mock(stdout="", stderr="Operation not supported by kernel")
        invalid = mock.Mock(stdout="", stderr="syntax error near /private/config")
        self.assertEqual(vmess_guard._firewall_failure_reason(denied, "firewall_apply_failed"), "firewall_permission_denied")
        self.assertEqual(vmess_guard._firewall_failure_reason(unsupported, "firewall_apply_failed"), "firewall_kernel_unsupported")
        self.assertEqual(vmess_guard._firewall_failure_reason(invalid, "firewall_apply_failed"), "firewall_rule_validation_failed")
        self.assertNotIn("secret", json.dumps([
            vmess_guard._firewall_failure_reason(denied, "firewall_apply_failed"),
            vmess_guard._firewall_failure_reason(unsupported, "firewall_apply_failed"),
            vmess_guard._firewall_failure_reason(invalid, "firewall_apply_failed"),
        ]))

    def test_config_parser_reports_protocol_without_secrets(self):
        xray = socks_detector.parse_inbound_protocols(
            '{"inbounds":[{"protocol":"vmess","port":443,"streamSettings":{"network":"tcp"},"settings":{"clients":[{"id":"secret"}]}}]}',
            "xray",
        )
        sing_box = socks_detector.parse_inbound_protocols(
            '{"inbounds":[{"type":"vmess","listen_port":8443}]}', "sing-box"
        )
        self.assertEqual(xray["endpoints"][0]["protocol"], "vmess")
        self.assertEqual(xray["endpoints"][0]["transports"], ["tcp"])
        self.assertEqual(sing_box["endpoints"][0]["port"], 8443)
        self.assertNotIn("secret", json.dumps(xray))

    def test_unrelated_gost_process_does_not_make_vmess_scan_incomplete(self):
        process_output = (
            "120 S xray /usr/bin/xray -config /etc/xray/config.json\n"
            "121 S gost /usr/bin/gost -C /etc/gost/config.json\n"
        )
        metadata = "1:2:24:2026-10-28:2026-10-28|1793139000|1793139000"
        with mock.patch.object(agent, "run", side_effect=[
            "120", metadata, '{"inbounds":[]}', metadata, "120",
        ]):
            result = agent._collect_socks_config_evidence(
                "incus", "fixture", "default", False, process_output
            )
        self.assertEqual(result["protocol_inventory_state"], "complete")
        self.assertEqual(result["configured_inbound_protocols"], [])
        self.assertEqual(result["protocol_process_scan_states"], [
            {"pid": 120, "process": "xray", "state": "complete", "start_ticks": "120",
             "reason": "", "config_files": ["/etc/xray/config.json"]},
        ])

    def test_scan_states_are_scoped_to_each_supported_engine_process(self):
        process_output = (
            "120 S xray /usr/bin/xray -config /etc/xray/config.json\n"
            "121 S v2ray /usr/bin/v2ray -config /etc/v2ray/config.json\n"
        )
        with mock.patch.object(agent, "run", side_effect=[
            "120",
            "1:2:120:2026-10-28:2026-10-28|1793139000|1793139000",
            '{"inbounds":[{"protocol":"vmess","port":443,"streamSettings":{"network":"tcp"}}]}',
            "1:2:120:2026-10-28:2026-10-28|1793139000|1793139000",
            "120",
            "121",
            "1:3:20:2026-10-28:2026-10-28|1793139000|1793139000",
            '{invalid',
            "1:3:20:2026-10-28:2026-10-28|1793139000|1793139000",
            "121",
        ]):
            result = agent._collect_socks_config_evidence(
                "incus", "fixture", "default", False, process_output
            )
        self.assertEqual(result["protocol_inventory_state"], "partial")
        self.assertEqual(result["protocol_process_scan_states"], [
            {"pid": 120, "process": "xray", "state": "complete", "start_ticks": "120",
             "reason": "", "config_files": ["/etc/xray/config.json"]},
            {"pid": 121, "process": "v2ray", "state": "partial", "start_ticks": "121",
             "reason": "config_parse_failed_or_too_large", "config_files": ["/etc/v2ray/config.json"]},
        ])
        self.assertEqual(result["configured_inbound_protocols"][0]["port"], 443)

    def test_xray_config_directory_is_scanned_with_bounded_file_list(self):
        process_output = "120 S xray /usr/bin/xray run -confdir /etc/xray/conf.d\n"
        with mock.patch.object(agent, "run", side_effect=[
            "/etc/xray/conf.d/inbound.json\n/etc/xray/conf.d/inbound-link.json\n@@CONFIG_DIR_SCAN_OK@@",
            "120",
            "1:4:90:2026-10-28:2026-10-28|1793139000|1793139000",
            '{"inbounds":[{"protocol":"vmess","port":8443,"streamSettings":{"network":"tcp"}}]}',
            "1:4:90:2026-10-28:2026-10-28|1793139000|1793139000",
            "1:2:120:2026-10-28:2026-10-28|1793139000|1793139000",
            '{"inbounds":[{"protocol":"vless","port":443,"streamSettings":{"network":"tcp"}}]}',
            "1:2:120:2026-10-28:2026-10-28|1793139000|1793139000",
            "120",
        ]) as run:
            result = agent._collect_socks_config_evidence(
                "incus", "fixture", "default", False, process_output
            )
        self.assertEqual(result["protocol_inventory_state"], "complete")
        self.assertEqual(result["configured_inbound_protocols"][0]["port"], 8443)
        scan = result["protocol_process_scan_states"][0]
        self.assertEqual(scan["state"], "complete")
        self.assertEqual(scan["config_files"], [
            "/etc/xray/conf.d/inbound-link.json", "/etc/xray/conf.d/inbound.json",
        ])
        self.assertEqual(scan["reason"], "")
        self.assertEqual(run.call_count, 9)

    def test_unreadable_xray_config_directory_reports_actionable_reason(self):
        process_output = "120 S xray /usr/bin/xray run -confdir /etc/xray/conf.d\n"
        with mock.patch.object(agent, "run", side_effect=["", "120", "120"]):
            result = agent._collect_socks_config_evidence(
                "incus", "fixture", "default", False, process_output
            )
        self.assertEqual(result["protocol_inventory_state"], "partial")
        self.assertEqual(result["protocol_process_scan_states"][0]["reason"],
                         "config_directory_unreadable_or_truncated")

    def test_engine_restart_during_config_scan_invalidates_generation_evidence(self):
        process_output = "120 S xray /usr/bin/xray -config /etc/xray/config.json\n"
        with mock.patch.object(agent, "run", side_effect=[
            "120",
            "1:2:120:2026-10-28:2026-10-28|1793139000|1793139000",
            '{"inbounds":[{"protocol":"vmess","port":443}]}',
            "1:2:120:2026-10-28:2026-10-28|1793139000|1793139000",
            "121",
        ]):
            result = agent._collect_socks_config_evidence(
                "incus", "fixture", "default", False, process_output
            )
        self.assertEqual(result["protocol_inventory_state"], "partial")
        self.assertEqual(result["protocol_process_scan_states"], [
            {"pid": 120, "process": "xray", "state": "partial", "start_ticks": "",
             "reason": "process_changed_during_config_scan", "config_files": ["/etc/xray/config.json"]},
        ])

    def test_config_replacement_during_read_invalidates_protocol_evidence(self):
        process_output = "120 S xray /usr/bin/xray -config /etc/xray/config.json\n"
        with mock.patch.object(agent, "run", side_effect=[
            "120",
            "1:2:120:2026-10-28:2026-10-28|1793139000|1793139000",
            '{"inbounds":[{"protocol":"vmess","port":443}]}',
            "1:3:140:2026-10-28:2026-10-28|1793139000|1793139000",
            "120",
        ]):
            result = agent._collect_socks_config_evidence(
                "incus", "fixture", "default", False, process_output
            )
        self.assertEqual(result["protocol_inventory_state"], "partial")
        self.assertEqual(result["protocol_process_scan_states"][0]["reason"],
                         "config_file_changed_during_scan")

    def test_stable_config_rewritten_after_start_cannot_be_a_vmess_block_basis(self):
        for mtime, ctime in [(1793140100, 1793140100), (1793139000, 1793140100),
                             (1793139997, 1793139997)]:
            with self.subTest(mtime=mtime, ctime=ctime):
                metadata = f'1:2:120:stable|{mtime}|{ctime}'
                with mock.patch.object(agent, 'run', side_effect=[
                    '120', metadata, '{"inbounds":[{"protocol":"vmess","port":443}]}', metadata, '120',
                ]):
                    evidence = agent._collect_socks_config_evidence(
                        'incus', 'fixture', 'default', False,
                        '120 S xray /usr/bin/xray -config /etc/xray/config.json\n',
                    )
                self.assertEqual(evidence['protocol_inventory_state'], 'partial')
                self.assertEqual(evidence['configured_inbound_protocols'][0]['protocol'], 'vmess')
                self.assertEqual(evidence['protocol_process_scan_states'][0]['reason'],
                                 'config_not_known_before_process_start')
                planned = vmess_guard.plan(
                    'incus', evidence['configured_inbound_protocols'], [self.listener], [],
                    evidence['protocol_inventory_state'],
                    process_scan_states=evidence['protocol_process_scan_states'],
                    listener_inventory_complete=True,
                )
                self.assertEqual(planned['blocked_endpoints'], [])

    def test_config_with_unavailable_process_clock_remains_detected_but_unverified(self):
        metadata = '1:2:120:stable|1793139000|1793139000'
        with mock.patch.object(agent, '_protocol_process_start_epoch_lower_bound', return_value=None), \
                mock.patch.object(agent, 'run', side_effect=[
                    '120', metadata, '{"inbounds":[{"protocol":"vmess","port":443}]}', metadata, '120',
                ]):
            evidence = agent._collect_socks_config_evidence(
                'incus', 'fixture', 'default', False,
                '120 S xray /usr/bin/xray -config /etc/xray/config.json\n',
            )
        self.assertEqual(evidence['protocol_inventory_state'], 'partial')
        self.assertEqual(evidence['configured_inbound_protocols'][0]['protocol'], 'vmess')
        self.assertEqual(evidence['protocol_process_scan_states'][0]['reason'],
                         'config_process_clock_unavailable')

    def test_old_unchanged_config_with_clock_evidence_is_eligible(self):
        metadata = '1:2:120:stable|1793139000|1793139000'
        with mock.patch.object(agent, 'run', side_effect=[
            '120', metadata, '{"inbounds":[{"protocol":"vmess","port":443}]}', metadata, '120',
        ]):
            evidence = agent._collect_socks_config_evidence(
                'incus', 'fixture', 'default', False,
                '120 S xray /usr/bin/xray -config /etc/xray/config.json\n',
            )
        self.assertEqual(evidence['protocol_inventory_state'], 'complete')
        planned = vmess_guard.plan(
            'incus', evidence['configured_inbound_protocols'], [self.listener], [],
            evidence['protocol_inventory_state'],
            process_scan_states=evidence['protocol_process_scan_states'],
            listener_inventory_complete=True,
        )
        self.assertEqual(planned['blocked_endpoints'][0]['port'], 443)

    def test_customer_banner_copy_says_only_port_is_blocked(self):
        title, detail, extra, advice = security_banner.customer_copy({
            "type": "vmess_port_blocked",
            "title": "VMess 入站端口已自动阻断",
            "detail": "已核实 VMess 进程 xray（容器内 PID 120）监听 TCP/443；已阻断该端口",
        })
        self.assertIn("VMess", title)
        self.assertIn("xray（容器内 PID 120）", detail)
        self.assertIn("TCP/443", detail)
        self.assertEqual(extra, [])
        self.assertIn("没有停止进程、容器或其他端口", advice)
        self.assertIn("不代表认定您有滥用行为", advice)
        self.assertIn("VLESS + Reality + Vision", advice)

    def test_release_pending_is_operator_only_and_banner_does_not_claim_recovery(self):
        title, detail, _, advice = security_banner.customer_copy({
            "type": "vmess_block_release_unverified",
            "title": "VMess 端口恢复待核实",
            "detail": "原受保护端口仍有进程监听：TCP/443",
        })
        self.assertEqual(title, "VMess 端口恢复待核实")
        self.assertIn("仍有进程监听", detail)
        self.assertIn("暂时保留了原端口阻断", advice)
        self.assertTrue(buyer_notifications.is_protection_only_alert({"type": "vmess_block_release_unverified"}))
        self.assertNotIn("vmess_block_release_unverified", agent._MOTD_THREAT_TYPES)

    def test_confirmed_vmess_alert_label_identifies_container_process_pid_and_port(self):
        label = agent._vmess_endpoint_label({"process":"xray","pid":120,"proto":"tcp","port":443})
        self.assertEqual(label, "xray（容器内 PID 120）监听 TCP/443")
        pending = agent._vmess_endpoint_label({"process":"xray","pid":120,"proto":"tcp","port":443}, pending=True)
        self.assertEqual(pending, "xray（容器内 PID 120），待核实 TCP/443")
        self.assertEqual(agent._vmess_endpoint_label({"process":"gost","pid":121,"proto":"udp","port":53}), "UDP/53")


class VmessConfigClockTests(unittest.TestCase):
    def _start_bound(self, namespaces='time:[42]\ntime:[42]\n', elapsed=0.01,
                     clock_id=7, ticks='90000'):
        with mock.patch.object(agent.os, 'readlink', return_value='time:[42]'), \
                mock.patch.object(agent.os, 'sysconf', return_value=100, create=True), \
                mock.patch.object(agent.time, 'CLOCK_BOOTTIME', clock_id, create=True), \
                mock.patch.object(agent.time, 'clock_gettime', return_value=1000.0, create=True), \
                mock.patch.object(agent.time, 'time', side_effect=[1700001000.0, 1700001000.0 + elapsed]), \
                mock.patch.object(agent, 'run', return_value=namespaces) as execute:
            bound = agent._protocol_process_start_epoch_lower_bound(
                'incus', 'fixture', 'default', 120, ticks,
            )
        return bound, execute

    def test_same_time_namespace_clock_gives_a_conservative_start_bound(self):
        bound, execute = self._start_bound()
        self.assertAlmostEqual(bound, 1700000899.99, places=4)
        command = execute.call_args.args[0][-1]
        self.assertIn('readlink /proc/120/ns/time', command)
        self.assertNotIn('date ', command)
        self.assertNotIn('getconf ', command)
        self.assertTrue(agent._protocol_config_predates_process(
            '1:2:100:stable|1700000800|1700000800', bound,
        ))

    def test_independent_time_namespace_is_not_combined_with_host_clock(self):
        for namespaces in ['time:[42]\ntime:[43]\n', 'time:[43]\ntime:[42]\n', '']:
            with self.subTest(namespaces=namespaces):
                self.assertIsNone(self._start_bound(namespaces=namespaces)[0])

    def test_unavailable_or_unstable_clock_basis_is_rejected(self):
        self.assertIsNone(self._start_bound(clock_id=None)[0])
        self.assertIsNone(self._start_bound(elapsed=-1)[0])
        self.assertIsNone(self._start_bound(elapsed=0.5)[0])
        self.assertIsNone(self._start_bound(ticks='100001')[0])

    def test_missing_epoch_metadata_does_not_prove_loaded_configuration(self):
        self.assertFalse(agent._protocol_config_predates_process('1:2:100:human-times', 1700000900.0))
        self.assertFalse(agent._protocol_config_predates_process('1:2:100|bad|1700000800', 1700000900.0))
        self.assertFalse(agent._protocol_config_predates_process('1:2:100|1700000800|1700000800', None))


class VmessReconcileTests(unittest.TestCase):
    def _reconcile_release(self, live_listeners, remaining_table=False, preserve_existing=False):
        identity = "incus\0default\0fixture\0container-id"
        digest = hashlib.sha256(identity.encode()).hexdigest()[:12]
        marker = f"narwhal-vmess-guard-v1-{digest}"
        table = f"narwhal_vmess_{digest}"
        calls = []

        def runner(args, **kwargs):
            command = args[4:]
            calls.append(command)
            if command == ["-a", "list", "table", "inet", table]:
                return mock.Mock(returncode=0, stdout=marker + "-tcp-443", stderr="")
            if command == ["delete", "table", "inet", table]:
                return mock.Mock(returncode=0, stdout="", stderr="")
            if command == ["-j", "list", "tables"]:
                tables = [{"table": {"family": "inet", "name": table}}] if remaining_table else []
                return mock.Mock(returncode=0, stdout=json.dumps({"nftables": tables}), stderr="")
            return mock.Mock(returncode=2, stdout="", stderr="unexpected command")

        with mock.patch.object(vmess_guard, "_pid_epoch", return_value="epoch"), \
                mock.patch.object(vmess_guard, "_open_namespace_fd", return_value=17), \
                mock.patch.object(vmess_guard.os, "close"), \
                mock.patch.object(vmess_guard.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}"):
            result = vmess_guard.reconcile(
                120, identity, "epoch", [], runner=runner,
                release_if_absent=True, live_listeners=live_listeners,
                preserve_existing=preserve_existing,
            )
        return result, calls

    def test_namespace_fd_is_closed_if_pid_identity_changes_while_opening(self):
        with mock.patch.object(vmess_guard, "_pid_epoch", side_effect=["epoch", "changed"]), \
                mock.patch.object(vmess_guard.os, "open", return_value=23), \
                mock.patch.object(vmess_guard.os, "close") as close:
            self.assertIsNone(vmess_guard._open_namespace_fd(120, "epoch"))
        close.assert_called_once_with(23)

    def test_nft_rules_are_namespace_local_validated_applied_and_read_back(self):
        identity = "podman\0\0fixture\0container-id"
        digest = hashlib.sha256(identity.encode()).hexdigest()[:12]
        marker = f"narwhal-vmess-guard-v1-{digest}"
        calls = []
        applied = False

        def runner(args, **kwargs):
            nonlocal applied
            calls.append((args, kwargs))
            command = args[4:]
            if command[:4] == ["-a", "list", "table", "inet"]:
                return mock.Mock(returncode=0 if applied else 1,
                                 stdout=(marker + "-tcp-443") if applied else "", stderr="")
            if command == ["-j", "list", "tables"]:
                return mock.Mock(returncode=0, stdout='{"nftables":[]}', stderr="")
            if command[:1] == ["--check"]:
                return mock.Mock(returncode=0, stdout="", stderr="")
            if command == ["-f", "-"]:
                applied = True
                return mock.Mock(returncode=0, stdout="", stderr="")
            return mock.Mock(returncode=2, stdout="", stderr="unexpected command")

        with mock.patch.object(vmess_guard, "_pid_epoch", return_value="epoch"), \
                mock.patch.object(vmess_guard, "_open_namespace_fd", return_value=17), \
                mock.patch.object(vmess_guard.os, "close"), \
                mock.patch.object(vmess_guard.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}"):
            result = vmess_guard.reconcile(
                120, identity, "epoch", [{"proto": "tcp", "port": 443}], runner=runner
            )

        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["blocked_endpoints"], [{"proto": "tcp", "port": 443}])
        self.assertTrue(all(call[0][0] == "/usr/bin/nsenter" for call in calls))
        self.assertTrue(all(call[0][1] == "--net=/proc/self/fd/17" for call in calls))
        self.assertTrue(all(call[1]["pass_fds"] == (17,) for call in calls))
        script = next(kwargs["input"] for args, kwargs in calls if "--check" in args)
        self.assertIn("add chain inet narwhal_vmess_", script)
        self.assertIn("meta l4proto tcp tcp dport 443 drop", script)
        self.assertIn(marker + "-tcp-443", script)

    def test_complete_absence_removes_owned_rule_and_reads_back_absence(self):
        result, calls = self._reconcile_release([])
        self.assertEqual(result["state"], "cleared")
        self.assertIn(["delete", "table", "inet", calls[0][-1]], calls)
        self.assertEqual(calls[-1], ["-j", "list", "tables"])

    def test_live_listener_keeps_old_rule_and_reports_pending_release(self):
        result, calls = self._reconcile_release([{
            "proto": "tcp", "port": 443, "pid": 120, "process": "xray",
            "application_protocols": ["vmess"],
            "application_protocol_evidence": "config_matches_live_pid_and_port",
            "vmess_process_scan_complete": True,
        }])
        self.assertEqual(result["state"], "release_pending")
        self.assertEqual(result["reason"], "guarded_port_still_has_listener")
        self.assertEqual(result["pending_removal_endpoints"], [{"proto": "tcp", "port": 443}])
        self.assertNotIn("delete", calls)

    def test_vless_listener_on_previously_guarded_port_is_released(self):
        result, calls = self._reconcile_release([{
            "proto": "tcp", "port": 443, "pid": 120, "process": "xray",
            "application_protocols": ["vless"],
            "application_protocol_evidence": "config_matches_live_pid_and_port",
        }])
        self.assertEqual(result["state"], "cleared")
        self.assertIn(["delete", "table", "inet", calls[0][-1]], calls)

    def test_shared_vmess_vless_endpoint_is_released_not_preserved(self):
        vmess = {
            "proto": "tcp", "port": 443, "pid": 120, "process": "xray",
            "application_protocols": ["vmess"],
            "application_protocol_evidence": "config_matches_live_pid_and_port",
            "vmess_process_scan_complete": True,
        }
        vless = {
            **vmess,
            "application_protocols": ["vless"],
            "vmess_process_scan_complete": False,
        }
        result, calls = self._reconcile_release([vmess, vless], preserve_existing=True)
        self.assertEqual(result["state"], "cleared")
        self.assertIn(["delete", "table", "inet", calls[0][-1]], calls)

    def test_failed_rule_removal_readback_is_not_reported_as_recovered(self):
        result, _ = self._reconcile_release([], remaining_table=True)
        self.assertEqual(result["state"], "release_pending")
        self.assertEqual(result["reason"], "firewall_remove_readback_failed")

    def test_full_listener_inventory_cap_prevents_release_eligibility(self):
        listeners = [
            {"pid": index + 2, "process": "test", "proto": "tcp", "port": index + 1,
             "local": f"0.0.0.0:{index + 1}"}
            for index in range(100)
        ]
        inventory, state = agent._build_service_inventory(
            {"connection_metrics": {"valid": True}, "listening_ports": [], "udp_listening_ports": []},
            {"communication_detail_available": True, "communication_snapshot_truncated": False,
             "service_listeners": listeners},
            [],
        )
        self.assertEqual(len(inventory), 100)
        self.assertEqual(state, "partial")

    def test_namespace_mismatch_fails_closed_before_running_commands(self):
        with mock.patch.object(vmess_guard, "_pid_epoch", return_value="changed"):
            runner = mock.Mock()
            result = vmess_guard.reconcile(
                120, "container", "expected", [{"proto": "tcp", "port": 443}], runner=runner
            )
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["reason"], "container_namespace_changed_or_shared")
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
