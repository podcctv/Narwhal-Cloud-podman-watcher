import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("narwhal_agent", ROOT / "client" / "agent.py")
assert SPEC and SPEC.loader
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class RuntimeDiscoveryTests(unittest.TestCase):
    def setUp(self):
        agent._podman_bin = None
        agent._container_bin = None
        agent._runtime_bins = None
        agent._disk_alert_cache = {}
        agent._disk_alert_cache_at = 0.0
        agent._warned_missing_bins.clear()

    def test_auto_discovers_all_available_runtimes(self):
        with mock.patch.dict(os.environ, {"CONTAINER_RUNTIMES": "auto"}, clear=False):
            with mock.patch.object(agent.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}"):
                self.assertEqual(
                    agent.get_runtime_bins(),
                    {"podman": "podman", "docker": "docker", "incus": "incus"},
                )

    def test_runtime_command_timeout_is_bounded_and_non_blocking(self):
        agent._warned_timeout_commands.clear()
        with mock.patch.dict(
            os.environ, {"RUNTIME_COMMAND_TIMEOUT_SECONDS": "7"}, clear=False
        ), mock.patch.object(
            agent.subprocess,
            "run",
            side_effect=agent.subprocess.TimeoutExpired(["incus", "list"], 7),
        ) as runner:
            self.assertEqual(agent.run(["incus", "list"]), "")
        self.assertEqual(runner.call_args.kwargs["timeout"], 7.0)
        self.assertIn("incus", agent._warned_timeout_commands)

    def test_explicit_runtime_subset_is_honored(self):
        with mock.patch.dict(os.environ, {"CONTAINER_RUNTIMES": "docker,incus"}, clear=False):
            with mock.patch.object(agent.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}"):
                self.assertEqual(agent.get_runtime_bins(), {"docker": "docker", "incus": "incus"})

    def test_server_tls_verify_defaults_to_enabled(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIs(agent.server_tls_verify(), True)

    def test_server_tls_verify_uses_configured_ca(self):
        with tempfile.NamedTemporaryFile() as ca_file:
            with mock.patch.dict(os.environ, {"SERVER_TLS_CA_FILE": ca_file.name}, clear=True):
                self.assertEqual(agent.server_tls_verify(), ca_file.name)

    def test_network_health_uses_host_routes_without_container_curl(self):
        def family_available(family):
            return family == agent.socket.AF_INET

        with mock.patch.object(
            agent, "_host_ip_family_available", side_effect=family_available
        ):
            self.assertEqual(agent.network_health([]), (True, False))

    def test_lists_oci_and_incus_containers_together(self):
        incus_payload = json.dumps(
            [
                {
                    "name": "web-incus",
                    "type": "container",
                    "status": "Running",
                    "project": "default",
                    "config": {"image.description": "Debian 13"},
                    "state": {"pid": 4321},
                }
            ]
        )

        def fake_run(cmd):
            if cmd[0] == "podman" and cmd[1] == "ps":
                return "p1|web-podman|alpine:latest\n"
            if cmd[0] == "docker" and cmd[1] == "ps":
                return "d1|web-docker|alpine:latest\n"
            if cmd[0] == "incus" and "list" in cmd:
                return incus_payload
            return ""

        env = {
            "MONITORED_IMAGE_PATTERNS": "alpine",
            "MONITORED_INCUS_PATTERNS": "*",
            "INCUS_PROJECT": "default",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch.object(
                agent,
                "get_runtime_bins",
                return_value={"podman": "podman", "docker": "docker", "incus": "incus"},
            ), mock.patch.object(agent, "run", side_effect=fake_run):
                containers = agent.list_containers()

        self.assertEqual([x["runtime"] for x in containers], ["podman", "docker", "incus"])
        self.assertEqual(containers[-1]["pid"], "4321")
        self.assertEqual(containers[-1]["project"], "default")

    def test_incus_all_projects_are_discovered_in_one_bounded_list(self):
        payload = json.dumps(
            [
                {"name": "default-node", "type": "container", "status": "Running", "project": "default"},
                {"name": "tenant-node", "type": "container", "status": "Running", "project": "tenant-a"},
            ]
        )

        def fake_run(cmd):
            if cmd[:2] == ["incus", "list"]:
                self.assertIn("--all-projects", cmd)
                return payload
            return "[]"

        with mock.patch.dict(
            os.environ,
            {"INCUS_PROJECT": "all", "MONITORED_INCUS_PATTERNS": "*"},
            clear=False,
        ), mock.patch.object(agent, "run", side_effect=fake_run):
            containers = agent._incus_containers("incus")

        self.assertEqual([item["name"] for item in containers], ["default-node", "tenant-node"])
        self.assertEqual([item["project"] for item in containers], ["default", "tenant-a"])

    def test_wildcard_includes_panel_and_service_images(self):
        with mock.patch.object(
            agent,
            "run",
            return_value="x1|xboard-panel|ghcr.io/cedar2025/xboard:latest\nn1|node|custom/service:latest\n",
        ):
            containers = agent._oci_containers("docker", "docker", ["*"])
        self.assertEqual([item["name"] for item in containers], ["xboard-panel", "node"])

    def test_docker_notice_mode_creates_lightweight_report_and_info_alert(self):
        source = {"id": "d1", "name": "helper", "image": "helper:latest", "runtime": "docker"}
        fs = {"root": {"total_bytes": 1000, "avail_bytes": 400}}
        with mock.patch.object(agent, "collect_disk_alert", return_value={}), mock.patch.object(
            agent,
            "collect_container_disk_usage",
            return_value={"rw_bytes": 0, "rootfs_bytes": 0, "fs": fs},
        ) as disk_mock:
            report = agent.collect_docker_notice(source)
        with mock.patch.dict(os.environ, {"SECURITY_ACCESS_LOG_PATHS": ""}, clear=False):
            summary = agent.collect_security_summary([report], 60)
        self.assertEqual(report["monitor_mode"], "notice")
        self.assertTrue(report["security"]["notice_only"])
        self.assertEqual(report["container_disk"]["fs"]["root"]["total_bytes"], 1000)
        disk_mock.assert_called_once_with("helper", "docker", "", include_layer_size=False)
        self.assertEqual(summary["alerts"][0]["type"], "docker_container_notice")
        self.assertEqual(summary["alerts"][0]["severity"], "info")

    def test_docker_off_mode_omits_docker_from_discovery(self):
        with mock.patch.dict(os.environ, {"DOCKER_MONITOR_MODE": "off"}, clear=False), mock.patch.object(
            agent, "get_runtime_bins", return_value={"docker": "docker", "podman": "podman"}
        ), mock.patch.object(agent, "_oci_containers", return_value=[] ) as collect_mock:
            agent.list_containers()
        self.assertEqual(collect_mock.call_count, 1)
        self.assertEqual(collect_mock.call_args.args[0], "podman")

    def test_host_main_disk_falls_back_to_root_without_data_mount(self):
        df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 1000 250 750 25% /\n"

        def exists(path):
            return False

        with mock.patch.object(agent.os.path, "exists", side_effect=exists), mock.patch.object(
            agent, "run", return_value=df
        ) as run_mock:
            disk = agent.collect_disk_alert()
        self.assertEqual(disk["data_requested_path"], "/")
        self.assertEqual(disk["data_mountpoint"], "/")
        self.assertEqual(disk["data_total_bytes"], 1000 * 1024)
        self.assertEqual(run_mock.call_args_list[-1].args[0], ["df", "-P", "/"])

    def test_host_main_disk_uses_data_when_present(self):
        root_df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 1000 250 750 25% /\n"
        data_df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vdb1 2000 500 1500 25% /data\n"

        def exists(path):
            return path == "/data"

        def fake_run(cmd):
            return data_df if cmd[-1] == "/data" else root_df

        with mock.patch.object(agent.os.path, "exists", side_effect=exists), mock.patch.object(
            agent, "run", side_effect=fake_run
        ):
            disk = agent.collect_disk_alert()
        self.assertEqual(disk["data_requested_path"], "/data")
        self.assertEqual(disk["data_mountpoint"], "/data")
        self.assertEqual(disk["data_avail_bytes"], 1500 * 1024)


class IncusMetricsTests(unittest.TestCase):
    SAMPLE = """
# TYPE incus_cpu_seconds_total counter
incus_cpu_seconds_total{cpu="0",mode="user",name="c1",project="default",type="container"} 12.5
incus_cpu_seconds_total{cpu="0",mode="system",name="c1",project="default",type="container"} 2.5
incus_cpu_seconds_total{cpu="0",mode="idle",name="c1",project="default",type="container"} 100
incus_cpu_effective_total{name="c1",project="default",type="container"} 2
incus_memory_MemTotal_bytes{name="c1",project="default",type="container"} 1048576
incus_memory_MemAvailable_bytes{name="c1",project="default",type="container"} 262144
incus_network_receive_bytes_total{device="eth0",name="c1",project="default",type="container"} 1000
incus_network_receive_bytes_total{device="lo",name="c1",project="default",type="container"} 999
incus_network_transmit_bytes_total{device="eth0",name="c1",project="default",type="container"} 2000
incus_network_receive_packets_total{device="eth0",name="c1",project="default",type="container"} 10
incus_network_transmit_packets_total{device="eth0",name="c1",project="default",type="container"} 20
incus_cpu_seconds_total{cpu="0",mode="user",name="vm1",project="default",type="virtual-machine"} 999
"""

    def test_parses_and_sums_container_metrics(self):
        parsed = agent._parse_incus_metrics(self.SAMPLE)
        self.assertEqual(set(parsed), {("default", "c1")})
        item = parsed[("default", "c1")]
        self.assertEqual(item["cpu_seconds"], 15.0)
        self.assertEqual(item["effective_cpus"], 2)
        self.assertEqual(item["mem_total_bytes"], 1048576)
        self.assertEqual(item["mem_available_bytes"], 262144)
        self.assertEqual(item["mem_bytes"], 786432)
        self.assertEqual(item["net_rx_total_bytes"], 1000)
        self.assertEqual(item["net_tx_total_bytes"], 2000)
        self.assertEqual(item["net_rx_total_packets"], 10)
        self.assertEqual(item["net_tx_total_packets"], 20)

    def test_incus_stats_uses_total_minus_available_without_container_exec(self):
        snapshot = agent._parse_incus_metrics(self.SAMPLE)
        with mock.patch.object(agent, "_derive_cpu_percent", return_value=12.5), mock.patch.object(
            agent, "run"
        ) as run_mock:
            result = agent._incus_stats("incus", "c1", "default", snapshot)
        self.assertEqual(result["cpu_percent"], 12.5)
        self.assertEqual(result["cpu_effective_cpus"], 2)
        self.assertEqual(result["mem_bytes"], 786432)
        self.assertEqual(result["mem_limit_bytes"], 1048576)
        self.assertEqual(result["mem_percent"], 75.0)
        run_mock.assert_not_called()

    def test_oci_stats_keeps_memory_limit_and_calculates_percent(self):
        parsed = agent._parse_stats_json(
            json.dumps([{"CPUPerc": "1.25%", "MemUsage": "20MiB / 100MiB", "NetIO": "1MB / 2MB"}])
        )
        self.assertEqual(parsed["mem_bytes"], 20 * 1024 * 1024)
        self.assertEqual(parsed["mem_limit_bytes"], 100 * 1024 * 1024)
        self.assertEqual(parsed["mem_percent"], 20.0)

    def test_incus_exec_uses_argument_separator_and_project(self):
        self.assertEqual(
            agent._runtime_exec_cmd("incus", "c1", "df -P /", "prod"),
            ["incus", "--project", "prod", "exec", "c1", "--", "sh", "-lc", "df -P /"],
        )
        self.assertEqual(
            agent._runtime_exec_cmd("docker", "c1", "df -P /"),
            ["docker", "exec", "c1", "sh", "-lc", "df -P /"],
        )

    def test_incus_instance_pid_queries_project_in_url(self):
        payload = json.dumps({"metadata": {"pid": 592319}})
        with mock.patch.object(agent, "run", return_value=payload) as run_mock:
            pid = agent._incus_instance_pid("incus", "node 1", "prod/main")

        self.assertEqual(pid, 592319)
        run_mock.assert_called_once_with(
            ["incus", "query", "/1.0/instances/node%201/state?project=prod%2Fmain"]
        )


class SecurityTelemetryTests(unittest.TestCase):
    def setUp(self):
        agent._access_log_states.clear()
        agent._protocol_counters.clear()
        agent._geoip_country_cache.clear()

    def test_reads_protocol_counters_from_container_network_namespace(self):
        snmp = (
            "Tcp: ActiveOpens AttemptFails EstabResets OutRsts\n"
            "Tcp: 100 7 3 9\n"
            "Udp: OutDatagrams NoPorts InErrors\n"
            "Udp: 500 2 1\n"
        )
        with mock.patch("builtins.open", mock.mock_open(read_data=snmp)):
            counters = agent._read_protocol_counters(123)
        self.assertEqual(counters["Tcp_ActiveOpens"], 100)
        self.assertEqual(counters["Tcp_AttemptFails"], 7)
        self.assertEqual(counters["Udp_OutDatagrams"], 500)

    def test_reads_process_count_from_container_cgroup(self):
        with mock.patch("builtins.open", mock.mock_open(read_data="321\n")):
            self.assertEqual(agent._read_process_count_from_pid(123), 321)

    def test_socket_snapshot_attributes_inbound_and_outbound_processes(self):
        snapshot = (
            '@@SS_AVAILABLE@@\n'
            'tcp ESTAB 0 0 10.0.0.2:443 203.0.113.10:50123 users:(("nginx",pid=42,fd=8))\n'
            'tcp ESTAB 0 0 10.0.0.2:53000 198.51.100.20:443 users:(("curl",pid=88,fd=3))\n'
        )
        with mock.patch.object(agent, "run", return_value=snapshot):
            result = agent._collect_socket_process_details(
                "incus", "node1", "default", [443]
            )

        self.assertTrue(result["communication_detail_available"])
        self.assertEqual(
            [item["direction"] for item in result["communication_sockets"]],
            ["inbound", "outbound"],
        )
        self.assertEqual(result["communication_processes"][0]["process"], "nginx")
        self.assertEqual(result["communication_processes"][0]["inbound_connections"], 1)

    def test_conntrack_restores_original_sources_hidden_by_incus_proxy(self):
        entries = []
        for suffix in range(1, 12):
            parsed = agent._parse_conntrack_line(
                f"ipv4 2 tcp 6 431999 ESTABLISHED src=8.8.8.{suffix} "
                "dst=9.9.9.9 sport=50000 dport=18443 "
                f"src=9.9.9.9 dst=8.8.8.{suffix} sport=18443 dport=50000 [ASSURED]"
            )
            self.assertIsNotNone(parsed)
            entries.append(parsed)
        security = {
            "container_ips": ["10.91.0.2"],
            "inbound_unique_ips": 1,
            "inbound_top_ips": [{"ip": "10.91.0.1", "connections": 11}],
        }
        agent._apply_host_conntrack_security(
            security,
            {"available": True, "snapshot_count": 11, "entries": entries},
            ["10.91.0.2"],
            [
                {
                    "source": "incus-proxy",
                    "listen": "tcp:0.0.0.0:18443",
                    "target": "tcp:10.91.0.2:443",
                }
            ],
        )
        self.assertEqual(security["inbound_ip_observation"], "host_conntrack")
        self.assertEqual(security["inbound_unique_ips"], 11)
        self.assertEqual(security["inbound_public_flows"][0]["container_port"], 443)

    def test_original_conntrack_sources_are_attributed_to_listening_process(self):
        communication = {
            "communication_sockets": [
                {
                    "direction": "inbound",
                    "local": "10.91.0.2:443",
                    "process": "nginx",
                    "pid": 42,
                }
            ],
            "communication_processes": [{"process": "nginx", "pid": 42}],
        }
        agent._enrich_communication_with_original_sources(
            communication,
            [
                {
                    "remote_ip": "8.8.8.8",
                    "container_port": 443,
                    "connections": 3,
                }
            ],
        )
        process = communication["communication_processes"][0]
        self.assertEqual(process["original_inbound_unique_ips"], 1)
        self.assertEqual(
            communication["communication_sockets"][0]["original_remote_ips"],
            ["8.8.8.8"],
        )

    def test_private_proxy_gateway_is_not_counted_as_public_source(self):
        entry = agent._parse_conntrack_line(
            "ipv4 2 tcp 6 431999 ESTABLISHED src=10.91.0.1 dst=10.91.0.5 "
            "sport=50000 dport=22 src=10.91.0.5 dst=10.91.0.1 sport=22 dport=50000"
        )
        security = {"container_ips": ["10.91.0.5"], "inbound_unique_ips": 1}
        agent._apply_host_conntrack_security(
            security,
            {"available": True, "snapshot_count": 1, "entries": [entry]},
            ["10.91.0.5"],
            [],
        )
        self.assertEqual(security["inbound_unique_ips"], 1)
        self.assertEqual(security.get("inbound_ip_observation"), None)

    def test_host_nat_rule_links_outer_proxy_connection_to_container(self):
        conntrack_line = (
            "ipv4 2 tcp 6 431999 ESTABLISHED src=8.8.4.4 dst=9.9.9.9 "
            "sport=50000 dport=18443 src=9.9.9.9 dst=8.8.4.4 sport=18443 dport=50000"
        )
        ip_output = '[{"addr_info":[{"local":"9.9.9.9","scope":"global"}]}]'
        nat_output = (
            "-A PREROUTING -d 9.9.9.9/32 -p tcp --dport 18443 "
            "-j DNAT --to-destination 10.91.0.5:443"
        )
        with mock.patch("builtins.open", side_effect=FileNotFoundError), mock.patch.object(
            agent,
            "run",
            side_effect=[conntrack_line, ip_output, nat_output],
        ):
            snapshot = agent._collect_host_conntrack_snapshot()
        security = {"container_ips": ["10.91.0.5"], "inbound_unique_ips": 0}
        agent._apply_host_conntrack_security(
            security,
            snapshot,
            ["10.91.0.5"],
            [],
        )
        self.assertEqual(security["inbound_ip_observation"], "host_conntrack")
        self.assertEqual(security["inbound_unique_ips"], 1)
        self.assertEqual(security["inbound_public_flows"][0]["container_port"], 443)

    def test_incus_network_forward_ports_become_container_mappings(self):
        agent._incus_forward_cache.clear()
        networks = '[{"name":"incusbr0","managed":true}]'
        forwards = json.dumps(
            [
                {
                    "listen_address": "9.9.9.9",
                    "config": {},
                    "ports": [
                        {
                            "protocol": "tcp",
                            "listen_port": "18080,18443",
                            "target_address": "10.91.0.5",
                            "target_port": "80,443",
                        }
                    ],
                }
            ]
        )
        with mock.patch.object(agent, "run", side_effect=[networks, forwards]):
            mappings = agent._incus_network_forward_mappings("incus", "default")
        self.assertEqual(len(mappings), 2)
        self.assertEqual(mappings[0]["listen"], "tcp:9.9.9.9:18080")
        self.assertEqual(mappings[1]["target"], "tcp:10.91.0.5:443")

    def test_unique_host_proxy_pid_links_public_socket_to_container(self):
        snapshot = (
            'tcp LISTEN 0 128 9.9.9.9:18443 0.0.0.0:* users:(("socat",pid=100,fd=3))\n'
            'tcp ESTAB 0 0 9.9.9.9:18443 8.8.8.8:50000 users:(("socat",pid=100,fd=4))\n'
            'tcp ESTAB 0 0 10.91.0.1:40000 10.91.0.5:443 users:(("socat",pid=100,fd=5))\n'
        )
        conntrack = {"entries": [], "nat_mappings": []}
        containers = [
            {
                "runtime": "incus",
                "name": "node1",
                "network_addresses": ["10.91.0.5"],
            }
        ]
        with mock.patch.object(agent, "run", return_value=snapshot):
            agent._augment_conntrack_with_host_proxy_sockets(conntrack, containers)
        security = {"container_ips": ["10.91.0.5"], "inbound_unique_ips": 0}
        agent._apply_host_conntrack_security(
            security,
            conntrack,
            ["10.91.0.5"],
            [],
        )
        self.assertEqual(conntrack["host_proxy_matched_connections"], 1)
        self.assertEqual(security["inbound_unique_ips"], 1)
        self.assertEqual(security["inbound_public_flows"][0]["container_port"], 443)

    def test_proc_ipv6_decoder_normalizes_ipv4_mapped_address(self):
        self.assertEqual(
            agent._decode_proc_addr("0000000000000000FFFF000006005B0A", is_v6=True),
            "10.91.0.6",
        )
        self.assertEqual(
            agent._parse_socket_endpoint("[::ffff:113.118.70.81]:31022"),
            ("113.118.70.81", 31022),
        )

    def test_audits_podman_and_incus_isolation_risks(self):
        oci = agent._oci_security_risks(
            {
                "HostConfig": {"Privileged": True, "CapAdd": ["SYS_ADMIN"], "NetworkMode": "host"},
                "Mounts": [{"Source": "/", "Destination": "/host"}],
            }
        )
        incus = agent._incus_security_risks(
            {
                "config": {"security.privileged": "true", "security.nesting": "true"},
                "expanded_devices": {"host-root": {"type": "disk", "source": "/", "path": "/host"}},
            }
        )
        self.assertIn("oci_privileged", {item["code"] for item in oci})
        self.assertIn("oci_sensitive_mount", {item["code"] for item in oci})
        self.assertIn("incus_privileged", {item["code"] for item in incus})
        self.assertIn("incus_sensitive_mount", {item["code"] for item in incus})
        oci_exposure = agent._oci_network_exposure(
            {
                "NetworkSettings": {
                    "Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "32001"}]}
                }
            }
        )
        incus_exposure = agent._incus_network_exposure(
            {
                "expanded_devices": {
                    "web": {
                        "type": "proxy",
                        "listen": "tcp:0.0.0.0:32002",
                        "connect": "tcp:127.0.0.1:8080",
                    }
                }
            }
        )
        self.assertEqual(oci_exposure[0]["listen"], "0.0.0.0:32001")
        self.assertEqual(oci_exposure[0]["target"], "8080/tcp")
        self.assertEqual(incus_exposure[0]["listen"], "tcp:0.0.0.0:32002")
        self.assertEqual(incus_exposure[0]["target"], "tcp:127.0.0.1:8080")

    def test_detects_panel_pairing_without_returning_api_keys(self):
        commands = []

        def fake_run(cmd):
            commands.append(cmd[-1])
            if "ps -eo pid=,stat=,comm=,args=" in cmd[-1]:
                return "123 S xboard-node xboard-node --config /etc/xboard-node/config.yml\n"
            return (
                "@@FILE:/etc/xboard-node/config.yml\n"
                "https://panel.example.net/api\n"
                "@@KEY:ApiHost\n@@KEY:ApiKey\n@@KEY:NodeID\n@@ENV\n"
            )

        env = {
            "SECURITY_PANEL_PROCESS_PATTERNS": "xboard-node,xrayr",
            "SECURITY_PANEL_CONFIG_PATHS": "/etc/xboard-node/config.yml",
            "SECURITY_ALLOWED_PANEL_DOMAINS": "trusted.example.com",
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(agent, "run", side_effect=fake_run):
            result = agent.collect_panel_pairing_indicators("node", "podman")
        self.assertTrue(result["detected"])
        self.assertEqual(result["panel_domains"], ["panel.example.net"])
        self.assertEqual(result["unapproved_domains"], ["panel.example.net"])
        self.assertEqual(result["process_matches"], [{"pid": 123, "pattern": "xboard-node"}])
        self.assertNotIn("secret", json.dumps(result))
        evidence_command = next(item for item in commands if "scan_panel_env" in item)
        self.assertIn("env_scan_max=32", evidence_command)
        self.assertIn("for pid in 123", evidence_command)
        self.assertEqual(evidence_command.count('dd if="$f"'), 1)
        self.assertTrue(agent._panel_domain_allowed("api.trusted.example.com", ["trusted.example.com"]))
        self.assertFalse(agent._panel_domain_allowed("trusted.example.com.evil.test", ["trusted.example.com"]))

    def test_geoip_uses_local_results_before_batched_https(self):
        with mock.patch.object(
            agent,
            "_geoip_local_country_batch",
            return_value={"1.1.1.1": "AU"},
        ) as local_lookup, mock.patch.object(
            agent,
            "_geoip_https_country_batch",
            return_value={"8.8.8.8": "US"},
        ) as https_lookup:
            result = agent._geoip_country_batch({"1.1.1.1": 2, "8.8.8.8": 3})
        local_lookup.assert_called_once_with(["1.1.1.1", "8.8.8.8"])
        https_lookup.assert_called_once_with(["8.8.8.8"])
        self.assertEqual(
            {item["country"]: item["connections"] for item in result},
            {"AU": 2, "US": 3},
        )

    def test_geoip_https_is_encrypted_batched_and_cache_is_bounded(self):
        response = mock.Mock()
        response.json.return_value = [
            {"ip": "1.1.1.1", "country": "AU"},
            {"ip": "8.8.8.8", "country": "US"},
        ]
        with mock.patch.dict(
            os.environ,
            {
                "GEOIP_HTTPS_ENDPOINT": "https://api.country.is/",
                "GEOIP_CACHE_MAX_ENTRIES": "100",
            },
            clear=False,
        ), mock.patch.object(agent.requests, "post", return_value=response) as post:
            resolved = agent._geoip_https_country_batch(["1.1.1.1", "8.8.8.8"])
            for index in range(110):
                agent._geoip_cache_put(f"203.0.113.{index}", "UN", float(index))
        self.assertEqual(resolved, {"1.1.1.1": "AU", "8.8.8.8": "US"})
        self.assertEqual(post.call_args.args[0], "https://api.country.is/")
        self.assertEqual(post.call_args.kwargs["json"], ["1.1.1.1", "8.8.8.8"])
        self.assertLessEqual(len(agent._geoip_country_cache), 100)

    def test_geoip_never_sends_private_ips_to_external_services(self):
        with mock.patch.object(
            agent, "_geoip_local_country_batch"
        ) as local_lookup, mock.patch.object(
            agent, "_geoip_https_country_batch"
        ) as https_lookup:
            result = agent._geoip_country_batch({"10.0.0.8": 4})
        local_lookup.assert_not_called()
        https_lookup.assert_not_called()
        self.assertEqual(result, [{"country": "UN", "connections": 4, "ip_count": 1}])

    def test_panel_detection_ignores_zombie_processes(self):
        def fake_run(cmd):
            if "ps -eo pid=,stat=,comm=,args=" in cmd[-1]:
                return "456 Z v2bx [v2bx] <defunct>\n"
            return "@@ENV\n"

        with mock.patch.dict(
            os.environ,
            {"SECURITY_PANEL_PROCESS_PATTERNS": "v2bx", "SECURITY_PANEL_CONFIG_PATHS": ""},
            clear=False,
        ), mock.patch.object(agent, "run", side_effect=fake_run):
            result = agent.collect_panel_pairing_indicators("node", "incus")
        self.assertFalse(result["detected"])
        self.assertEqual(result["process_matches"], [])

    def test_panel_detection_does_not_treat_config_path_as_process(self):
        def fake_run(cmd):
            if "ps -eo pid=,stat=,comm=,args=" in cmd[-1]:
                return "789 S cat cat /etc/V2bX/config.json\n"
            return "@@ENV\n"

        with mock.patch.dict(
            os.environ,
            {"SECURITY_PANEL_PROCESS_PATTERNS": "v2bx", "SECURITY_PANEL_CONFIG_PATHS": ""},
            clear=False,
        ), mock.patch.object(agent, "run", side_effect=fake_run):
            result = agent.collect_panel_pairing_indicators("node", "incus")
        self.assertFalse(result["detected"])

    def test_persistent_panel_allowlist_merges_exact_domains(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = str(Path(tmp) / "allowlist.json")
            env = {
                "SECURITY_ALLOWED_PANEL_DOMAINS": "trusted.example.com",
                "SECURITY_PANEL_ALLOWLIST_FILE": policy,
            }
            with mock.patch.dict(os.environ, env, clear=False):
                merged = agent.add_allowed_panel_domains(["panel.example.net"])
                self.assertEqual(merged, ["panel.example.net", "trusted.example.com"])
                self.assertEqual(agent._configured_allowed_panel_domains(), merged)
                if os.name != "nt":
                    self.assertEqual(Path(policy).stat().st_mode & 0o777, 0o600)

    def test_panel_remediation_executes_inside_container_without_stopping_container(self):
        action = {
            "runtime": "incus",
            "project": "default",
            "container_name": "node1",
            "params": {
                "process_patterns": ["v2bx"],
                "process_pids": [4321],
                "config_files": ["/etc/V2bX/config.json"],
            },
        }
        env = {
            "SECURITY_PANEL_PROCESS_PATTERNS": "v2bx,xrayr",
            "SECURITY_PANEL_CONFIG_PATHS": "/etc/V2bX/config.json,/etc/XrayR/config.yml",
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
            agent, "get_runtime_bins", return_value={"incus": "incus"}
        ), mock.patch.object(
            agent, "_incus_host_namespace_kill", return_value=(0, 0, 0, "")
        ), mock.patch.object(agent, "_run_action_command", return_value=(True, "cleaned")) as runner:
            ok, _ = agent.remediate_panel_pairing(action)
        self.assertTrue(ok)
        command = runner.call_args.args[0]
        self.assertEqual(command[:5], ["incus", "--project", "default", "exec", "node1"])
        self.assertIn("/etc/V2bX/config.json", command[-1])
        self.assertIn("for proc in /proc/[0-9]*", command[-1])
        self.assertIn("openrc\\.", command[-1])
        self.assertNotIn("-type f,l", command[-1])
        self.assertIn("\\( -type f -o -type l \\)", command[-1])
        self.assertIn('rc-update del "$svc"', command[-1])
        self.assertNotIn(" stop node1", " ".join(command))

    def test_panel_remediation_reports_zero_changes_as_failure(self):
        action = {
            "runtime": "incus",
            "project": "default",
            "container_name": "node1",
            "params": {"process_patterns": ["v2bx"], "process_pids": [4321]},
        }
        with mock.patch.dict(
            os.environ, {"SECURITY_PANEL_PROCESS_PATTERNS": "v2bx"}, clear=False
        ), mock.patch.object(agent, "get_runtime_bins", return_value={"incus": "incus"}), mock.patch.object(
            agent, "_incus_host_namespace_kill", return_value=(1, 0, 0, "host matched but not killed")
        ), mock.patch.object(
            agent,
            "_run_action_command",
            return_value=(False, "killed_processes=0 removed_services=0 removed_configs=0 cleanup_errors=0"),
        ):
            ok, message = agent.remediate_panel_pairing(action)
        self.assertFalse(ok)
        self.assertIn("killed_processes=0", message)

    @unittest.skipIf(os.name == "nt", "POSIX shell integration requires Linux")
    def test_panel_remediation_shell_removes_openrc_alias_service(self):
        action = {
            "runtime": "incus",
            "project": "default",
            "container_name": "node1",
            "params": {"process_patterns": ["xboard-node"]},
        }
        with mock.patch.dict(
            os.environ,
            {
                "SECURITY_PANEL_PROCESS_PATTERNS": "xboard-node",
                "SECURITY_PANEL_CONFIG_PATHS": "",
            },
            clear=False,
        ), mock.patch.object(
            agent, "get_runtime_bins", return_value={"incus": "incus"}
        ), mock.patch.object(
            agent, "_incus_host_namespace_kill", return_value=(0, 0, 0, "")
        ), mock.patch.object(
            agent, "_run_action_command", return_value=(True, "cleaned")
        ) as runner, tempfile.TemporaryDirectory() as tmp:
            ok, _ = agent.remediate_panel_pairing(action)
            script = runner.call_args.args[0][-1]
            root = Path(tmp)
            init_dir = root / "etc" / "init.d"
            init_dir.mkdir(parents=True)
            alias = init_dir / "bby-agent"
            alias.write_text(
                "#!/bin/sh\n# xboard-node OpenRC alias\nexit 0\n",
                encoding="utf-8",
            )
            alias.chmod(0o755)
            replacements = {
                "/etc/systemd/system": str(root / "etc-systemd"),
                "/lib/systemd/system": str(root / "lib-systemd"),
                "/usr/lib/systemd/system": str(root / "usr-systemd"),
                "/run/systemd/system": str(root / "run-systemd"),
                "/etc/init.d": str(init_dir),
                "/etc/supervisor": str(root / "supervisor"),
                "/etc/cron.d": str(root / "cron.d"),
                "/etc/cron.daily": str(root / "cron.daily"),
                "/etc/cron.hourly": str(root / "cron.hourly"),
                "/var/spool/cron": str(root / "spool-cron"),
                "/proc/": str(root / "proc") + "/",
            }
            for source, target in replacements.items():
                script = script.replace(source, target)
            completed = agent.subprocess.run(
                ["sh", "-lc", script], capture_output=True, text=True, timeout=10
            )
            alias_removed = not alias.exists()
        self.assertTrue(ok)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("removed_services=1", completed.stdout)
        self.assertTrue(alias_removed)

    def test_incus_remediation_falls_back_to_host_user_namespace(self):
        action = {
            "runtime": "incus",
            "project": "default",
            "container_name": "node1",
            "params": {"process_patterns": ["v2bx"], "process_pids": [4321]},
        }
        results = [
            (False, "killed_processes=0 removed_services=0 removed_configs=0 cleanup_errors=0"),
            (True, "host_matched_processes=1 host_killed_processes=1 host_kill_errors=0"),
        ]
        with mock.patch.dict(
            os.environ, {"SECURITY_PANEL_PROCESS_PATTERNS": "v2bx"}, clear=False
        ), mock.patch.object(agent, "get_runtime_bins", return_value={"incus": "incus"}), mock.patch.object(
            agent, "_incus_instance_pid", return_value=9876
        ), mock.patch.object(agent.shutil, "which", return_value="/usr/bin/nsenter"), mock.patch.object(
            agent, "_run_action_command", side_effect=results
        ) as runner:
            ok, message = agent.remediate_panel_pairing(action)

        self.assertTrue(ok)
        self.assertIn("killed_processes=1", message)
        host_command = runner.call_args_list[1].args[0]
        self.assertEqual(host_command[:5], ["nsenter", "-t", "9876", "-p", "-m"])
        self.assertEqual(host_command[6], "/bin/sh")
        self.assertIn('"$candidate" = "$pattern"', host_command[-1])
        self.assertIn("extra_candidates=", host_command[-1])
        self.assertIn("supervise-daemo|supervise-daemon", host_command[-1])
        self.assertNotIn("requested_pids", host_command[-1])

    def test_panel_defaults_include_bby_agent_config(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIn(
                "/usr/local/etc/bby-agent.yml",
                agent._configured_panel_config_paths(),
            )

    def test_confirmed_panel_domain_is_silently_auto_remediated(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = str(Path(tmp) / "auto-remediate.json")
            env = {
                "SECURITY_PANEL_AUTO_REMEDIATE_FILE": policy,
                "SECURITY_PANEL_PROCESS_PATTERNS": "v2bx",
                "SECURITY_PANEL_CONFIG_PATHS": "/etc/V2bX/config.json",
                "SECURITY_ACCESS_LOG_PATHS": "",
            }
            container = {
                "runtime": "incus",
                "project": "default",
                "name": "node1",
                "security": {
                    "panel_pairing": {
                        "detected": True,
                        "panel_domains": ["panel.example.net"],
                        "unapproved_domains": ["panel.example.net"],
                        "process_patterns": ["v2bx"],
                        "config_files": ["/etc/V2bX/config.json"],
                    }
                },
            }
            with mock.patch.dict(os.environ, env, clear=False):
                agent.add_auto_remediate_panel_domains(["panel.example.net"])
                with mock.patch.object(
                    agent, "remediate_panel_pairing", return_value=(True, "cleaned")
                ) as remediate:
                    summary = agent.collect_security_summary([container], 60)
            self.assertEqual(
                [item for item in summary["alerts"] if item["type"] == "unauthorized_panel_pairing"],
                [],
            )
            remediate.assert_called_once()

    def test_manual_remediation_remembers_domains_for_future_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = str(Path(tmp) / "auto-remediate.json")
            action = {
                "action_type": "remediate_panel_pairing",
                "params": {"domains": ["panel.example.net"]},
            }
            with mock.patch.dict(
                os.environ, {"SECURITY_PANEL_AUTO_REMEDIATE_FILE": policy}, clear=False
            ), mock.patch.object(agent, "remediate_panel_pairing", return_value=(True, "cleaned")):
                ok, message = agent.execute_security_action(action)
                remembered = agent._configured_auto_remediate_panel_domains()
            self.assertTrue(ok)
            self.assertIn("silent automatic remediation", message)
            self.assertEqual(remembered, ["panel.example.net"])

    def test_new_panel_domain_still_alerts_when_known_domain_is_auto_remediated(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = str(Path(tmp) / "auto-remediate.json")
            env = {
                "SECURITY_PANEL_AUTO_REMEDIATE_FILE": policy,
                "SECURITY_PANEL_PROCESS_PATTERNS": "v2bx",
                "SECURITY_PANEL_CONFIG_PATHS": "/etc/V2bX/config.json",
                "SECURITY_ACCESS_LOG_PATHS": "",
            }
            container = {
                "runtime": "podman",
                "name": "node1",
                "security": {
                    "panel_pairing": {
                        "detected": True,
                        "panel_domains": ["known.example.net", "new.example.net"],
                        "unapproved_domains": ["known.example.net", "new.example.net"],
                        "process_patterns": ["v2bx"],
                        "config_files": ["/etc/V2bX/config.json"],
                    }
                },
            }
            with mock.patch.dict(os.environ, env, clear=False):
                agent.add_auto_remediate_panel_domains(["known.example.net"])
                with mock.patch.object(
                    agent, "remediate_panel_pairing", return_value=(True, "cleaned")
                ):
                    summary = agent.collect_security_summary([container], 60)
            panel_alert = next(
                item for item in summary["alerts"] if item["type"] == "unauthorized_panel_pairing"
            )
            self.assertEqual(panel_alert["unapproved_domains"], ["new.example.net"])

    def test_deep_sample_action_is_scheduled_without_premature_result(self):
        action = {
            "id": 42,
            "runtime": "incus",
            "project": "default",
            "container_name": "node1",
            "action_type": "request_deep_sample",
            "params": {"sample_seconds": 1, "process_limit": 100, "socket_limit": 250},
        }
        agent._pending_deep_samples.clear()
        with mock.patch.object(
            agent, "signed_post_json", return_value={"actions": [action]}
        ) as post:
            changed = agent.process_security_actions("https://server", "secret", "host1")
        self.assertTrue(changed)
        self.assertEqual(post.call_count, 1)
        self.assertEqual(agent._pending_deep_samples[42]["container_name"], "node1")
        self.assertEqual(
            agent._pending_deep_sample_for(
                {"runtime": "incus", "project": "default", "name": "node1"}
            )["id"],
            42,
        )
        agent._pending_deep_samples.clear()

    def test_deep_process_snapshot_redacts_common_credentials(self):
        output = (
            "12 1 root S 3.5 2048 app /usr/bin/app --token=abc123 "
            "--password=hunter2 https://user:pass@example.net/api\n"
        )
        with mock.patch.object(agent, "run", return_value=output):
            result = agent._collect_deep_process_snapshot("incus", "node1", "default", 100)
        command = result["items"][0]["command"]
        self.assertNotIn("abc123", command)
        self.assertNotIn("hunter2", command)
        self.assertNotIn("user:pass", command)
        self.assertGreater(result["items"][0]["rss_bytes"], 0)

    @unittest.skipUnless(os.path.isdir("/proc/self"), "Linux /proc is required")
    def test_deep_process_snapshot_falls_back_to_bounded_host_proc(self):
        result, private_items = agent._collect_host_proc_process_snapshot(os.getpid(), 20)
        self.assertTrue(result["available"])
        self.assertGreaterEqual(result["captured"], 1)
        self.assertEqual(result["source"], "host_proc")
        self.assertNotIn("host_pid", result["items"][0])
        self.assertIn("host_pid", private_items[0])

    def test_socks_process_detection_flags_no_auth_without_exposing_credentials(self):
        no_auth = agent._socks_process_evidence(
            "12 S microsocks /usr/bin/microsocks -p 1080\n", "container"
        )
        weak = agent._socks_process_evidence(
            "13 S microsocks /usr/bin/microsocks -u admin -P password\n", "container"
        )
        self.assertTrue(no_auth["detected"])
        self.assertEqual(no_auth["auth_mode"], "no_auth")
        self.assertEqual(weak["auth_mode"], "weak_password")
        self.assertNotIn("password", json.dumps(weak["process_matches"]))

    def test_socks_config_detection_returns_markers_not_credentials(self):
        markers = "@@SOCKS:/etc/danted.conf\n@@NOAUTH:/etc/danted.conf\n"
        with mock.patch.object(agent, "run", return_value=markers):
            result = agent._collect_socks_config_evidence("incus", "proxy", "default", True)
        self.assertTrue(result["detected"])
        self.assertEqual(result["auth_mode"], "no_auth")
        self.assertEqual(result["config_files"], ["/etc/danted.conf"])

    def test_config_confirmed_xray_socks_keeps_safe_process_target(self):
        process_output = "12 S xray /usr/bin/xray run -config /etc/xray/config.json\n"
        markers = "@@SOCKS:/etc/xray/config.json\n@@NOAUTH:/etc/xray/config.json\n"
        with mock.patch.object(agent, "run", side_effect=[process_output, markers, ""]):
            result = agent.collect_panel_pairing_indicators(
                "proxy", "incus", "default", "xray:latest"
            )
        socks = result["socks_proxy"]
        self.assertTrue(socks["detected"])
        self.assertEqual(socks["auth_mode"], "no_auth")
        self.assertEqual(
            socks["process_matches"],
            [{"pid": 12, "process": "xray", "auth_state": "no_auth"}],
        )

    def test_config_confirmed_sockd_uses_config_auth_for_safe_process_target(self):
        process_output = "14 S sockd /usr/sbin/sockd -f /etc/sockd.conf\n"
        markers = "@@SOCKS:/etc/sockd.conf\n@@NOAUTH:/etc/sockd.conf\n"
        with mock.patch.object(agent, "run", side_effect=[process_output, markers, ""]):
            result = agent.collect_panel_pairing_indicators(
                "proxy", "incus", "default", "debian:latest"
            )
        socks = result["socks_proxy"]
        self.assertEqual(socks["auth_mode"], "no_auth")
        self.assertEqual(
            socks["process_matches"],
            [{"pid": 14, "process": "sockd", "auth_state": "no_auth"}],
        )

    def test_socks_inbound_fanout_replaces_generic_alert(self):
        container = {
            "name": "proxy",
            "runtime": "incus",
            "security": {
                "inbound_unique_ips": 11,
                "communication_processes": [],
                "socks_proxy": {
                    "detected": True,
                    "auth_mode": "no_auth",
                    "public_exposure": True,
                    "process_matches": [{"pid": 12, "process": "microsocks"}],
                },
                "panel_pairing": {},
            },
        }
        with mock.patch.dict(
            os.environ,
            {"ALERT_INBOUND_UNIQUE_IPS": "10", "SECURITY_ACCESS_LOG_PATHS": ""},
            clear=False,
        ):
            result = agent.collect_security_summary([container], 60)
        types = {item["type"] for item in result["alerts"]}
        self.assertIn("socks_weak_auth", types)
        self.assertIn("socks_inbound_fanout", types)
        self.assertNotIn("inbound_ip_fanout", types)

    def test_socks_alert_contains_safe_action_evidence(self):
        container = {
            "name": "proxy",
            "runtime": "incus",
            "project": "default",
            "security": {
                "socks_proxy": {
                    "detected": True,
                    "auth_mode": "no_auth",
                    "public_exposure": True,
                    "process_matches": [{"pid": 12, "process": "microsocks"}],
                    "config_files": ["/etc/microsocks.conf"],
                },
                "panel_pairing": {},
            },
        }
        with mock.patch.object(agent, "_socks_auth_enforcement_entries", return_value=[]):
            result = agent.collect_security_summary([container], 60)
        alert = next(item for item in result["alerts"] if item["type"] == "socks_weak_auth")
        self.assertEqual(alert["socks_auth_mode"], "no_auth")
        self.assertEqual(alert["socks_processes"], ["microsocks"])
        self.assertEqual(alert["socks_process_pids"], [12])
        self.assertNotIn("password", json.dumps(alert))

    def test_socks_enforcement_repeats_no_auth_stop_and_releases_on_nonempty_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = str(Path(tmp) / "socks-policy.json")
            env = {"SECURITY_SOCKS_AUTH_ENFORCEMENT_FILE": policy_path}
            with mock.patch.dict(os.environ, env, clear=False):
                agent.set_socks_auth_enforcement(
                    "incus", "default", "proxy", ["microsocks"]
                )
                entries = agent._socks_auth_enforcement_entries()
                container = {
                    "name": "proxy",
                    "runtime": "incus",
                    "project": "default",
                    "security": {
                        "socks_proxy": {
                            "detected": True,
                            "auth_mode": "no_auth",
                            "process_matches": [{"pid": 42, "process": "microsocks"}],
                        }
                    },
                }
                with mock.patch.object(
                    agent,
                    "stop_unauthenticated_socks",
                    return_value=(True, "killed_processes=1"),
                ) as stop_mock:
                    result = agent.enforce_socks_auth_policy(container, entries)
                self.assertTrue(result["succeeded"])
                stop_mock.assert_called_once()

                container["security"]["socks_proxy"]["auth_mode"] = "weak_password"
                released = agent.enforce_socks_auth_policy(container)
                self.assertTrue(released["released"])
                self.assertEqual(agent._socks_auth_enforcement_entries(), [])

    def test_socks_enforcement_action_persists_policy_without_deleting_config(self):
        action = {
            "action_type": "enforce_socks_auth",
            "runtime": "incus",
            "project": "default",
            "container_name": "proxy",
            "params": {
                "auth_mode": "no_auth",
                "process_names": ["microsocks"],
                "process_pids": [42],
                "config_files": ["/etc/should-not-be-deleted"],
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "SECURITY_SOCKS_AUTH_ENFORCEMENT_FILE": str(Path(tmp) / "policy.json")
            }
            with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
                agent,
                "stop_unauthenticated_socks",
                return_value=(True, "stopped_services=1 killed_processes=1 stop_errors=0"),
            ) as stop_mock:
                ok, message = agent.execute_security_action(action)
                stored = agent._socks_auth_enforcement_entries()
        self.assertTrue(ok)
        self.assertIn("policy_installed=1", message)
        self.assertEqual(stored[0]["process_names"], ["microsocks"])
        self.assertNotIn("config_files", stored[0])
        stop_mock.assert_called_once_with(action)

    def test_socks_stop_rejects_nonempty_auth_and_docker(self):
        base = {
            "container_name": "proxy",
            "params": {"auth_mode": "weak_password", "process_names": ["microsocks"]},
        }
        self.assertFalse(agent.stop_unauthenticated_socks(dict(base, runtime="incus"))[0])
        base["params"]["auth_mode"] = "no_auth"
        self.assertFalse(agent.stop_unauthenticated_socks(dict(base, runtime="docker"))[0])

    def test_allow_socks_action_removes_persistent_enforcement(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "SECURITY_SOCKS_AUTH_ENFORCEMENT_FILE": str(Path(tmp) / "policy.json")
            }
            with mock.patch.dict(os.environ, env, clear=False):
                agent.set_socks_auth_enforcement(
                    "incus", "default", "proxy", ["microsocks"]
                )
                ok, message = agent.execute_security_action(
                    {
                        "action_type": "release_socks_auth",
                        "runtime": "incus",
                        "project": "default",
                        "container_name": "proxy",
                    }
                )
                remaining = agent._socks_auth_enforcement_entries()
        self.assertTrue(ok)
        self.assertIn("policy_removed=1", message)
        self.assertEqual(remaining, [])

    def test_parses_caddy_and_nginx_access_logs(self):
        caddy = agent._parse_access_log_line(
            json.dumps(
                {
                    "request": {"client_ip": "203.0.113.5", "method": "GET", "uri": "/login"},
                    "status": 429,
                }
            )
        )
        nginx = agent._parse_access_log_line(
            '198.51.100.2 - - [25/Aug/2026:10:00:00 +0800] "POST /api/login HTTP/1.1" 403 12 "-" "curl"'
        )
        self.assertEqual(caddy, {"ip": "203.0.113.5", "status": 429, "method": "GET", "uri": "/login"})
        self.assertEqual(nginx["ip"], "198.51.100.2")
        self.assertEqual(nginx["status"], 403)

    def test_access_log_reader_only_counts_new_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log"
            path.write_text(
                '198.51.100.2 - - [x] "GET / HTTP/1.1" 200 1 "-" "x"\n',
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"SECURITY_ACCESS_LOG_PATHS": str(path)}, clear=False):
                first = agent._collect_access_log_stats(10)
                with path.open("a", encoding="utf-8") as handle:
                    handle.write('198.51.100.2 - - [x] "GET /x HTTP/1.1" 404 1 "-" "x"\n')
                second = agent._collect_access_log_stats(10)
            self.assertEqual(first["requests"], 0)
            self.assertEqual(second["requests"], 1)
            self.assertEqual(second["status_4xx"], 1)

    def test_access_log_reader_distinguishes_missing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "missing-access.log")
            with mock.patch.dict(
                os.environ, {"SECURITY_ACCESS_LOG_PATHS": missing}, clear=False
            ):
                result = agent._collect_access_log_stats(10)
            self.assertEqual(result["configured_files"], 1)
            self.assertEqual(result["missing_files"], 1)
            self.assertEqual(result["unreadable_files"], 0)

    def test_host_telemetry_reports_container_log_source(self):
        host_access = {
            "enabled": True,
            "configured_files": 2,
            "readable_files": 0,
            "missing_files": 2,
            "unreadable_files": 0,
        }
        container = {
            "name": "panel",
            "runtime": "incus",
            "security": {
                "access_log": {"enabled": True, "readable_files": 1},
                "panel_pairing": {},
            },
        }
        with mock.patch.object(agent, "_collect_access_log_stats", return_value=host_access):
            result = agent.collect_security_summary([container], 60)
        self.assertEqual(result["access_log"]["source"], "container")
        self.assertEqual(result["access_log"]["container_readable_files"], 1)

    def test_container_access_log_reader_scans_logs_inside_runtime(self):
        state = {"size": 100}

        def fake_run(cmd):
            shell = cmd[-1]
            if "wc -c" in shell:
                return str(state["size"])
            if "tail -c" in shell:
                return '203.0.113.9 - - [x] "GET /.env HTTP/1.1" 403 1 "-" "x"\n'
            return ""

        container = {"name": "xboard", "runtime": "docker", "runtime_bin": "docker", "project": ""}
        env = {"SECURITY_CONTAINER_ACCESS_LOG_PATHS": "/var/log/nginx/access.log"}
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(agent, "run", side_effect=fake_run):
            first = agent._collect_container_access_log_stats(container, 10)
            state["size"] = 200
            second = agent._collect_container_access_log_stats(container, 10)
        self.assertEqual(first["requests"], 0)
        self.assertEqual(second["requests"], 1)
        self.assertEqual(second["suspicious_requests"], 1)

    def test_security_summary_emits_all_detector_categories(self):
        container = {
            "name": "panel",
            "runtime": "podman",
            "project": "",
            "net_rx_bps": 200,
            "net_tx_bps": 200,
            "security": {
                "net_rx_pps": 200,
                "net_tx_pps": 200,
                "syn_recv_count": 20,
                "inbound_unique_ips": 11,
                "communication_processes": [
                    {
                        "process": "nginx",
                        "pid": 42,
                        "inbound_connections": 11,
                        "outbound_connections": 0,
                    }
                ],
                "scan_unique_ports_max": 8,
                "scan_source_ip": "203.0.113.10",
                "outbound_unique_ips": 20,
                "suspicious_outbound_connections": 5,
                "protocol_rates": {
                    "Tcp_ActiveOpens_per_second": 20,
                    "Tcp_AttemptFails_per_second": 10,
                    "Udp_OutDatagrams_per_second": 200,
                },
                "configuration_risks": [
                    {"code": "oci_privileged", "severity": "critical", "message": "privileged"}
                ],
                "process_count": 20,
                "panel_pairing": {
                    "detected": True,
                    "process_patterns": ["xboard-node"],
                    "config_files": ["/etc/xboard-node/config.yml"],
                    "panel_domains": ["panel.example.net"],
                    "unapproved_domains": ["panel.example.net"],
                },
            },
        }
        env = {
            "SECURITY_MONITOR_ENABLED": "true",
            "SECURITY_ACCESS_LOG_PATHS": "",
            "ALERT_DDOS_RX_BPS": "100",
            "ALERT_DDOS_RX_PPS": "100",
            "ALERT_DDOS_SYN_RECV": "10",
            "ALERT_INBOUND_UNIQUE_IPS": "10",
            "ALERT_SCAN_UNIQUE_PORTS": "5",
            "ALERT_ABUSE_OUTBOUND_UNIQUE_IPS": "10",
            "ALERT_ABUSE_SUSPICIOUS_CONNECTIONS": "3",
            "ALERT_ABUSE_TX_BPS": "100",
            "ALERT_ABUSE_TX_PPS": "100",
            "ALERT_ABUSE_TCP_OPENS_PER_SEC": "10",
            "ALERT_ABUSE_TCP_FAILS_PER_SEC": "5",
            "ALERT_ABUSE_UDP_OUT_PER_SEC": "100",
            "ALERT_ABUSE_PROCESS_COUNT": "10",
            "SECURITY_CONFIG_AUDIT_ENABLED": "true",
            "SECURITY_PANEL_PAIRING_DETECTION_ENABLED": "true",
            "SECURITY_ALLOWED_PANEL_DOMAINS": "trusted.example.com",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = agent.collect_security_summary([container], 60)
        types = {item["type"] for item in result["alerts"]}
        self.assertTrue(
            {
                "ddos_bandwidth",
                "ddos_packets",
                "ddos_syn",
                "inbound_ip_fanout",
                "port_scan",
                "outbound_fanout",
                "outbound_sensitive_ports",
                "outbound_bandwidth_abuse",
                "outbound_packet_abuse",
                "outbound_connection_churn",
                "outbound_connection_failures",
                "udp_outbound_flood",
                "container_security_risk",
                "process_fanout_abuse",
                "unauthorized_panel_pairing",
            }.issubset(types)
        )

    def test_connection_count_alert_uses_warning_and_critical_thresholds(self):
        container = {"name": "node1", "runtime": "podman", "conn_count": 501, "security": {}}
        env = {
            "SECURITY_MONITOR_ENABLED": "true",
            "SECURITY_ACCESS_LOG_PATHS": "",
            "ALERT_CONN_WARNING_THRESHOLD": "500",
            "ALERT_CONN_CRITICAL_THRESHOLD": "1000",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            container["conn_count"] = 500
            normal = agent.collect_security_summary([container], 60)
            container["conn_count"] = 1000
            upper_warning = agent.collect_security_summary([container], 60)
            container["conn_count"] = 501
            warning = agent.collect_security_summary([container], 60)
            container["conn_count"] = 1001
            critical = agent.collect_security_summary([container], 60)
        self.assertFalse(any(x["type"] == "container_connection_count" for x in normal["alerts"]))
        upper_warning_alert = next(
            x for x in upper_warning["alerts"] if x["type"] == "container_connection_count"
        )
        warning_alert = next(x for x in warning["alerts"] if x["type"] == "container_connection_count")
        critical_alert = next(x for x in critical["alerts"] if x["type"] == "container_connection_count")
        self.assertEqual(upper_warning_alert["severity"], "warning")
        self.assertEqual(warning_alert["severity"], "warning")
        self.assertEqual(critical_alert["severity"], "critical")

    def test_signed_automatic_stop_targets_only_the_named_container(self):
        action = {
            "action_type": "stop_container",
            "runtime": "incus",
            "project": "default",
            "container_name": "node1",
            "params": {
                "reason": "sustained_connection_overload",
                "connection_count": 1600,
                "duration_seconds": 900,
            },
        }
        with mock.patch.object(
            agent, "get_runtime_bins", return_value={"incus": "incus"}
        ), mock.patch.object(
            agent, "_run_action_command", return_value=(True, "stopped")
        ) as runner:
            ok, message = agent.execute_security_action(action)
        self.assertTrue(ok)
        self.assertEqual(message, "stopped")
        self.assertEqual(runner.call_args.args[0], ["incus", "--project", "default", "stop", "node1"])

    def test_security_summary_detects_http_cc_signals(self):
        access_stats = {
            "enabled": True,
            "readable_files": 1,
            "requests": 200,
            "requests_per_second": 20.0,
            "unique_ips": 2,
            "top_ip": "203.0.113.8",
            "top_ip_requests": 150,
            "top_ip_requests_per_second": 15.0,
            "status_4xx": 150,
            "status_5xx": 0,
            "top_ip_4xx": "203.0.113.8",
            "top_ip_4xx_requests": 30,
            "suspicious_requests": 12,
            "suspicious_unique_paths": 3,
            "top_scanner_ip": "203.0.113.8",
            "parse_errors": 0,
        }
        env = {
            "SECURITY_MONITOR_ENABLED": "true",
            "ALERT_CC_TOTAL_RPS": "10",
            "ALERT_CC_IP_RPS": "10",
            "ALERT_CC_4XX_RATE": "0.5",
            "ALERT_CC_MIN_REQUESTS": "50",
            "ALERT_WEB_SCAN_REQUESTS": "10",
            "ALERT_AUTH_FAILURES_PER_IP": "20",
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
            agent, "_collect_access_log_stats", return_value=access_stats
        ):
            result = agent.collect_security_summary([], 10)
        self.assertEqual(
            {item["type"] for item in result["alerts"]},
            {"cc_total_rps", "cc_single_ip", "cc_4xx_ratio", "web_scan", "http_abuse"},
        )

    def test_inbound_ip_alert_requires_more_than_ten_unique_ips(self):
        container = {
            "name": "web",
            "runtime": "incus",
            "security": {"inbound_unique_ips": 10, "panel_pairing": {}},
        }
        with mock.patch.dict(
            os.environ,
            {"ALERT_INBOUND_UNIQUE_IPS": "10", "SECURITY_ACCESS_LOG_PATHS": ""},
            clear=False,
        ):
            result = agent.collect_security_summary([container], 60)
        self.assertNotIn("inbound_ip_fanout", {item["type"] for item in result["alerts"]})

    def test_container_access_log_alert_keeps_container_identity(self):
        container = {
            "name": "xboard",
            "runtime": "docker",
            "project": "",
            "security": {
                "access_log": {
                    "requests": 20,
                    "requests_per_second": 20,
                    "top_ip_requests_per_second": 0,
                    "status_4xx": 0,
                }
            },
        }
        with mock.patch.dict(
            os.environ,
            {"SECURITY_ACCESS_LOG_PATHS": "", "ALERT_CC_TOTAL_RPS": "10"},
            clear=False,
        ):
            result = agent.collect_security_summary([container], 10)
        alert = next(item for item in result["alerts"] if item["type"] == "cc_total_rps")
        self.assertEqual(alert["container_name"], "xboard")
        self.assertEqual(alert["runtime"], "docker")

    def test_suspicious_process_is_reported_for_monitored_container(self):
        process_output = "PID %CPU COMMAND COMMAND\n42 88.0 xmrig /tmp/xmrig --donate-level 1\n"
        with mock.patch.dict(
            os.environ,
            {"SECURITY_SUSPICIOUS_PROCESS_PATTERNS": "xmrig", "SECURITY_ACCESS_LOG_PATHS": ""},
            clear=False,
        ), mock.patch.object(agent, "run", return_value=process_output):
            processes = agent.collect_suspicious_processes("panel", "podman")
        container = {
            "name": "panel",
            "runtime": "podman",
            "project": "",
            "security": {"suspicious_processes": processes},
        }
        with mock.patch.dict(
            os.environ,
            {"SECURITY_ACCESS_LOG_PATHS": "", "SECURITY_AUTO_REMEDIATE_XMRIG": "true"},
            clear=False,
        ), mock.patch.object(
            agent,
            "remediate_malicious_process",
            return_value=(True, "killed_processes=1 removed_services=0 removed_configs=0"),
        ) as remediate:
            result = agent.collect_security_summary([container], 60)
        alert = next(item for item in result["alerts"] if item["type"] == "malicious_process")
        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(alert["container_name"], "panel")
        self.assertEqual(alert["malicious_processes"][0]["process"], "xmrig")
        self.assertTrue(alert["automatic_remediation"]["succeeded"])
        remediate.assert_called_once()

    def test_docker_xmrig_is_notice_only_and_never_auto_remediated(self):
        container = {
            "name": "customer-helper",
            "runtime": "docker",
            "project": "",
            "security": {
                "suspicious_processes": [
                    {"pid": 42, "process": "xmrig", "pattern": "xmrig"}
                ]
            },
        }
        with mock.patch.dict(
            os.environ,
            {"SECURITY_ACCESS_LOG_PATHS": "", "SECURITY_AUTO_REMEDIATE_XMRIG": "true"},
            clear=False,
        ), mock.patch.object(agent, "remediate_malicious_process") as remediate:
            result = agent.collect_security_summary([container], 60)
        alert = next(item for item in result["alerts"] if item["type"] == "malicious_process")
        self.assertEqual(alert["runtime"], "docker")
        self.assertEqual(alert["automatic_remediation"], {})
        remediate.assert_not_called()

    def test_unapproved_xrayr_is_auto_remediated_but_approved_xrayr_is_not(self):
        base = {
            "name": "node",
            "runtime": "incus",
            "project": "default",
            "security": {
                "panel_pairing": {
                    "detected": True,
                    "approved": False,
                    "panel_domains": ["panel.example.net"],
                    "unapproved_domains": ["panel.example.net"],
                    "process_patterns": ["xrayr"],
                    "process_matches": [{"pid": 77, "pattern": "xrayr"}],
                    "config_files": ["/etc/XrayR/config.yml"],
                }
            },
        }
        with mock.patch.dict(
            os.environ,
            {"SECURITY_ACCESS_LOG_PATHS": "", "SECURITY_AUTO_REMEDIATE_XRAYR": "true"},
            clear=False,
        ), mock.patch.object(
            agent,
            "remediate_panel_pairing",
            return_value=(True, "killed_processes=1 removed_services=1 removed_configs=1"),
        ) as remediate:
            result = agent.collect_security_summary([base], 60)
            approved = json.loads(json.dumps(base))
            approved["security"]["panel_pairing"]["approved"] = True
            approved["security"]["panel_pairing"]["unapproved_domains"] = []
            agent.collect_security_summary([approved], 60)
        alert = next(
            item for item in result["alerts"]
            if item["type"] == "unauthorized_panel_pairing"
        )
        self.assertTrue(alert["automatic_remediation"]["succeeded"])
        self.assertEqual(remediate.call_count, 1)
if __name__ == "__main__":
    unittest.main()
