import json
import unittest
from unittest import mock

from client import agent


class HostFirewallInterfaceInventoryTests(unittest.TestCase):
    def setUp(self):
        agent._host_firewall_interface_inventory_cache.update({"ts": 0.0, "value": None})

    def tearDown(self):
        agent._host_firewall_interface_inventory_cache.update({"ts": 0.0, "value": None})

    def test_inventory_maps_only_confirmed_incus_and_podman_bridges(self):
        outputs = {
            ("ip", "-j", "address", "show"): json.dumps([
                {
                    "ifname": "eth0", "link_type": "ether", "operstate": "UP", "mtu": 1500,
                    "addr_info": [{"local": "198.51.100.9", "prefixlen": 24}],
                },
                {
                    "ifname": "incusbr0", "link_type": "ether", "operstate": "UP", "mtu": 1500,
                    "addr_info": [{"local": "10.90.0.1", "prefixlen": 24}],
                },
                {
                    "ifname": "podman1", "link_type": "ether", "operstate": "UP", "mtu": 1500,
                    "addr_info": [{"local": "10.88.0.1", "prefixlen": 16}],
                },
                {
                    "ifname": "incusbr0:1", "link_type": "ether", "operstate": "UP", "mtu": 1500,
                    "linkinfo": {"info_kind": "bridge"},
                    "addr_info": [],
                },
            ]),
            ("ip", "-j", "route", "show", "default"): json.dumps([{"dev": "eth0"}]),
            ("ip", "-j", "-6", "route", "show", "default"): "[]",
            ("incus", "network", "list", "--all-projects", "--format=json"): json.dumps([
                {"name": "incusbr0", "type": "bridge", "config": {}},
                {"name": "incusbr0:1", "type": "bridge", "config": {"bridge.name": "incusbr0:1"}},
                {"name": "ens3", "type": "physical", "config": {}},
            ]),
            ("podman", "network", "ls", "--format", "json"): json.dumps([
                {"name": "podman"}, {"name": "macvlan-net"},
            ]),
            ("podman", "network", "inspect", "podman", "macvlan-net"): json.dumps([
                {"name": "podman", "driver": "bridge", "network_interface": "podman1"},
                {"name": "macvlan-net", "driver": "macvlan", "network_interface": "eth0"},
            ]),
        }

        def fake_run(command, timeout=None):
            return outputs.get(tuple(command), "")

        with (
            mock.patch.object(agent.os, "name", "posix"),
            mock.patch.object(agent, "run", side_effect=fake_run),
            mock.patch.object(agent, "get_runtime_bins", return_value={"incus": "incus", "podman": "podman"}),
        ):
            result = agent._collect_host_firewall_interface_inventory(force=True)

        by_name = {item["name"]: item for item in result["interfaces"]}
        self.assertEqual(result["status"], "ready")
        self.assertTrue(by_name["eth0"]["is_default_route"])
        self.assertEqual(by_name["eth0"]["runtimes"], [])
        self.assertEqual(by_name["incusbr0"]["runtimes"], ["incus"])
        self.assertEqual(by_name["podman1"]["runtimes"], ["podman"])
        self.assertEqual(by_name["incusbr0"]["kind"], "bridge")
        self.assertEqual(by_name["podman1"]["kind"], "bridge")
        self.assertEqual(by_name["podman1"]["kernel_kind"], "ether")
        self.assertTrue(by_name["incusbr0"]["firewall_eligible"])
        self.assertTrue(by_name["podman1"]["firewall_eligible"])
        self.assertEqual(by_name["incusbr0:1"]["runtimes"], [])
        self.assertFalse(by_name["incusbr0:1"]["firewall_eligible"])
        self.assertEqual(by_name["podman1"]["addresses"], ["10.88.0.1/16"])

    def test_incus_network_interface_from_project_scoped_json_is_mapped(self):
        outputs = {
            ("ip", "-j", "address", "show"): json.dumps([
                {"ifname": "incusbr7", "link_type": "ether", "operstate": "UP", "mtu": 1500, "addr_info": []},
            ]),
            ("ip", "-j", "route", "show", "default"): "[]",
            ("ip", "-j", "-6", "route", "show", "default"): "[]",
            ("incus", "network", "list", "--all-projects", "--format=json"): json.dumps([
                {"Name": "private-net", "Type": "bridge", "NetworkInterface": "incusbr7", "Config": {"user.project": "isolated"}},
            ]),
        }

        def fake_run(command, timeout=None):
            return outputs.get(tuple(command), "")

        with (
            mock.patch.object(agent.os, "name", "posix"),
            mock.patch.object(agent, "run", side_effect=fake_run),
            mock.patch.object(agent, "get_runtime_bins", return_value={"incus": "incus"}),
        ):
            result = agent._collect_host_firewall_interface_inventory(force=True)

        item = result["interfaces"][0]
        self.assertEqual(item["name"], "incusbr7")
        self.assertEqual(item["runtimes"], ["incus"])
        self.assertEqual(item["network_names"], ["private-net"])
        self.assertTrue(item["firewall_eligible"])

    def test_invalid_ip_json_marks_inventory_unavailable(self):
        with (
            mock.patch.object(agent.os, "name", "posix"),
            mock.patch.object(agent, "run", return_value="ip: unsupported option"),
        ):
            result = agent._collect_host_firewall_interface_inventory(force=True)

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["interfaces"], [])

    def test_rfw_readback_and_events_continue_when_security_scans_are_disabled(self):
        readback = {"status": "ready", "observed_at": 100, "snapshot": {"rule_count": 1}}
        events = {"events_api": "ready", "next_cursor": "instance:2", "events": []}
        with (
            mock.patch.dict(agent.os.environ, {"SECURITY_MONITOR_ENABLED": "false"}),
            mock.patch.object(agent, "_firewall_event_cursor", "instance:1"),
            mock.patch.object(agent, "_pending_firewall_event_cursor", "unchanged"),
            mock.patch.object(agent, "_runman_firewall_control_status", return_value={"control_api": "ready", "observed_at": 100}),
            mock.patch.object(agent, "_collect_host_firewall_interface_inventory", return_value={"status": "ready", "interfaces": []}),
            mock.patch.object(agent, "_runman_firewall_readback", return_value=readback) as get_readback,
            mock.patch.object(agent, "_runman_firewall_events", return_value=events) as get_events,
        ):
            summary = agent.collect_security_summary([], 10)

        self.assertFalse(summary["enabled"])
        self.assertEqual(summary["host_firewall"]["readback"], readback)
        self.assertEqual(summary["host_firewall"]["events_api"], "ready")
        self.assertEqual(summary["host_firewall"]["next_cursor"], "instance:2")
        get_readback.assert_called_once_with()
        get_events.assert_called_once_with("instance:1")


if __name__ == "__main__":
    unittest.main()
