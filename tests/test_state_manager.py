import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from netshaper.core.orchestrator import NetShaper
from netshaper.core.state_manager import NetworkStateSnapshot, StateSnapshotManager
from netshaper.network.shaper import ShapingProfile


class StateSnapshotTests(unittest.TestCase):
    def test_save_state_writes_manifest_for_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            ns = NetShaper.__new__(NetShaper)
            ns.interface = "eth0"
            ns.gw = "192.0.2.1"
            ns.own_ip = "192.0.2.10"
            ns.session_id = "NS-TEST"
            ns._global_rules_applied = False
            ns._global_rules_created = []
            ns.state_snapshot = NetworkStateSnapshot(
                session_id="NS-TEST",
                interface="eth0",
                ipv4_forwarding=0,
                ipv6_forwarding=0,
                route_localnet=0,
                iptables_rules="",
                ip6tables_rules="",
                tc_configuration="",
            )
            ns.sessions = {
                "192.0.2.20": SimpleNamespace(
                    target=SimpleNamespace(ip="192.0.2.20"),
                    dns_on=False,
                    limit=5.0,
                    shaping_profile=ShapingProfile(
                        bandwidth_mbps=5.0,
                        latency_ms=100,
                        loss_percent=1.0,
                    ),
                    firewall=SimpleNamespace(
                        _http_redirect_port=None,
                        _rule_comment="netshaper:NS-TEST:192.0.2.20",
                        _dns_input_rules=set(),
                        _dns_added=False,
                        MANGLE="NS-MNG-TEST",
                        NAT="NS-NAT-TEST",
                    ),
                )
            }

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp):
                result = ns.save_state()

            self.assertTrue(result)
            state_path = os.path.join(tmp, ns.session_id, "state.json")
            self.assertTrue(os.path.exists(state_path))
            with open(state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["session_id"], "NS-TEST")
            self.assertEqual(data["interface"], "eth0")
            self.assertFalse(data["global_rules_applied"])
            self.assertIsNone(data["global_rule_comment"])
            self.assertEqual(data["global_rules_created"], [])
            self.assertFalse(data["shaper_base_initialized"])
            self.assertFalse(data["shaper_root_qdisc_pending"])
            self.assertEqual(data["snapshot"]["route_localnet"], 0)
            self.assertEqual(
                data["targets"][0]["mangle_chain"], "NS-MNG-TEST")
            self.assertEqual(data["targets"][0]["nat_chain"], "NS-NAT-TEST")
            self.assertEqual(
                data["targets"][0]["firewall_rule_comment"],
                "netshaper:NS-TEST:192.0.2.20",
            )
            self.assertEqual(
                data["targets"][0]["shaping_profile"],
                {
                    "bandwidth_mbps": 5.0,
                    "latency_ms": 100,
                    "jitter_ms": 0,
                    "loss_percent": 1.0,
                    "corruption_percent": 0.0,
                    "duplicate_percent": 0.0,
                    "reorder_percent": 0.0,
                },
            )

    def test_save_state_records_global_rule_comment(self):
        with tempfile.TemporaryDirectory() as tmp:
            ns = NetShaper.__new__(NetShaper)
            ns.interface = "eth0"
            ns.gw = "192.0.2.1"
            ns.own_ip = "192.0.2.10"
            ns.session_id = "NS-TEST"
            ns._global_rules_applied = True
            ns._global_firewall_binaries_applied = ["iptables"]
            ns._global_rules_created = [{
                "binary": "iptables",
                "description": "iptables test rule",
                "delete": ["iptables", "-D", "FORWARD", "-j", "ACCEPT"],
                "check": ["iptables", "-C", "FORWARD", "-j", "ACCEPT"],
            }]
            ns.state_snapshot = NetworkStateSnapshot(
                session_id="NS-TEST",
                interface="eth0",
                ipv4_forwarding=0,
                ipv6_forwarding=0,
                route_localnet=0,
                iptables_rules="",
                ip6tables_rules="",
                tc_configuration="",
            )
            ns.sessions = {}

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp):
                result = ns.save_state()

            self.assertTrue(result)
            state_path = os.path.join(tmp, ns.session_id, "state.json")
            with open(state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertTrue(data["global_rules_applied"])
            self.assertEqual(
                data["global_rule_comment"],
                "netshaper:NS-TEST:global",
            )
            self.assertEqual(data["global_firewall_binaries"], ["iptables"])
            self.assertEqual(
                data["global_rules_created"],
                ns._global_rules_created,
            )

    def test_dry_run_save_state_stays_in_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            ns = NetShaper.__new__(NetShaper)
            ns.interface = "eth0"
            ns.gw = "192.0.2.1"
            ns.own_ip = "192.0.2.10"
            ns.session_id = "NS-TEST"
            ns._global_rules_applied = False
            ns._global_rules_created = []
            ns.state_snapshot = NetworkStateSnapshot(
                session_id="NS-TEST",
                interface="eth0",
                ipv4_forwarding=0,
                ipv6_forwarding=0,
                route_localnet=0,
                iptables_rules="",
                ip6tables_rules="",
                tc_configuration="",
            )
            ns.sessions = {}

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.config.DRY_RUN", True):
                result = ns.save_state()

            self.assertTrue(result)
            self.assertEqual(ns._dry_run_state["session_id"], "NS-TEST")
            self.assertFalse(os.path.exists(os.path.join(tmp, "NS-TEST")))

    @mock.patch("netshaper.core.state_manager.subprocess.run")
    def test_capture_records_original_forwarding_values(self, run_mock):
        run_mock.side_effect = [
            SimpleNamespace(returncode=0, stdout="1\n"),
            SimpleNamespace(returncode=0, stdout="0\n"),
            SimpleNamespace(returncode=0, stdout="0\n"),
            SimpleNamespace(returncode=0, stdout="*filter\nCOMMIT\n"),
            SimpleNamespace(returncode=0, stdout="*filter\nCOMMIT\n"),
            SimpleNamespace(returncode=0, stdout="qdisc ok\n"),
        ]

        snapshot = StateSnapshotManager.capture("wlp0s20f3", "NS-TEST")

        self.assertEqual(snapshot.session_id, "NS-TEST")
        self.assertEqual(snapshot.interface, "wlp0s20f3")
        self.assertEqual(snapshot.ipv4_forwarding, 1)
        self.assertEqual(snapshot.ipv6_forwarding, 0)
        self.assertEqual(snapshot.route_localnet, 0)
        run_mock.assert_any_call(
            ["iptables-save"], capture_output=True, text=True, check=False)
        run_mock.assert_any_call(
            ["ip6tables-save"], capture_output=True, text=True, check=False)

    @mock.patch("netshaper.core.state_manager.subprocess.run")
    def test_capture_keeps_failed_sysctl_reads_unknown(self, run_mock):
        run_mock.side_effect = [
            SimpleNamespace(returncode=1, stdout=""),
            SimpleNamespace(returncode=0, stdout="0\n"),
            SimpleNamespace(returncode=1, stdout=""),
            SimpleNamespace(returncode=0, stdout="*filter\nCOMMIT\n"),
            SimpleNamespace(returncode=0, stdout="*filter\nCOMMIT\n"),
            SimpleNamespace(returncode=0, stdout="qdisc ok\n"),
        ]

        snapshot = StateSnapshotManager.capture("wlp0s20f3", "NS-TEST")

        self.assertIsNone(snapshot.ipv4_forwarding)
        self.assertEqual(snapshot.ipv6_forwarding, 0)
        self.assertIsNone(snapshot.route_localnet)

    @mock.patch("netshaper.core.state_manager.subprocess.run")
    def test_restore_reapplies_saved_forwarding_and_rules(self, run_mock):
        run_mock.return_value = SimpleNamespace(returncode=0)
        snapshot = NetworkStateSnapshot(
            session_id="NS-TEST",
            interface="wlp0s20f3",
            ipv4_forwarding=1,
            ipv6_forwarding=0,
            route_localnet=0,
            iptables_rules="*filter\n-A FORWARD -j ACCEPT\nCOMMIT\n",
            ip6tables_rules="*filter\n-A FORWARD -j ACCEPT\nCOMMIT\n",
            tc_configuration="qdisc noqueue 0: dev wlp0s20f3 root",
        )

        result = StateSnapshotManager.restore(snapshot, restore_firewall=True)

        self.assertTrue(result)
        run_mock.assert_any_call(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            capture_output=True,
            text=True,
            check=False,
        )
        run_mock.assert_any_call(
            ["sysctl", "-w", "net.ipv6.conf.all.forwarding=0"],
            capture_output=True,
            text=True,
            check=False,
        )
        run_mock.assert_any_call(
            ["sysctl", "-w", "net.ipv4.conf.wlp0s20f3.route_localnet=0"],
            capture_output=True,
            text=True,
            check=False,
        )
        run_mock.assert_any_call(
            ["iptables-restore"],
            input="*filter\n-A FORWARD -j ACCEPT\nCOMMIT\n",
            text=True,
            check=False,
        )
        run_mock.assert_any_call(
            ["ip6tables-restore"],
            input="*filter\n-A FORWARD -j ACCEPT\nCOMMIT\n",
            text=True,
            check=False,
        )
        self.assertFalse(
            any(call.args[0][:3] == ["tc", "qdisc", "del"]
                for call in run_mock.call_args_list)
        )

    @mock.patch("netshaper.core.state_manager.subprocess.run")
    def test_restore_skips_firewall_snapshot_by_default(self, run_mock):
        run_mock.return_value = SimpleNamespace(returncode=0)
        snapshot = NetworkStateSnapshot(
            session_id="NS-TEST",
            interface="wlp0s20f3",
            ipv4_forwarding=None,
            ipv6_forwarding=None,
            route_localnet=None,
            iptables_rules="*filter\nCOMMIT\n",
            ip6tables_rules="*filter\nCOMMIT\n",
            tc_configuration="",
        )

        result = StateSnapshotManager.restore(snapshot)

        self.assertTrue(result)
        run_mock.assert_not_called()

    @mock.patch("netshaper.core.state_manager.subprocess.run")
    def test_restore_reports_firewall_restore_failure(self, run_mock):
        run_mock.return_value = SimpleNamespace(returncode=1)
        snapshot = NetworkStateSnapshot(
            session_id="NS-TEST",
            interface="wlp0s20f3",
            ipv4_forwarding=None,
            ipv6_forwarding=None,
            route_localnet=None,
            iptables_rules="*filter\nCOMMIT\n",
            ip6tables_rules="",
            tc_configuration="",
        )

        result = StateSnapshotManager.restore(snapshot, restore_firewall=True)

        self.assertFalse(result)

    @mock.patch("netshaper.core.state_manager.subprocess.run")
    def test_restore_from_state_file_uses_explicit_firewall_restore(self, run_mock):
        run_mock.return_value = SimpleNamespace(returncode=0)
        state = {
            "session_id": "NS-TEST",
            "interface": "eth0",
            "snapshot": {
                "session_id": "NS-TEST",
                "interface": "eth0",
                "ipv4_forwarding": None,
                "ipv6_forwarding": None,
                "route_localnet": None,
                "iptables_rules": "*filter\nCOMMIT\n",
                "ip6tables_rules": "",
                "tc_configuration": "qdisc htb 1: root",
            },
        }

        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as fh:
            json.dump(state, fh)
            fh.flush()

            result = StateSnapshotManager.restore_from_state_file(
                fh.name,
                restore_firewall=True,
            )

        self.assertTrue(result)
        run_mock.assert_called_once_with(
            ["iptables-restore"],
            input="*filter\nCOMMIT\n",
            text=True,
            check=False,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
