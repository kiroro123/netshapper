import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from netshaper.core.orchestrator import NetShaper
from netshaper.core.state_manager import NetworkStateSnapshot, StateSnapshotManager


class StateSnapshotTests(unittest.TestCase):
    def test_save_state_writes_manifest_for_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            ns = NetShaper.__new__(NetShaper)
            ns.interface = "eth0"
            ns.gw = "192.0.2.1"
            ns.own_ip = "192.0.2.10"
            ns.session_id = "NS-TEST"
            ns._global_rules_applied = False
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
                    limit=None,
                    firewall=None,
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
            self.assertEqual(data["snapshot"]["route_localnet"], 0)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
