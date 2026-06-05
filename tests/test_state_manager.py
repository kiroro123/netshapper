import unittest
from types import SimpleNamespace
from unittest import mock

from netshaper.core.state_manager import NetworkStateSnapshot, StateSnapshotManager


class StateSnapshotTests(unittest.TestCase):
    @mock.patch("netshaper.core.state_manager.subprocess.run")
    def test_capture_records_original_forwarding_values(self, run_mock):
        run_mock.side_effect = [
            SimpleNamespace(returncode=0, stdout="1\n"),
            SimpleNamespace(returncode=0, stdout="0\n"),
            SimpleNamespace(returncode=0, stdout="-S\n"),
            SimpleNamespace(returncode=0, stdout="-S\n"),
            SimpleNamespace(returncode=0, stdout="qdisc ok\n"),
        ]

        snapshot = StateSnapshotManager.capture("wlp0s20f3", "NS-TEST")

        self.assertEqual(snapshot.session_id, "NS-TEST")
        self.assertEqual(snapshot.interface, "wlp0s20f3")
        self.assertEqual(snapshot.ipv4_forwarding, 1)
        self.assertEqual(snapshot.ipv6_forwarding, 0)

    @mock.patch("netshaper.core.state_manager.subprocess.run")
    def test_restore_reapplies_saved_forwarding_and_rules(self, run_mock):
        snapshot = NetworkStateSnapshot(
            session_id="NS-TEST",
            interface="wlp0s20f3",
            ipv4_forwarding=1,
            ipv6_forwarding=0,
            iptables_rules="*filter\n-A FORWARD -j ACCEPT\nCOMMIT\n",
            ip6tables_rules="*filter\n-A FORWARD -j ACCEPT\nCOMMIT\n",
            tc_configuration="qdisc noqueue 0: dev wlp0s20f3 root",
        )

        StateSnapshotManager.restore(snapshot)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
