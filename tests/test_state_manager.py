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
            ns.sessions = {
                "192.0.2.20": SimpleNamespace(
                    target=SimpleNamespace(ip="192.0.2.20"),
                    dns_on=False,
                    limit=None,
                )
            }

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp):
                ns.save_state()

            state_path = os.path.join(tmp, ns.session_id, "state.json")
            self.assertTrue(os.path.exists(state_path))
            with open(state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["session_id"], "NS-TEST")
            self.assertEqual(data["interface"], "eth0")

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
        run_mock.assert_any_call(
            ["iptables-save"], capture_output=True, text=True, check=False)
        run_mock.assert_any_call(
            ["ip6tables-save"], capture_output=True, text=True, check=False)

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
        self.assertFalse(
            any(call.args[0][:3] == ["tc", "qdisc", "del"]
                for call in run_mock.call_args_list)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
