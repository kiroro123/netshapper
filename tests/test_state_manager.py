import unittest
from types import SimpleNamespace
from unittest import mock

from netshaper.core.state_manager import StateSnapshotManager


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
