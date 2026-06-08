import tempfile
import threading
import unittest
from unittest import mock

from netshaper.core.orchestrator import NetShaper


class NetShaperCleanupTests(unittest.TestCase):
    def test_cleanup_runs_all_steps_once_even_when_steps_fail(self):
        ns = NetShaper.__new__(NetShaper)
        ns._lifecycle_lock = threading.RLock()
        ns._cleanup_running = False
        ns._cleanup_complete = False
        ns.is_shutting_down = False
        ns.stop_event = threading.Event()
        ns.sessions = {}
        ns.sniffer = mock.Mock()
        ns.sniffer.stop.side_effect = RuntimeError("sniffer stop failed")
        ns._mitm_proc = mock.Mock()
        ns._mitm_proc.terminate.side_effect = RuntimeError("mitm stop failed")
        ns._remove_global_rules = mock.Mock(side_effect=RuntimeError("rules failed"))
        ns.state_snapshot = mock.Mock()
        ns.shaper = mock.Mock()
        ns.shaper.cleanup.side_effect = RuntimeError("shaper failed")
        ns.session_id = "NS-TEST"

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
             mock.patch("netshaper.core.orchestrator.print_flush"), \
             mock.patch("netshaper.core.orchestrator.log"), \
             mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                        side_effect=RuntimeError("restore failed")) as restore_mock:
            ns.cleanup()
            ns.cleanup()

        ns.sniffer.stop.assert_called_once()
        ns._mitm_proc.terminate.assert_called_once()
        ns._remove_global_rules.assert_called_once()
        restore_mock.assert_called_once_with(ns.state_snapshot)
        ns.shaper.cleanup.assert_called_once()
        self.assertTrue(ns._cleanup_complete)


if __name__ == "__main__":
    unittest.main(verbosity=2)
