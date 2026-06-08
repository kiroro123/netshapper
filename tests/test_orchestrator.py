import tempfile
import threading
import unittest
from unittest import mock

from netshaper.core.orchestrator import NetShaper
from netshaper.models import Device


class NetShaperCleanupTests(unittest.TestCase):
    def test_add_target_rejects_duplicate_target(self):
        ns = NetShaper.__new__(NetShaper)
        ns._lifecycle_lock = threading.RLock()
        ns.sessions = {"192.0.2.10": mock.Mock()}

        with self.assertRaisesRegex(ValueError, "already active"):
            ns.add_target(Device(ip="192.0.2.10", mac="00:11:22:33:44:55"))

    def test_cleanup_keeps_session_incomplete_when_steps_fail(self):
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

        ns.sniffer.stop.assert_called_once()
        ns._mitm_proc.terminate.assert_called_once()
        ns._remove_global_rules.assert_called_once()
        restore_mock.assert_called_once_with(ns.state_snapshot)
        ns.shaper.cleanup.assert_called_once()
        self.assertFalse(ns._cleanup_complete)

    def test_add_target_rolls_back_partially_created_session(self):
        ns = NetShaper.__new__(NetShaper)
        ns._lifecycle_lock = threading.RLock()
        ns.sessions = {}
        ns.mark_pool = mock.Mock()
        ns.mark_pool.acquire.return_value = 10
        ns.interface = "eth0"
        ns.own_mac = "aa:bb:cc:dd:ee:ff"
        ns.own_ip = "192.0.2.1"
        ns.own_ipv6 = None
        ns.gw = "192.0.2.254"
        ns.gw_mac = "ff:ee:dd:cc:bb:aa"
        ns.gw_ipv6 = None
        ns.shaper = mock.Mock()
        target = Device(ip="192.0.2.10", mac="00:11:22:33:44:55")

        with mock.patch("netshaper.core.orchestrator.TargetSession") as session_cls:
            session = session_cls.return_value
            session.setup.side_effect = RuntimeError("setup failed")

            with self.assertRaises(RuntimeError):
                ns.add_target(target)

        self.assertEqual(ns.sessions, {})
        session.cleanup.assert_called_once()
        ns.mark_pool.release.assert_called_once_with("192.0.2.10")

    def test_dry_run_launch_sniffer_does_not_start_capture(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.sniffer = None

        with mock.patch("netshaper.core.orchestrator.config.DRY_RUN", True), \
             mock.patch("netshaper.core.orchestrator.PacketSniffer") as sniffer_cls, \
             mock.patch("netshaper.core.orchestrator.print_flush"):
            ns.launch_sniffer(["192.0.2.10"])

        sniffer_cls.assert_not_called()
        self.assertIsNone(ns.sniffer)

    def test_dry_run_launch_mitmproxy_does_not_start_process(self):
        ns = NetShaper.__new__(NetShaper)
        ns.own_ip = "192.0.2.1"

        with mock.patch("netshaper.core.orchestrator.config.DRY_RUN", True), \
             mock.patch("netshaper.core.orchestrator.subprocess.Popen") as popen_mock, \
             mock.patch("netshaper.core.orchestrator.print_flush"):
            result = ns.launch_mitmproxy()

        self.assertTrue(result)
        popen_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
