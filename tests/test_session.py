import unittest
from types import SimpleNamespace
from unittest import mock

from netshaper.core.session import TargetSession


class TargetSessionCleanupTests(unittest.TestCase):
    def test_dry_run_start_spoof_does_not_construct_spoofers(self):
        session = TargetSession.__new__(TargetSession)
        session.target = SimpleNamespace(ip="192.0.2.10")

        with mock.patch("netshaper.core.session.config.DRY_RUN", True), \
             mock.patch("netshaper.core.session.ARPSpoofer") as arp_cls, \
             mock.patch("netshaper.core.session.NDPSpoofer") as ndp_cls:
            session.start_spoof(arp_on=True)

        arp_cls.assert_not_called()
        ndp_cls.assert_not_called()

    def test_cleanup_continues_after_spoofer_failure(self):
        session = TargetSession.__new__(TargetSession)
        session.target = SimpleNamespace(ip="192.0.2.10")
        session.active = True
        session.is_shutting_down = False
        arp_spoof = mock.Mock()
        arp_spoof.shutdown.side_effect = RuntimeError("arp failed")
        ndp_spoof = mock.Mock()
        firewall = mock.Mock()
        session.arp_spoof = arp_spoof
        session.ndp_spoof = ndp_spoof
        session.firewall = firewall
        session.throttle_on = True
        session._mark_id = 10
        session.limit = 5.0
        session.shaper = mock.Mock()

        with mock.patch("netshaper.core.session.log"):
            result = session.cleanup()

        arp_spoof.shutdown.assert_called_once()
        ndp_spoof.shutdown.assert_called_once()
        firewall.cleanup.assert_called_once()
        session.shaper.cleanup_target.assert_called_once_with(10)
        self.assertFalse(session.active)
        self.assertTrue(session.is_shutting_down)
        self.assertIs(session.arp_spoof, arp_spoof)
        self.assertIsNone(session.ndp_spoof)
        self.assertIsNone(session.firewall)
        self.assertFalse(session.throttle_on)
        self.assertIsNone(session._mark_id)
        self.assertFalse(result)

    def test_failed_firewall_cleanup_is_retried(self):
        session = TargetSession.__new__(TargetSession)
        session.target = SimpleNamespace(ip="192.0.2.10")
        session.active = True
        session.is_shutting_down = False
        session.arp_spoof = None
        session.ndp_spoof = None
        firewall = mock.Mock()
        firewall.cleanup.side_effect = [False, True]
        session.firewall = firewall
        session.throttle_on = False
        session._mark_id = None
        session.limit = None
        session.shaper = mock.Mock()

        with mock.patch("netshaper.core.session.log"):
            first = session.cleanup()
            second = session.cleanup()

        self.assertFalse(first)
        self.assertTrue(second)
        self.assertIsNone(session.firewall)
        self.assertEqual(firewall.cleanup.call_count, 2)

    def test_failed_shaper_cleanup_preserves_mark_for_retry(self):
        session = TargetSession.__new__(TargetSession)
        session.target = SimpleNamespace(ip="192.0.2.10")
        session.active = True
        session.is_shutting_down = False
        session.arp_spoof = None
        session.ndp_spoof = None
        session.firewall = None
        session.throttle_on = True
        session._mark_id = 10
        session.limit = 5.0
        session.shaper = mock.Mock()
        session.shaper.cleanup_target.side_effect = [False, True]

        with mock.patch("netshaper.core.session.log"):
            first = session.cleanup()
            second = session.cleanup()

        self.assertFalse(first)
        self.assertTrue(second)
        self.assertFalse(session.throttle_on)
        self.assertIsNone(session._mark_id)
        self.assertIsNone(session.limit)
        self.assertEqual(session.shaper.cleanup_target.call_count, 2)

    def test_failed_firewall_setup_remains_attached_for_recovery(self):
        session = TargetSession.__new__(TargetSession)
        session.target = SimpleNamespace(ip="192.0.2.10")
        session.interface = "eth0"
        session.session_id = "NS-TEST"
        session.firewall = None
        session.shaper = mock.Mock()

        with mock.patch("netshaper.core.session.FirewallManager") as fw_cls:
            firewall = fw_cls.return_value
            firewall.setup.side_effect = RuntimeError("setup failed")

            with self.assertRaisesRegex(RuntimeError, "setup failed"):
                session.setup()

        fw_cls.assert_called_once_with(
            "192.0.2.10",
            "eth0",
            session_id="NS-TEST",
            auto_setup=False,
        )
        self.assertIs(session.firewall, firewall)


if __name__ == "__main__":
    unittest.main(verbosity=2)
