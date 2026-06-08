import unittest
from types import SimpleNamespace
from unittest import mock

from netshaper.core.session import TargetSession


class TargetSessionCleanupTests(unittest.TestCase):
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
        self.assertIsNone(session.arp_spoof)
        self.assertIsNone(session.ndp_spoof)
        self.assertIsNone(session.firewall)
        self.assertFalse(session.throttle_on)
        self.assertIsNone(session._mark_id)
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
