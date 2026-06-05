import unittest
from unittest import mock

from netshaper.network.backends import DryRunPacketBackend, RealPacketBackend


class PacketBackendTests(unittest.TestCase):
    @mock.patch("netshaper.network.backends.sendp")
    def test_real_backend_sends_packet(self, sendp_mock):
        backend = RealPacketBackend()
        packet = object()

        backend.send(packet, "wlp0s20f3")

        sendp_mock.assert_called_once_with(packet, iface="wlp0s20f3", verbose=False)

    def test_dry_run_backend_does_not_send_packet(self):
        backend = DryRunPacketBackend()
        with mock.patch("netshaper.network.backends.log") as log_mock:
            backend.send(object(), "wlp0s20f3")
        self.assertTrue(log_mock.info.called)


if __name__ == "__main__":
    unittest.main(verbosity=2)
