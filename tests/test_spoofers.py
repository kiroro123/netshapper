import threading
import unittest
from types import SimpleNamespace
from unittest import mock


class _FakeLayer:
    """Minimal Scapy-layer stand-in that supports the / composition operator."""
    def __init__(self, **kw):
        self._kw = kw
    def __truediv__(self, other): return self
    def __rtruediv__(self, other): return self


class NDPSpooferShutdownTests(unittest.TestCase):
    def _make_spoofer(self, packet_backend):
        from netshaper.network import spoofers

        spoofer = spoofers.NDPSpoofer.__new__(spoofers.NDPSpoofer)
        spoofer.interface   = "eth0"
        spoofer.target_ipv6 = "2001:db8::10"
        spoofer.target_mac  = "00:11:22:33:44:55"
        spoofer.router_ipv6 = "2001:db8::1"
        spoofer.router_mac  = "aa:bb:cc:dd:ee:ff"
        spoofer.own_mac     = "de:ad:be:ef:00:01"
        spoofer.session     = SimpleNamespace(active=False, is_shutting_down=True)
        spoofer.packet_backend = packet_backend
        spoofer._stop  = threading.Event()
        spoofer.threads = []
        return spoofer

    def test_shutdown_sends_corrective_packets(self):
        """NDPSpoofer.shutdown() must send 3 x 2 corrective NA packets."""
        backend = mock.Mock()
        from netshaper.network import spoofers

        with mock.patch.object(spoofers, "_ensure_scapy_layers"), \
             mock.patch.object(spoofers, "Ether",                _FakeLayer), \
             mock.patch.object(spoofers, "IPv6",                 _FakeLayer), \
             mock.patch.object(spoofers, "ICMPv6ND_NA",          _FakeLayer), \
             mock.patch.object(spoofers, "ICMPv6NDOptSrcLLAddr", _FakeLayer), \
             mock.patch("netshaper.network.spoofers.time.sleep"):
            ndp = self._make_spoofer(backend)
            ndp.shutdown()

        self.assertEqual(backend.send.call_count, 6,
                         "Expected 3 iterations x 2 packets = 6 send() calls")

    def test_shutdown_restores_router_mac_on_target(self):
        """Each corrective iteration must use router_mac then target_mac as Ether src."""
        backend = mock.Mock()
        sent_src_macs = []
        from netshaper.network import spoofers

        class TrackingSrcLayer(_FakeLayer):
            def __init__(self, **kw):
                super().__init__(**kw)
                if "src" in kw:
                    sent_src_macs.append(kw["src"])

        with mock.patch.object(spoofers, "_ensure_scapy_layers"), \
             mock.patch.object(spoofers, "Ether",                TrackingSrcLayer), \
             mock.patch.object(spoofers, "IPv6",                 _FakeLayer), \
             mock.patch.object(spoofers, "ICMPv6ND_NA",          _FakeLayer), \
             mock.patch.object(spoofers, "ICMPv6NDOptSrcLLAddr", _FakeLayer), \
             mock.patch("netshaper.network.spoofers.time.sleep"):
            ndp = self._make_spoofer(backend)
            ndp.shutdown()

        # 3 iterations x 2 Ether() calls each = 6 src values
        self.assertEqual(len(sent_src_macs), 6)
        for i in range(3):
            self.assertEqual(sent_src_macs[i * 2],     "aa:bb:cc:dd:ee:ff",
                             "target-restore Ether src must be router_mac")
            self.assertEqual(sent_src_macs[i * 2 + 1], "00:11:22:33:44:55",
                             "router-restore Ether src must be target_mac")


class ARPSpooferShutdownTests(unittest.TestCase):
    """Regression guard: ARPSpoofer.shutdown() still sends 3 x 2 corrective packets."""

    def test_shutdown_sends_corrective_packets(self):
        from netshaper.network import spoofers

        backend = mock.Mock()
        spoofer = spoofers.ARPSpoofer.__new__(spoofers.ARPSpoofer)
        spoofer.interface    = "eth0"
        spoofer.target_ip    = "192.0.2.10"
        spoofer.target_mac   = "00:11:22:33:44:55"
        spoofer.gateway_ip   = "192.0.2.1"
        spoofer.gateway_mac  = "aa:bb:cc:dd:ee:ff"
        spoofer.own_mac      = "de:ad:be:ef:00:01"
        spoofer.packet_backend = backend
        spoofer._stop  = threading.Event()
        spoofer.threads = []

        with mock.patch.object(spoofers, "_ensure_scapy_layers"), \
             mock.patch.object(spoofers, "Ether", _FakeLayer), \
             mock.patch.object(spoofers, "ARP",   _FakeLayer), \
             mock.patch("netshaper.network.spoofers.time.sleep"):
            spoofer.shutdown()

        self.assertEqual(backend.send.call_count, 6)


if __name__ == "__main__":
    unittest.main(verbosity=2)
