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
             mock.patch.object(spoofers, "ICMPv6NDOptDstLLAddr", _FakeLayer), \
             mock.patch("netshaper.network.spoofers.time.sleep"):
            ndp = self._make_spoofer(backend)
            ndp.shutdown()

        self.assertEqual(backend.send.call_count, 6,
                         "Expected 3 iterations x 2 packets = 6 send() calls")

    def test_shutdown_keeps_peer_macs_out_of_ethernet_source(self):
        """Repair ND options without moving peer MACs in switch forwarding tables."""
        backend = mock.Mock()
        sent_src_macs = []
        advertised_macs = []
        hop_limits = []
        from netshaper.network import spoofers

        class TrackingSrcLayer(_FakeLayer):
            def __init__(self, **kw):
                super().__init__(**kw)
                if "src" in kw:
                    sent_src_macs.append(kw["src"])

        class TrackingOptionLayer(_FakeLayer):
            def __init__(self, **kw):
                super().__init__(**kw)
                if "lladdr" in kw:
                    advertised_macs.append(kw["lladdr"])

        class TrackingIPv6Layer(_FakeLayer):
            def __init__(self, **kw):
                super().__init__(**kw)
                hop_limits.append(kw["hlim"])

        with mock.patch.object(spoofers, "_ensure_scapy_layers"), \
             mock.patch.object(spoofers, "Ether",                TrackingSrcLayer), \
             mock.patch.object(spoofers, "IPv6",                 TrackingIPv6Layer), \
             mock.patch.object(spoofers, "ICMPv6ND_NA",          _FakeLayer), \
             mock.patch.object(
                 spoofers, "ICMPv6NDOptDstLLAddr", TrackingOptionLayer
             ), \
             mock.patch("netshaper.network.spoofers.time.sleep"):
            ndp = self._make_spoofer(backend)
            ndp.shutdown()

        self.assertEqual(sent_src_macs, ["de:ad:be:ef:00:01"] * 6)
        self.assertEqual(hop_limits, [255] * 6)
        for i in range(3):
            self.assertEqual(advertised_macs[i * 2], "aa:bb:cc:dd:ee:ff")
            self.assertEqual(advertised_macs[i * 2 + 1], "00:11:22:33:44:55")


class ARPSpooferShutdownTests(unittest.TestCase):
    """Regression guard: ARPSpoofer.shutdown() still sends 3 x 2 corrective packets."""

    def test_shutdown_sends_corrective_packets(self):
        from netshaper.network import spoofers

        backend = mock.Mock()
        sent_src_macs = []
        advertised_macs = []
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

        class TrackingEtherLayer(_FakeLayer):
            def __init__(self, **kw):
                super().__init__(**kw)
                sent_src_macs.append(kw["src"])

        class TrackingArpLayer(_FakeLayer):
            def __init__(self, **kw):
                super().__init__(**kw)
                advertised_macs.append(kw["hwsrc"])

        with mock.patch.object(spoofers, "_ensure_scapy_layers"), \
             mock.patch.object(spoofers, "Ether", TrackingEtherLayer), \
             mock.patch.object(spoofers, "ARP",   TrackingArpLayer), \
             mock.patch("netshaper.network.spoofers.time.sleep"):
            spoofer.shutdown()

        self.assertEqual(backend.send.call_count, 6)
        self.assertEqual(sent_src_macs, ["de:ad:be:ef:00:01"] * 6)
        for i in range(3):
            self.assertEqual(advertised_macs[i * 2], "aa:bb:cc:dd:ee:ff")
            self.assertEqual(advertised_macs[i * 2 + 1], "00:11:22:33:44:55")


class SpoofTimingTests(unittest.TestCase):
    def test_burst_helper_sends_bounded_count(self):
        from netshaper.network import spoofers

        backend = mock.Mock()
        packet = object()
        spoofers._send_burst(backend, packet, "eth0", 3)

        self.assertEqual(backend.send.call_count, 3)
        backend.send.assert_called_with(packet, "eth0")

    def test_timing_rejects_unbounded_values(self):
        from netshaper.network.spoofers import validate_spoof_timing

        for interval, burst in ((0.1, 1), (2.0, 0), (2.0, 6)):
            with self.subTest(interval=interval, burst=burst):
                with self.assertRaises(ValueError):
                    validate_spoof_timing(interval, burst)

    def test_timing_accepts_lab_bounds(self):
        from netshaper.network.spoofers import validate_spoof_timing

        self.assertEqual(validate_spoof_timing(0.25, 5), (0.25, 5))


if __name__ == "__main__":
    unittest.main(verbosity=2)
