import unittest
from unittest import mock

from netshaper.capture import sniffer


class FakeIPv6Packet:
    def __init__(self, ipv6_layer):
        self._layers = {ipv6_layer: type("L", (), {"src": "2001::1", "dst": "2001::2"})()}

    def haslayer(self, layer):
        return layer in self._layers

    def __getitem__(self, item):
        return self._layers[item]

    def sprintf(self, fmt):
        return "58" if fmt.endswith("nh%") else ""


class PacketSnifferTests(unittest.TestCase):
    def test_packet_callback_accepts_ipv6_packets(self):
        with mock.patch("netshaper.capture.sniffer.IP", new=object()), \
             mock.patch("netshaper.capture.sniffer.IPv6", new=object()), \
             mock.patch("netshaper.capture.sniffer.print_flush") as print_flush_mock:
            fake_pkt = FakeIPv6Packet(sniffer.IPv6)
            s = sniffer.PacketSniffer("eth0")
            s._packet_callback(fake_pkt)

        print_flush_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
