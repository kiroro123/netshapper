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


class FakeAsyncSniffer:
    def __init__(self, **_kwargs):
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


class PacketSnifferTests(unittest.TestCase):
    def test_packet_callback_accepts_ipv6_packets(self):
        with mock.patch("netshaper.capture.sniffer.IP", new=object()), \
             mock.patch("netshaper.capture.sniffer.IPv6", new=object()), \
             mock.patch("netshaper.capture.sniffer.print_flush") as print_flush_mock:
            fake_pkt = FakeIPv6Packet(sniffer.IPv6)
            s = sniffer.PacketSniffer("eth0")
            s._packet_callback(fake_pkt)

        print_flush_mock.assert_called_once()

    def test_packet_sniffer_tracks_liveness_and_written_pcap(self):
        with mock.patch("netshaper.capture.sniffer._ensure_capture_tools"), \
             mock.patch("netshaper.capture.sniffer.AsyncSniffer",
                        new=FakeAsyncSniffer), \
             mock.patch("netshaper.capture.sniffer.wrpcap") as wrpcap_mock:
            s = sniffer.PacketSniffer("eth0", save_pcap=True)
            s.start()
            self.assertTrue(s.is_running())
            s._queue.put_nowait(object())
            s.stop()

        self.assertFalse(s.is_running())
        wrpcap_mock.assert_called_once()
        self.assertEqual(len(s.output_files), 1)
        self.assertTrue(s.output_files[0].endswith(".pcap"))

    def test_rolling_sniffer_fails_startup_when_writer_cannot_open(self):
        class FailingWriter:
            def __init__(self, *_args, **_kwargs):
                raise OSError("disk full")

        with mock.patch("netshaper.capture.sniffer._ensure_capture_tools"), \
             mock.patch("netshaper.capture.sniffer.AsyncSniffer",
                        new=FakeAsyncSniffer), \
             mock.patch("netshaper.capture.sniffer.RawPcapWriter",
                        new=FailingWriter):
            s = sniffer.RollingPacketSniffer("eth0")
            with self.assertRaisesRegex(RuntimeError, "disk full"):
                s.start()

        self.assertFalse(s.is_running())
        self.assertIn("disk full", s.last_error)


if __name__ == "__main__":
    unittest.main(verbosity=2)
