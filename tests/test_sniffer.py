import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from netshaper.capture import sniffer
from netshaper.capture.secure import CapturePathError
from netshaper.capture.secure import SecureCaptureDirectory


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
    def test_packet_callback_accepts_ipv6_packets_without_default_printing(self):
        with mock.patch("netshaper.capture.sniffer.IP", new=object()), \
             mock.patch("netshaper.capture.sniffer.IPv6", new=object()), \
             mock.patch("netshaper.capture.sniffer.print_flush") as print_flush_mock:
            fake_pkt = FakeIPv6Packet(sniffer.IPv6)
            s = sniffer.PacketSniffer("eth0")
            s._packet_callback(fake_pkt)

        self.assertEqual(s.packets_seen, 1)
        print_flush_mock.assert_not_called()

    def test_packet_callback_prints_when_verbose_enabled(self):
        with mock.patch("netshaper.capture.sniffer.IP", new=object()), \
             mock.patch("netshaper.capture.sniffer.IPv6", new=object()), \
             mock.patch("netshaper.capture.sniffer.print_flush") as print_flush_mock:
            fake_pkt = FakeIPv6Packet(sniffer.IPv6)
            s = sniffer.PacketSniffer("eth0", packet_verbose=True)
            s._packet_callback(fake_pkt)

        print_flush_mock.assert_called_once()

    def _run_one_shot_capture(self) -> None:
        class Writer:
            def __init__(self, fileobj, **kwargs):
                self.fileobj = fileobj
                self.kwargs = kwargs

            def write(self, _packet):
                self.fileobj.write(b"packet")

            def close(self):
                self.fileobj.close()

        with mock.patch("netshaper.capture.sniffer._ensure_capture_tools"), \
             mock.patch("netshaper.capture.sniffer.AsyncSniffer",
                        new=FakeAsyncSniffer), \
             mock.patch("netshaper.capture.sniffer.RawPcapWriter",
                        new=Writer), \
             tempfile.TemporaryDirectory() as capture_dir:
            s = sniffer.PacketSniffer(
                "eth0",
                save_pcap=True,
                capture_dir=capture_dir,
            )
            s.start()
            self.assertTrue(s.is_running())
            s._queue.put_nowait(object())
            s.stop()

            self.assertFalse(s.is_running())
            self.assertEqual(len(s.output_files), 1)
            self.assertTrue(s.output_files[0].endswith(".pcap"))
            self.assertEqual(
                stat.S_IMODE(os.stat(s.output_files[0]).st_mode),
                0o600,
            )

    def test_packet_sniffer_tracks_liveness_and_written_pcap(self):
        self._run_one_shot_capture()

    def test_packet_sniffer_drains_entire_queue_on_stop(self):
        writes = []

        class Writer:
            def __init__(self, fileobj, **_kwargs):
                self.fileobj = fileobj

            def write(self, packet):
                writes.append(packet)
                self.fileobj.write(b"packet")

            def close(self):
                self.fileobj.close()

        with mock.patch("netshaper.capture.sniffer._ensure_capture_tools"), \
             mock.patch("netshaper.capture.sniffer.AsyncSniffer",
                        new=FakeAsyncSniffer), \
             mock.patch("netshaper.capture.sniffer.RawPcapWriter",
                        new=Writer), \
             tempfile.TemporaryDirectory() as capture_dir:
            s = sniffer.PacketSniffer(
                "eth0",
                save_pcap=True,
                capture_dir=capture_dir,
            )
            s.start()
            for _ in range(8_000):
                s._queue.put_nowait(object())
            s.stop()

        self.assertEqual(len(writes), 8_000)
        self.assertEqual(s.packets_written, 8_000)
        self.assertEqual(s.packets_shutdown_discarded, 0)

    def test_core_capture_rejects_preexisting_symlink(self):
        class Writer:
            def __init__(self, *_args, **_kwargs):
                raise AssertionError("writer must not open a symlink collision")

        with tempfile.TemporaryDirectory() as capture_dir:
            symlink_path = (
                Path(capture_dir) / "capture_20260101_000000_owned.pcap"
            )
            symlink_path.symlink_to("/etc/passwd")
            with mock.patch("netshaper.capture.sniffer._ensure_capture_tools"), \
                 mock.patch("netshaper.capture.sniffer.AsyncSniffer",
                            new=FakeAsyncSniffer), \
                 mock.patch("netshaper.capture.sniffer.RawPcapWriter",
                            new=Writer), \
                 mock.patch("netshaper.capture.secure.time.strftime",
                            return_value="20260101_000000"), \
                 mock.patch("netshaper.capture.secure.secrets.token_hex",
                            return_value="owned"):
                s = sniffer.PacketSniffer(
                    "eth0",
                    save_pcap=True,
                    capture_dir=capture_dir,
                )
                s.start()
                s._queue.put_nowait(object())
                with self.assertRaisesRegex(CapturePathError, "unique"):
                    s.stop()

    def test_core_capture_file_mode_is_0600(self):
        self._run_one_shot_capture()

    def test_root_capture_directory_rejects_non_root_owned_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            original_lstat = os.lstat
            untrusted = os.path.abspath(tmp)

            def fake_lstat(path):
                result = original_lstat(path)
                if os.path.abspath(os.fspath(path)) == untrusted:
                    values = list(result)
                    values[4] = 1234
                    return os.stat_result(values)
                return result

            capture_dir = SecureCaptureDirectory(os.path.join(tmp, "captures"))
            with mock.patch("netshaper.capture.secure.os.geteuid",
                            return_value=0), \
                 mock.patch("netshaper.capture.secure.os.lstat",
                            side_effect=fake_lstat), \
                 self.assertRaisesRegex(CapturePathError, "owned by root"):
                capture_dir.ensure()

    def test_rolling_capture_does_not_append_existing_file(self):
        writers = []

        class Writer:
            def __init__(self, fileobj, **kwargs):
                self.fileobj = fileobj
                self.kwargs = kwargs
                writers.append(self)

            def write(self, packet):
                self.fileobj.write(bytes(packet))

            def close(self):
                self.fileobj.close()

        with tempfile.TemporaryDirectory() as capture_dir:
            existing = Path(capture_dir) / "capture_0_20260101_000000_collide.pcap"
            existing.write_bytes(b"old")
            with mock.patch("netshaper.capture.sniffer._ensure_capture_tools"), \
                 mock.patch("netshaper.capture.sniffer.AsyncSniffer",
                            new=FakeAsyncSniffer), \
                 mock.patch("netshaper.capture.sniffer.RawPcapWriter",
                            new=Writer), \
                 mock.patch("netshaper.capture.secure.time.strftime",
                            return_value="20260101_000000"), \
                 mock.patch("netshaper.capture.secure.secrets.token_hex",
                            side_effect=["collide", "fresh"]):
                s = sniffer.RollingPacketSniffer(
                    "eth0",
                    capture_dir=capture_dir,
                )
                s.start()
                s.stop()

            self.assertEqual(existing.read_bytes(), b"old")
            self.assertEqual(len(writers), 1)
            self.assertIs(writers[0].kwargs["append"], False)
            self.assertIn("fresh", s.output_files[0])

    def test_rolling_sniffer_fails_startup_when_writer_cannot_open(self):
        class FailingWriter:
            def __init__(self, *_args, **_kwargs):
                raise OSError("disk full")

        with mock.patch("netshaper.capture.sniffer._ensure_capture_tools"), \
             mock.patch("netshaper.capture.sniffer.AsyncSniffer",
                        new=FakeAsyncSniffer), \
             mock.patch("netshaper.capture.sniffer.RawPcapWriter",
                        new=FailingWriter), \
             tempfile.TemporaryDirectory() as capture_dir:
            s = sniffer.RollingPacketSniffer("eth0", capture_dir=capture_dir)
            with self.assertRaisesRegex(RuntimeError, "disk full"):
                s.start()

        self.assertFalse(s.is_running())
        self.assertIn("disk full", s.last_error)

    def test_rolling_stop_reports_unflushed_consumer(self):
        s = sniffer.RollingPacketSniffer("eth0")
        s._consumer = mock.Mock()
        s._consumer.is_alive.return_value = True
        s._queue.put_nowait(b"first")
        s._queue.put_nowait(b"second")

        result = s.stop()

        self.assertFalse(result)
        s._consumer.join.assert_called_once_with(timeout=5.0)
        self.assertIn("did not finish flushing", s.last_error)
        self.assertEqual(s.packets_shutdown_discarded, 2)

    def test_rolling_stop_reports_sniffer_stop_failure(self):
        s = sniffer.RollingPacketSniffer("eth0")
        s._sniffer = mock.Mock()
        s._sniffer.stop.side_effect = RuntimeError("closed early")

        result = s.stop()

        self.assertFalse(result)
        self.assertIn("closed early", s.last_error)


if __name__ == "__main__":
    unittest.main(verbosity=2)
