"""
NetShaper — packet capture.

PacketSniffer       — bounded-queue sniffer with optional one-shot pcap save.
RollingPacketSniffer — streaming writer with 50 MB file rotation.
"""
import logging
import queue
import threading
import time
from typing import List, Optional

from netshaper.capture.secure import SecureCaptureDirectory
from netshaper.utils import print_flush

log = logging.getLogger("netshaper")

IP = None
IPv6 = None
AsyncSniffer = None
RawPcapWriter = None
_wrpcap = None


def _ensure_packet_layers() -> None:
    global IP, IPv6
    if IP is None or IPv6 is None:
        from scapy.all import IP as scapy_IP, IPv6 as scapy_IPv6

        if IP is None:
            IP = scapy_IP
        if IPv6 is None:
            IPv6 = scapy_IPv6


def _ensure_capture_tools() -> None:
    global AsyncSniffer, RawPcapWriter, _wrpcap
    if AsyncSniffer is None or RawPcapWriter is None or _wrpcap is None:
        from scapy.all import AsyncSniffer as scapy_AsyncSniffer
        from scapy.utils import RawPcapWriter as scapy_RawPcapWriter
        from scapy.utils import wrpcap as scapy_wrpcap

        if AsyncSniffer is None:
            AsyncSniffer = scapy_AsyncSniffer
        if RawPcapWriter is None:
            RawPcapWriter = scapy_RawPcapWriter
        if _wrpcap is None:
            _wrpcap = scapy_wrpcap


def wrpcap(*args, **kwargs):
    _ensure_capture_tools()
    return _wrpcap(*args, **kwargs)


def _async_sniffer_running(sniffer) -> bool:
    if sniffer is None:
        return False
    running = getattr(sniffer, "running", None)
    if running is False:
        return False
    thread = getattr(sniffer, "thread", None)
    if thread is not None:
        try:
            return thread.is_alive()
        except Exception:
            return False
    return True


class PacketSniffer:
    """
    Captures packets into a bounded queue (maxsize=10 000).
    Drops packets rather than blocking the sniffer thread on a full queue.
    The queue is only allocated when save_pcap=True to avoid overhead.
    """
    def __init__(self, interface: str,
                 target_ips: Optional[List[str]] = None,
                 save_pcap: bool = False,
                 capture_dir: Optional[str] = None,
                 packet_verbose: bool = False):
        self.interface  = interface
        self.target_ips = target_ips or []
        self.save_pcap  = save_pcap
        self.capture_dir = capture_dir
        self.packet_verbose = packet_verbose
        self._sniffer   = None
        self._stop      = threading.Event()
        self._dropped   = 0
        self.packets_seen = 0
        self.packets_written = 0
        self.packets_queue_dropped = 0
        self.packets_shutdown_discarded = 0
        self.started_at: Optional[float] = None
        self.last_error: Optional[str] = None
        self.output_files: List[str] = []
        self._queue: Optional[queue.Queue] = (
            queue.Queue(maxsize=10_000) if save_pcap else None
        )

    def _packet_callback(self, pkt) -> None:
        self.packets_seen += 1
        _ensure_packet_layers()
        ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6] if pkt.haslayer(IPv6) else None
        if ip_layer is not None:
            src, dst = ip_layer.src, ip_layer.dst
            if (self.target_ips
                    and src not in self.target_ips
                    and dst not in self.target_ips):
                return
            if self.packet_verbose:
                proto = pkt.sprintf('%IP.proto%') if pkt.haslayer(IP) else pkt.sprintf('%IPv6.nh%')
                print_flush(f"[Sniff] {src} → {dst}  {proto}")
        if self._queue is not None:
            try:
                self._queue.put_nowait(pkt)
            except queue.Full:
                self._dropped += 1
                self.packets_queue_dropped += 1

    def start(self) -> None:
        log.info("Packet sniffer started" +
                 (" (saving to .pcap)" if self.save_pcap else ""))
        _ensure_capture_tools()
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._packet_callback,
            store=False,
            stop_filter=lambda _: self._stop.is_set())
        try:
            self._sniffer.start()
            self.started_at = time.time()
        except Exception as exc:
            self.last_error = f"sniffer start failed: {exc}"
            log.error(f"[Sniffer] {self.last_error}")
            raise

    def is_running(self) -> bool:
        if self._stop.is_set() or self.last_error:
            return False
        return _async_sniffer_running(self._sniffer)

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer:
            self._sniffer.stop()
        if self._dropped:
            log.warning(
                f"[Sniffer] {self._dropped} packets dropped (queue saturation)")
        if self.save_pcap and self._queue is not None:
            if not self._queue.empty():
                capture_file = SecureCaptureDirectory(
                    self.capture_dir
                ).open_new_pcap("capture")
                writer = None
                written = 0
                try:
                    writer = RawPcapWriter(
                        capture_file.handle,
                        append=False,
                        sync=True,
                    )
                    while True:
                        try:
                            packet = self._queue.get_nowait()
                        except queue.Empty:
                            break
                        writer.write(packet)
                        self._queue.task_done()
                        written += 1
                except Exception as exc:
                    self.packets_shutdown_discarded += self._queue.qsize()
                    self.last_error = f"pcap write failed: {exc}"
                    log.error(f"[Sniffer] {self.last_error}")
                    raise
                finally:
                    if writer is not None:
                        writer.close()
                    else:
                        capture_file.handle.close()
                self.packets_written += written
                self.output_files.append(capture_file.path)
                log.info(f"Saved {written} packets → {capture_file.path}")


class RollingPacketSniffer:
    """
    Streams packets from a bounded queue directly to disk via RawPcapWriter.
    Rotates to a new file every max_file_size_bytes (default 50 MB).
    Consumer thread + AsyncSniffer thread run concurrently.
    """
    def __init__(self, interface: str,
                 base_filename: str = "capture",
                 target_ips: Optional[List[str]] = None,
                 capture_dir: Optional[str] = None,
                 max_file_size_bytes: int = 50 * 1024 * 1024,
                 packet_verbose: bool = False):
        self.interface           = interface
        self.base_filename       = base_filename
        self.target_ips          = target_ips or []
        self.capture_dir         = capture_dir
        self.max_file_size_bytes = max_file_size_bytes
        self.packet_verbose      = packet_verbose
        self._queue              = queue.Queue(maxsize=10_000)
        self._stop_event         = threading.Event()
        self._dropped            = 0
        self.file_index          = 0
        self.current_bytes       = 0
        self._sniffer            = None
        self._consumer           = None
        self._writer_ready       = threading.Event()
        self.started_at: Optional[float] = None
        self.last_error: Optional[str] = None
        self.output_files: List[str] = []
        self.packets_shutdown_discarded = 0

    def _open_writer(self):
        capture_file = SecureCaptureDirectory(
            self.capture_dir
        ).open_new_pcap(f"{self.base_filename}_{self.file_index}")
        try:
            writer = RawPcapWriter(capture_file.handle, append=False, sync=True)
        except Exception:
            capture_file.handle.close()
            raise
        return capture_file.path, writer

    def _packet_callback(self, pkt) -> None:
        _ensure_packet_layers()
        ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6] if pkt.haslayer(IPv6) else None
        if ip_layer is not None:
            src, dst = ip_layer.src, ip_layer.dst
            if (self.target_ips
                    and src not in self.target_ips
                    and dst not in self.target_ips):
                return
            if self.packet_verbose:
                proto = pkt.sprintf('%IP.proto%') if pkt.haslayer(IP) else pkt.sprintf('%IPv6.nh%')
                print_flush(f"[Sniff] {src} → {dst}  {proto}")
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            self._dropped += 1

    def _consumer_flush_loop(self) -> None:
        active_pcap = ""
        writer = None
        try:
            _ensure_capture_tools()
            active_pcap, writer = self._open_writer()
        except Exception as e:
            self.last_error = f"Initial file open failed: {e}"
            self._writer_ready.set()
            log.error(f"[RollingSniffer] {self.last_error}")
            return

        self.output_files.append(active_pcap)
        self._writer_ready.set()
        log.info(f"[RollingSniffer] Writing → {active_pcap}")
        try:
            while not self._stop_event.is_set() or not self._queue.empty():
                try:
                    pkt = self._queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                pkt_len = len(pkt)
                if self.current_bytes + pkt_len > self.max_file_size_bytes:
                    # BUG FIX: log close errors instead of silencing them
                    try:
                        writer.close()
                    except Exception as e:
                        log.error(
                            f"[RollingSniffer] Close before rotation failed: {e}")
                    self.file_index    += 1
                    self.current_bytes  = 0
                    try:
                        active_pcap, writer = self._open_writer()
                        log.info(f"[RollingSniffer] Rotating → {active_pcap}")
                        self.output_files.append(active_pcap)
                    except Exception as e:
                        self.last_error = f"Rotation failed: {e}"
                        log.error(f"[RollingSniffer] {self.last_error}")
                        return   # Stop capture — disk problem

                try:
                    writer.write(pkt)
                    self.current_bytes += pkt_len
                    self._queue.task_done()
                except Exception as e:
                    self.packets_shutdown_discarded += 1 + self._queue.qsize()
                    self.last_error = f"Writer failed: {e}"
                    log.error(f"[RollingSniffer] {self.last_error}")
                    return
        finally:
            # BUG FIX: log final close errors instead of silencing them
            if writer is not None:
                try:
                    writer.close()
                except Exception as e:
                    self.last_error = f"Final close failed: {e}"
                    log.error(f"[RollingSniffer] {self.last_error}")

    def start(self) -> None:
        _ensure_capture_tools()
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._packet_callback,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set())
        self._consumer = threading.Thread(
            target=self._consumer_flush_loop, daemon=True)
        self._consumer.start()
        if not self._writer_ready.wait(timeout=2.0):
            self.last_error = "Initial file open timed out"
            self._stop_event.set()
            raise RuntimeError(self.last_error)
        if self.last_error:
            self._stop_event.set()
            raise RuntimeError(self.last_error)
        try:
            self._sniffer.start()
            self.started_at = time.time()
        except Exception as exc:
            self.last_error = f"sniffer start failed: {exc}"
            self._stop_event.set()
            if self._consumer:
                self._consumer.join(timeout=5.0)
            log.error(f"[RollingSniffer] {self.last_error}")
            raise
        log.info("Rolling sniffer started (50 MB rotation)")

    def is_running(self) -> bool:
        if self._stop_event.is_set() or self.last_error:
            return False
        if self._consumer is None or not self._consumer.is_alive():
            return False
        return _async_sniffer_running(self._sniffer)

    def stop(self) -> bool:
        self._stop_event.set()
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception as exc:
                self.last_error = f"sniffer stop failed: {exc}"
                log.error(f"[RollingSniffer] {self.last_error}")
        if self._consumer:
            self._consumer.join(timeout=5.0)
            if self._consumer.is_alive():
                self.packets_shutdown_discarded += self._queue.qsize()
                self.last_error = (
                    "rolling capture did not finish flushing within 5 seconds"
                )
                log.error(f"[RollingSniffer] {self.last_error}")
                return False
        if self._dropped:
            log.warning(
                f"[RollingSniffer] {self._dropped} packets dropped "
                f"(queue saturation)")
        return self.last_error is None
