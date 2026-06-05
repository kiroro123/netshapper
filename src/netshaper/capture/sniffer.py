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

from scapy.all import IP, AsyncSniffer, wrpcap
from scapy.utils import RawPcapWriter

from netshaper.utils import print_flush

log = logging.getLogger("netshaper")


class PacketSniffer:
    """
    Captures packets into a bounded queue (maxsize=10 000).
    Drops packets rather than blocking the sniffer thread on a full queue.
    The queue is only allocated when save_pcap=True to avoid overhead.
    """
    def __init__(self, interface: str,
                 target_ips: Optional[List[str]] = None,
                 save_pcap: bool = False):
        self.interface  = interface
        self.target_ips = target_ips or []
        self.save_pcap  = save_pcap
        self._sniffer   = None
        self._stop      = threading.Event()
        self._dropped   = 0
        self._queue: Optional[queue.Queue] = (
            queue.Queue(maxsize=10_000) if save_pcap else None
        )

    def _packet_callback(self, pkt) -> None:
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            if (self.target_ips
                    and src not in self.target_ips
                    and dst not in self.target_ips):
                return
            print_flush(f"[Sniff] {src} → {dst}  {pkt.sprintf('%IP.proto%')}")
        if self._queue is not None:
            try:
                self._queue.put_nowait(pkt)
            except queue.Full:
                self._dropped += 1

    def start(self) -> None:
        log.info("Packet sniffer started" +
                 (" (saving to .pcap)" if self.save_pcap else ""))
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._packet_callback,
            store=False,
            stop_filter=lambda _: self._stop.is_set())
        self._sniffer.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer:
            self._sniffer.stop()
        if self._dropped:
            log.warning(
                f"[Sniffer] {self._dropped} packets dropped (queue saturation)")
        if self.save_pcap and self._queue is not None:
            # BUG FIX: bounded drain so shutdown doesn't block on a full queue
            packets = []
            max_drain = 5_000
            while not self._queue.empty() and len(packets) < max_drain:
                try:
                    packets.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            if packets:
                fname = f"capture_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
                wrpcap(fname, packets)
                log.info(f"Saved {len(packets)} packets → {fname}")


class RollingPacketSniffer:
    """
    Streams packets from a bounded queue directly to disk via RawPcapWriter.
    Rotates to a new file every max_file_size_bytes (default 50 MB).
    Consumer thread + AsyncSniffer thread run concurrently.
    """
    def __init__(self, interface: str,
                 base_filename: str = "capture",
                 target_ips: Optional[List[str]] = None,
                 max_file_size_bytes: int = 50 * 1024 * 1024):
        self.interface           = interface
        self.base_filename       = base_filename
        self.target_ips          = target_ips or []
        self.max_file_size_bytes = max_file_size_bytes
        self._queue              = queue.Queue(maxsize=10_000)
        self._stop_event         = threading.Event()
        self._dropped            = 0
        self.file_index          = 0
        self.current_bytes       = 0
        self._sniffer            = None
        self._consumer           = None

    def _get_filename(self) -> str:
        ts = time.strftime('%Y%m%d_%H%M%S')
        return f"{self.base_filename}_{ts}_{self.file_index}.pcap"

    def _packet_callback(self, pkt) -> None:
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            if (self.target_ips
                    and src not in self.target_ips
                    and dst not in self.target_ips):
                return
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            self._dropped += 1

    def _consumer_flush_loop(self) -> None:
        active_pcap = self._get_filename()
        try:
            writer = RawPcapWriter(active_pcap, append=True, sync=True)
        except Exception as e:
            log.error(f"[RollingSniffer] Initial file open failed: {e}")
            return

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
                    active_pcap        = self._get_filename()
                    log.info(f"[RollingSniffer] Rotating → {active_pcap}")
                    try:
                        writer = RawPcapWriter(active_pcap, append=True, sync=True)
                    except Exception as e:
                        log.error(f"[RollingSniffer] Rotation failed: {e}")
                        return   # Stop capture — disk problem

                writer.write(pkt)
                self.current_bytes += pkt_len
                self._queue.task_done()
        finally:
            # BUG FIX: log final close errors instead of silencing them
            try:
                writer.close()
            except Exception as e:
                log.error(f"[RollingSniffer] Final close failed: {e}")

    def start(self) -> None:
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._packet_callback,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set())
        self._consumer = threading.Thread(
            target=self._consumer_flush_loop, daemon=True)
        self._consumer.start()
        self._sniffer.start()
        log.info("Rolling sniffer started (50 MB rotation)")

    def stop(self) -> None:
        self._stop_event.set()
        if self._sniffer:
            self._sniffer.stop()
        if self._consumer:
            self._consumer.join(timeout=5.0)
        if self._dropped:
            log.warning(
                f"[RollingSniffer] {self._dropped} packets dropped "
                f"(queue saturation)")
