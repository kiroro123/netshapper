"""
netshaper.sniffer
─────────────────
Two packet capture implementations:

PacketSniffer        — in-memory capture with optional single .pcap dump at stop.
                       Bounded queue (maxsize=10 000) drops rather than blocks.

RollingPacketSniffer — streaming consumer thread writes directly to disk via
                       RawPcapWriter. Rotates to a new file every max_file_size_bytes
                       (default 50 MB). Drops packets if the queue fills.

Both share the same design contract:
  • start() / stop() are the only public control methods.
  • _packet_callback() is called from the AsyncSniffer thread — must be fast
    and non-blocking; never acquire locks or do I/O here.
  • Drop counts are logged at shutdown.

Bug fixed vs original: when _consumer_flush_loop detects a disk failure it now
calls self._sniffer.stop() in addition to setting _stop_event, so the
AsyncSniffer thread also exits and stops feeding the orphaned queue.
"""

import queue
import threading
import time
import logging
from typing import List, Optional

from scapy.all import IP, AsyncSniffer, wrpcap
from scapy.utils import RawPcapWriter

from .system import print_flush

log = logging.getLogger("netshaper")


# ── Simple bounded sniffer ────────────────────────────────────────────────────

class PacketSniffer:
    """
    Captures packets to an in-memory bounded queue.
    If save_pcap=True, flushes to a timestamped .pcap file on stop().
    Queue is only allocated when save_pcap=True (no overhead otherwise).
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

    def _packet_callback(self, pkt):
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            if (self.target_ips
                    and src not in self.target_ips
                    and dst not in self.target_ips):
                return
            print_flush(
                f"[Sniff] {src} → {dst}  {pkt.sprintf('%IP.proto%')}"
            )
        if self._queue is not None:
            try:
                self._queue.put_nowait(pkt)
            except queue.Full:
                self._dropped += 1  # Drop rather than block the sniffer thread

    def start(self):
        log.info(
            "Packet sniffer started"
            + (" (saving to .pcap)" if self.save_pcap else "")
        )
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._packet_callback,
            store=False,
            stop_filter=lambda _: self._stop.is_set(),
        )
        self._sniffer.start()

    def stop(self):
        self._stop.set()
        if self._sniffer:
            self._sniffer.stop()
        if self._dropped:
            log.warning(
                f"[Sniffer] {self._dropped} packets dropped (queue saturation)"
            )
        if self.save_pcap and self._queue is not None:
            packets = []
            while not self._queue.empty():
                try:
                    packets.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            if packets:
                fname = f"capture_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
                wrpcap(fname, packets)
                log.info(f"Saved {len(packets)} packets → {fname}")


# ── Rolling file sniffer ──────────────────────────────────────────────────────

class RollingPacketSniffer:
    """
    Streams packets from a bounded queue to disk via RawPcapWriter.
    Rotates to a new file every max_file_size_bytes (default 50 MB).

    Circuit-breaker fix: on disk failure the consumer thread sets _stop_event
    *and* calls self._sniffer.stop() so the AsyncSniffer stops feeding the
    now-orphaned queue, preventing silent indefinite _dropped increments.
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

    def _packet_callback(self, pkt):
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

    def _consumer_flush_loop(self):
        active_pcap = self._get_filename()
        try:
            writer = RawPcapWriter(active_pcap, append=True, sync=True)
        except Exception as e:
            log.error(f"[RollingSniffer] Initial file open failed: {e}")
            # Stop the sniffer too so the callback stops feeding the queue
            if self._sniffer:
                self._sniffer.stop()
            self._stop_event.set()
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
                    try:
                        writer.close()
                    except Exception:
                        pass
                    self.file_index    += 1
                    self.current_bytes  = 0
                    active_pcap        = self._get_filename()
                    log.info(f"[RollingSniffer] Rotating → {active_pcap}")
                    try:
                        writer = RawPcapWriter(active_pcap, append=True, sync=True)
                    except Exception as e:
                        log.error(f"[RollingSniffer] Rotation failed: {e}")
                        # Circuit breaker: stop the sniffer, don't fill memory
                        if self._sniffer:
                            self._sniffer.stop()
                        self._stop_event.set()
                        return

                writer.write(pkt)
                self.current_bytes += pkt_len
                self._queue.task_done()
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def start(self):
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._packet_callback,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set(),
        )
        self._consumer = threading.Thread(
            target=self._consumer_flush_loop, daemon=True
        )
        self._consumer.start()
        self._sniffer.start()
        log.info("Rolling sniffer started (50 MB rotation)")

    def stop(self):
        self._stop_event.set()
        if self._sniffer:
            self._sniffer.stop()
        if self._consumer:
            self._consumer.join(timeout=5.0)
        if self._dropped:
            log.warning(
                f"[RollingSniffer] {self._dropped} packets dropped "
                f"(queue saturation)"
            )
