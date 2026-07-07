"""
NetShaper — per-target MITM session state.

TargetSession owns all resources for one intercepted device:
  firewall chains, ARP spoofer, NDP spoofer, and traffic shaping marks.

`active` and `is_shutting_down` are plain booleans read locklessly by spoof
threads — CPython bool reads are atomic at interpreter level. Only written
from within the orchestrator's _lifecycle_lock (RLock).
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

from netshaper import config
from netshaper.models import Device
from netshaper.network.backends import RealPacketBackend
from netshaper.network.firewall import FirewallManager
from netshaper.network.spoofers import ARPSpoofer, NDPSpoofer
from netshaper.network.shaper import ShapingProfile, TrafficShaper

log = logging.getLogger("netshaper")


class TargetSession:
    def __init__(self, target: Device, interface: str,
                 own_mac: str, own_ip: str, own_ipv6: Optional[str],
                 gateway_ip: str, gateway_mac: str,
                 gateway_ipv6: Optional[str],
                 shaper: TrafficShaper,
                 session_id: Optional[str] = None,
                 journal: Optional[Callable[[], bool]] = None):
        self.target       = target
        self.interface    = interface
        self.session_id   = session_id
        self.own_mac      = own_mac
        self.own_ip       = own_ip
        self.own_ipv6     = own_ipv6
        self.gateway_ip   = gateway_ip
        self.gateway_mac  = gateway_mac
        self.gateway_ipv6 = gateway_ipv6
        self.shaper       = shaper
        self._journal     = journal

        # Lockless state flags — write only under orchestrator._lifecycle_lock
        self.active           = True
        self.is_shutting_down = False

        self.arp_spoof: Optional[ARPSpoofer]    = None
        self.ndp_spoof: Optional[NDPSpoofer]    = None
        self.firewall:  Optional[FirewallManager] = None
        self.dns_on      = False
        self.throttle_on = False
        self.limit:    Optional[float] = None
        self.shaping_profile: Optional[ShapingProfile] = None
        self._mark_id: Optional[int]   = None

    def setup(self, dns_spoof: bool = False, captive_portal: bool = False,
              http_redirect_port: Optional[int] = None,
              limit: Optional[float] = None,
              shaping_profile: Optional[ShapingProfile] = None,
              mark_base: int = 10) -> None:
        session_id = getattr(self, "session_id", None)
        journal = getattr(self, "_journal", None)
        firewall = FirewallManager(
            self.target.ip,
            self.interface,
            session_id=session_id,
            auto_setup=False,
            journal=journal,
        )
        self.firewall = firewall
        if self._journal and not self._journal():
            raise RuntimeError(
                f"Could not persist per-target firewall intent for {self.target.ip}"
            )
        firewall.setup()
        if dns_spoof or captive_portal or http_redirect_port:
            if not self.firewall.add_redirect_rules(
                    dns_spoof=dns_spoof,
                    http_redirect_port=http_redirect_port):
                raise RuntimeError(
                    f"Failed to add redirect rules for {self.target.ip}"
                )
            self.dns_on = dns_spoof
        if limit is not None or shaping_profile is not None:
            self.shaper.apply_target(
                self.target.ip,
                limit,
                mark_base,
                journal=journal,
                profile=shaping_profile,
            )
            if not self.firewall.add_shaping(self.target.ip, mark_base):
                self.shaper.cleanup_target(mark_base)
                raise RuntimeError(
                    f"Failed to add shaping firewall marks for {self.target.ip}"
                )
            self.throttle_on = True
            self.limit = (
                shaping_profile.bandwidth_mbps
                if shaping_profile is not None
                else limit
            )
            self.shaping_profile = shaping_profile
            self._mark_id     = mark_base

    def start_spoof(
        self,
        arp_on: bool = True,
        *,
        interval: float = 2.0,
        burst: int = 1,
    ) -> None:
        if config.DRY_RUN:
            log.info(f"[DRY-RUN] Would start spoofers for {self.target.ip}")
            return
        packet_backend = RealPacketBackend()

        if arp_on and self.arp_spoof is None:
            self.arp_spoof = ARPSpoofer(
                self.interface, self.target.ip, self.target.mac,
                self.gateway_ip, self.gateway_mac, self.own_mac, self,
                packet_backend=packet_backend,
                interval=interval,
                burst=burst)
            self.arp_spoof.start()
        if (arp_on
                and self.target.ipv6
                and self.gateway_ipv6
                and self.ndp_spoof is None):
            self.ndp_spoof = NDPSpoofer(
                self.interface, self.target.ipv6, self.target.mac,
                self.gateway_ipv6, self.gateway_mac, self.own_mac, self,
                packet_backend=packet_backend,
                interval=interval,
                burst=burst)
            self.ndp_spoof.start()

    def stop_spoof(self) -> None:
        if self.arp_spoof:
            self.arp_spoof.shutdown()
        if self.ndp_spoof:
            self.ndp_spoof.shutdown()

    def cleanup(self) -> bool:
        self.active = False
        self.is_shutting_down = True
        errors = []

        def cleanup_step(description: str, action) -> bool:
            try:
                result = action()
                if result is False:
                    raise RuntimeError("cleanup command failed")
            except Exception as exc:
                errors.append((description, exc))
                log.error(
                    f"Target {self.target.ip} cleanup failed "
                    f"({description}): {exc}"
                )
                return False
            return True

        if self.arp_spoof:
            if cleanup_step("ARP spoof shutdown", self.arp_spoof.shutdown):
                self.arp_spoof = None
        if self.ndp_spoof:
            if cleanup_step("NDP spoof shutdown", self.ndp_spoof.shutdown):
                self.ndp_spoof = None
        if self.firewall:
            if cleanup_step("firewall cleanup", self.firewall.cleanup):
                self.firewall = None
        if self.throttle_on and self._mark_id is not None:
            mark_id = self._mark_id
            if cleanup_step(
                    "traffic shaping cleanup",
                    lambda mark_id=mark_id: self.shaper.cleanup_target(mark_id),
            ):
                self.throttle_on = False
                self._mark_id = None
                self.limit = None
                self.shaping_profile = None
        if errors:
            log.warning(
                f"Target {self.target.ip} cleanup completed with "
                f"{len(errors)} error(s)."
            )
        return not errors
