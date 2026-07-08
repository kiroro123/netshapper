"""Pure session plan objects for NetShaper execution."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union

from netshaper.models import Device
from netshaper.network.shaper import ShapingProfile


TargetRef = Union[Device, str]


class ModuleID(str, Enum):
    """Named offensive network modules used internally after CLI parsing."""

    ARP = "arp"
    DNS = "dns"
    PORTAL = "portal"
    SHAPING = "shaping"
    CAPTURE = "capture"
    MITM = "mitm"
    ARP_AMPLIFICATION = "arp-amplification"
    DNSSEC = "dnssec"
    HSTS_IDN_DEMO = "hsts-idn-demo"


@dataclass(frozen=True)
class ArpOptions:
    enabled: bool
    interval: float = 2.0
    burst: int = 1
    amplify: int = 0
    amplify_burst: int = 5
    amplify_interval: float = 0.1
    cam_exhaust: int = 0

    @property
    def amplification_enabled(self) -> bool:
        return self.amplify > 0 or self.cam_exhaust > 0


@dataclass(frozen=True)
class DnsOptions:
    enabled: bool
    dnssec_mode: str = "off"
    upstream: str = "8.8.8.8"

    @property
    def dnssec_enabled(self) -> bool:
        return self.dnssec_mode != "off"


@dataclass(frozen=True)
class PortalOptions:
    enabled: bool
    http_redirect_port: Optional[int] = None
    hsts_idn_demo: bool = False


@dataclass(frozen=True)
class CaptureOptions:
    enabled: bool
    save_pcap: bool = False
    rolling: bool = False
    packet_verbose: bool = False


@dataclass(frozen=True)
class MitmOptions:
    enabled: bool


@dataclass(frozen=True)
class SessionPlan:
    """Resolved execution plan consumed by SessionRunner."""

    interface: str
    authorized_cidrs: tuple[str, ...]
    targets: tuple[TargetRef, ...]
    modules: frozenset[ModuleID]
    arp: ArpOptions
    dns: DnsOptions
    portal: PortalOptions
    capture: CaptureOptions
    shaping: Optional[ShapingProfile]
    mitm: MitmOptions

    @property
    def target_ips(self) -> tuple[str, ...]:
        return tuple(
            target if isinstance(target, str) else target.ip
            for target in self.targets
        )

    @property
    def throttle_enabled(self) -> bool:
        return self.shaping is not None
