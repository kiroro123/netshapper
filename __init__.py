"""
netshaper
─────────
Production-ready multi-feature MITM framework — v3.8.0

Public API surface (import what you need):

    from netshaper import NetShaper
    from netshaper.discovery import NetworkDiscovery
    from netshaper.models import Device

Module layout:
    models     — Device dataclass (no deps)
    system     — SystemChecker, SubprocessRunner, utilities
    discovery  — NetworkDiscovery (ARP sweep, hostname resolution)
    spoof      — ARPSpoofer, NDPSpoofer
    firewall   — FirewallManager (per-target iptables chains)
    shaper     — TrafficShaper, MarkIDPool (tc HTB bandwidth control)
    sniffer    — PacketSniffer, RollingPacketSniffer
    core       — NetShaper orchestrator, TargetSession
    ui         — Interactive terminal helpers

Entry point: run.py (in the working/ directory)
"""

from .core    import NetShaper, TargetSession         # noqa: F401
from .models  import Device                           # noqa: F401
from .system  import SystemChecker, SubprocessRunner  # noqa: F401

__version__ = "3.8.0"
__all__ = [
    "NetShaper",
    "TargetSession",
    "Device",
    "SystemChecker",
    "SubprocessRunner",
]
