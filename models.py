"""
netshaper.models
────────────────
Data model definitions. No external dependencies — safe to import anywhere.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Device:
    ip:       str
    mac:      str
    hostname: str           = ""
    ipv6:     Optional[str] = None
    os_hint:  str           = ""   # Reserved: future passive OS fingerprinting
                                   # (TTL / TCP-window analysis). Not populated yet.
