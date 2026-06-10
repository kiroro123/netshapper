"""
NetShaper — data model and shared primitives.
"""
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Device:
    ip:       str
    mac:      str
    hostname: str           = ""
    ipv6:     Optional[str] = None
    os_hint:  str           = ""   # Reserved: future passive OS fingerprinting
                                   # (TTL / TCP-window analysis). Not populated yet.


class MarkIDPool:
    """
    Thread-safe registry of tc mark IDs.

    Marks are allocated in *pairs*: base and base+10.
    The step parameter must therefore be >= 20 to prevent pair-collision
    between adjacent allocations (e.g. target A gets base=10, target B
    gets base=30; A's pair mark is 20 which would not alias B's base — so
    step=20 is the minimum safe value).

    acquire() is idempotent for an already-registered IP.
    release() returns both the base slot to the pool (base+10 is implicit).
    """
    def __init__(self, start: int = 10, step: int = 20,
                 max_targets: int = 50):
        if step < 20:
            raise ValueError("step must be >= 20 to avoid mark-pair collisions")
        self._available: List[int]      = list(range(start,
                                                      start + step * max_targets,
                                                      step))
        self._used:      Dict[str, int] = {}
        self._lock = threading.Lock()

    def acquire(self, ip: str) -> int:
        with self._lock:
            if ip in self._used:
                return self._used[ip]
            if not self._available:
                raise RuntimeError(
                    "Mark ID pool exhausted — max_targets reached.")
            mark = self._available.pop(0)
            self._used[ip] = mark
            return mark

    def release(self, ip: str) -> None:
        with self._lock:
            mark = self._used.pop(ip, None)
            if mark is not None:
                self._available.insert(0, mark)
