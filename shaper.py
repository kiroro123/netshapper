"""
netshaper.shaper
────────────────
Bandwidth throttling via Linux tc (traffic control) HTB qdiscs.

MarkIDPool   — thread-safe registry of tc mark IDs, prevents collisions
               when targets are removed and re-added mid-session.
TrafficShaper — manages the root HTB qdisc and per-target class/filter
               lifecycle. Depends on MarkIDPool for mark allocation.
"""

import threading
import logging
from typing import Dict, List, Set

from .system import SubprocessRunner

log = logging.getLogger("netshaper")


# ── Mark ID Pool ──────────────────────────────────────────────────────────────

class MarkIDPool:
    """
    Thread-safe registry of tc mark IDs.

    IDs are allocated in steps of `step` so that upstream (mark_base) and
    downstream (mark_base + 10) marks never collide across targets.
    Released IDs are returned to the front of the pool for immediate reuse.
    """

    def __init__(self, start: int = 10, step: int = 20,
                 max_targets: int = 50):
        self._available: List[int] = list(
            range(start, start + step * max_targets, step)
        )
        self._used:  Dict[str, int] = {}
        self._lock   = threading.Lock()

    def acquire(self, ip: str) -> int:
        with self._lock:
            if ip in self._used:
                return self._used[ip]
            if not self._available:
                raise RuntimeError("Mark ID pool exhausted.")
            mark = self._available.pop(0)
            self._used[ip] = mark
            return mark

    def release(self, ip: str):
        with self._lock:
            mark = self._used.pop(ip, None)
            if mark is not None:
                self._available.insert(0, mark)


# ── Traffic Shaper ────────────────────────────────────────────────────────────

class TrafficShaper:
    """
    Manages an HTB root qdisc on the given interface.

    apply_target()  — adds an HTB class + fw filter pair for a mark_base.
    cleanup_target() — removes the class + filter for a single mark_base.
    cleanup()        — tears down the entire root qdisc (used at shutdown).
    """

    def __init__(self, interface: str):
        self.interface          = interface
        self._base_initialized  = False
        self._active_marks: Set[int] = set()

    def _init_root(self):
        """Create the root HTB qdisc once; subsequent calls are no-ops."""
        if not self._base_initialized:
            # Remove any pre-existing root qdisc silently
            SubprocessRunner.run(
                ["tc", "qdisc", "del", "dev", self.interface, "root"],
                check=False, silent=True,
            )
            SubprocessRunner.run(
                ["tc", "qdisc", "add", "dev", self.interface,
                 "root", "handle", "1:", "htb"]
            )
            self._base_initialized = True

    def apply_target(self, target_ip: str, mbps: float,
                     mark_base: int = 10):
        """
        Add HTB class + fw filter for both downstream (mark_base) and
        upstream (mark_base + 10) traffic of a single target.
        """
        kbps = int(mbps * 1000)
        self._init_root()

        for mark in [mark_base, mark_base + 10]:
            classid = f"1:{mark}"
            SubprocessRunner.run(
                ["tc", "class", "add", "dev", self.interface,
                 "parent", "1:", "classid", classid,
                 "htb", "rate", f"{kbps}kbit", "burst", "15k"]
            )
            for proto in ["ip", "ipv6"]:
                SubprocessRunner.run(
                    ["tc", "filter", "add", "dev", self.interface,
                     "parent", "1:", "protocol", proto,
                     "handle", str(mark), "fw", "flowid", classid],
                    silent=True,
                )

        self._active_marks.add(mark_base)
        log.info(
            f"Shaping {target_ip}: {mbps} Mbps "
            f"(marks {mark_base}/{mark_base + 10})"
        )

    def cleanup_target(self, mark_base: int):
        """Remove the HTB class and fw filter for a single mark pair."""
        for mark in [mark_base, mark_base + 10]:
            SubprocessRunner.run(
                ["tc", "filter", "del", "dev", self.interface,
                 "parent", "1:", "handle", str(mark), "fw"],
                check=False, silent=True,
            )
            SubprocessRunner.run(
                ["tc", "class", "del", "dev", self.interface,
                 "classid", f"1:{mark}"],
                check=False, silent=True,
            )
        self._active_marks.discard(mark_base)

    def cleanup(self):
        """Tear down the entire root qdisc — removes all classes and filters."""
        SubprocessRunner.run(
            ["tc", "qdisc", "del", "dev", self.interface, "root"],
            check=False, silent=True,
        )
        self._base_initialized = False
        self._active_marks.clear()
