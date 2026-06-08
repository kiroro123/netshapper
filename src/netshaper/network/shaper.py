"""
NetShaper — Linux tc HTB traffic shaper.
"""
import logging
import subprocess
from typing import Set

from netshaper.system import SubprocessRunner

log = logging.getLogger("netshaper")


class TrafficShaper:
    def __init__(self, interface: str):
        self.interface         = interface
        self._base_initialized = False
        self._active_marks: Set[int] = set()

    def _root_qdisc(self) -> str:
        try:
            result = subprocess.run(
                ["tc", "qdisc", "show", "dev", self.interface, "root"],
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return ""
        return result.stdout.strip() if result.returncode == 0 else ""

    def _init_root(self) -> None:
        if not self._base_initialized:
            root_qdisc = self._root_qdisc()
            if root_qdisc:
                raise RuntimeError(
                    "Refusing to replace existing root qdisc on "
                    f"{self.interface}: {root_qdisc}"
                )
            if not SubprocessRunner.run(
                ["tc", "qdisc", "add", "dev", self.interface,
                 "root", "handle", "1:", "htb"]):
                raise RuntimeError(
                    f"Failed to create NetShaper root qdisc on {self.interface}"
                )
            self._base_initialized = True

    def apply_target(self, target_ip: str, mbps: float,
                     mark_base: int = 10) -> None:
        k = int(mbps * 1000)
        self._init_root()
        for mark in [mark_base, mark_base + 10]:
            classid = f"1:{mark}"
            SubprocessRunner.run(
                ["tc", "class", "add", "dev", self.interface,
                 "parent", "1:", "classid", classid,
                 "htb", "rate", f"{k}kbit", "burst", "15k"])
            for proto in ["ip", "ipv6"]:
                SubprocessRunner.run(
                    ["tc", "filter", "add", "dev", self.interface,
                     "parent", "1:", "protocol", proto,
                     "handle", str(mark), "fw", "flowid", classid],
                    silent=True)
        self._active_marks.add(mark_base)
        log.info(
            f"Shaping {target_ip}: {mbps} Mbps "
            f"(marks {mark_base}/{mark_base + 10})")

    def cleanup_target(self, mark_base: int) -> None:
        for mark in [mark_base, mark_base + 10]:
            SubprocessRunner.run(
                ["tc", "filter", "del", "dev", self.interface,
                 "parent", "1:", "handle", str(mark), "fw"],
                check=False, silent=True)
            SubprocessRunner.run(
                ["tc", "class", "del", "dev", self.interface,
                 "classid", f"1:{mark}"],
                check=False, silent=True)
        self._active_marks.discard(mark_base)

    def cleanup(self) -> None:
        if self._base_initialized:
            SubprocessRunner.run(
                ["tc", "qdisc", "del", "dev", self.interface, "root"],
                check=False, silent=True)
        self._base_initialized = False
        self._active_marks.clear()
