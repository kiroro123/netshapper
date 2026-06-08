"""
NetShaper — Linux tc HTB traffic shaper.
"""
import logging
import subprocess
from typing import List, Set, Tuple

from netshaper.system import SubprocessRunner

log = logging.getLogger("netshaper")


class TrafficShaper:
    def __init__(self, interface: str):
        self.interface         = interface
        self._base_initialized = False
        self._active_marks: Set[int] = set()
        self._target_filters: Set[Tuple[int, str]] = set()
        self._target_classes: Set[int] = set()
        self._tracked_mark_bases: Set[int] = set()

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
        created_classes: List[int] = []
        created_filters: List[Tuple[int, str]] = []
        for mark in [mark_base, mark_base + 10]:
            classid = f"1:{mark}"
            if not SubprocessRunner.run(
                ["tc", "class", "add", "dev", self.interface,
                 "parent", "1:", "classid", classid,
                 "htb", "rate", f"{k}kbit", "burst", "15k"]):
                rollback_ok = self._rollback_failed_target(
                    created_filters, created_classes)
                message = f"Failed to create traffic class {classid}"
                if not rollback_ok:
                    message += "; rollback incomplete"
                raise RuntimeError(message)
            created_classes.append(mark)
            self._target_classes.add(mark)
            for proto in ["ip", "ipv6"]:
                if not SubprocessRunner.run(
                    ["tc", "filter", "add", "dev", self.interface,
                     "parent", "1:", "protocol", proto,
                     "handle", str(mark), "fw", "flowid", classid],
                    silent=True):
                    rollback_ok = self._rollback_failed_target(
                        created_filters, created_classes)
                    message = f"Failed to create traffic filter for mark {mark}"
                    if not rollback_ok:
                        message += "; rollback incomplete"
                    raise RuntimeError(message)
                created_filters.append((mark, proto))
                self._target_filters.add((mark, proto))
        self._tracked_mark_bases.add(mark_base)
        self._active_marks.add(mark_base)
        log.info(
            f"Shaping {target_ip}: {mbps} Mbps "
            f"(marks {mark_base}/{mark_base + 10})")

    def _rollback_failed_target(
            self,
            filters: List[Tuple[int, str]],
            classes: List[int]) -> bool:
        ok = self._rollback_created(filters, classes)
        if self._base_initialized and not self._active_marks:
            ok = self.cleanup() and ok
        return ok

    def _rollback_created(
            self,
            filters: List[Tuple[int, str]],
            classes: List[int]) -> bool:
        ok = True
        for mark, proto in reversed(filters):
            if self._delete_filter(mark, proto):
                self._target_filters.discard((mark, proto))
            else:
                ok = False
        for mark in reversed(classes):
            if self._delete_class(mark):
                self._target_classes.discard(mark)
            else:
                ok = False
        return ok

    def _delete_filter(self, mark: int, proto: str) -> bool:
        return SubprocessRunner.run(
            ["tc", "filter", "del", "dev", self.interface,
             "parent", "1:", "protocol", proto,
             "handle", str(mark), "fw"],
            check=False, silent=True)

    def _delete_class(self, mark: int) -> bool:
        return SubprocessRunner.run(
            ["tc", "class", "del", "dev", self.interface,
             "classid", f"1:{mark}"],
            check=False, silent=True)

    def cleanup_target(self, mark_base: int) -> bool:
        ok = True
        expected_filters = {
            (mark, proto)
            for mark in [mark_base, mark_base + 10]
            for proto in ["ip", "ipv6"]
        }
        expected_classes = {mark_base, mark_base + 10}
        if not hasattr(self, "_target_filters"):
            self._target_filters = set()
        if not hasattr(self, "_target_classes"):
            self._target_classes = set()
        if not hasattr(self, "_tracked_mark_bases"):
            self._tracked_mark_bases = set()
        if (
                mark_base in self._active_marks
                and mark_base not in self._tracked_mark_bases
                and not self._target_filters.intersection(expected_filters)
                and not self._target_classes.intersection(expected_classes)):
            self._target_filters.update(expected_filters)
            self._target_classes.update(expected_classes)
            self._tracked_mark_bases.add(mark_base)
        for mark, proto in sorted(
                self._target_filters.intersection(expected_filters)):
            if self._delete_filter(mark, proto):
                self._target_filters.discard((mark, proto))
            else:
                ok = False
        for mark in sorted(self._target_classes.intersection(expected_classes)):
            if self._delete_class(mark):
                self._target_classes.discard(mark)
            else:
                ok = False
        remaining = (
            self._target_filters.intersection(expected_filters)
            or self._target_classes.intersection(expected_classes)
        )
        if ok and not remaining:
            self._active_marks.discard(mark_base)
            self._tracked_mark_bases.discard(mark_base)
        return ok

    def cleanup(self) -> bool:
        if not self._base_initialized:
            return True
        ok = SubprocessRunner.run(
            ["tc", "qdisc", "del", "dev", self.interface, "root"],
            check=False, silent=True)
        if ok:
            self._base_initialized = False
            self._active_marks.clear()
            self._target_filters.clear()
            self._target_classes.clear()
            self._tracked_mark_bases.clear()
        return ok
