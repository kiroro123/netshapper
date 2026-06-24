"""
NetShaper — Linux tc HTB traffic shaper.
"""
import logging
from dataclasses import dataclass
from typing import Callable, List, Optional, Set, Tuple

from netshaper.system import (
    InspectionResult,
    InspectionStatus,
    SubprocessRunner,
    inspect_resource,
)

log = logging.getLogger("netshaper")


@dataclass(frozen=True)
class ShapingProfile:
    """Validated bandwidth and network-impairment settings."""

    bandwidth_mbps: Optional[float] = None
    latency_ms: int = 0
    jitter_ms: int = 0
    loss_percent: float = 0.0
    corruption_percent: float = 0.0
    duplicate_percent: float = 0.0
    reorder_percent: float = 0.0

    def __post_init__(self) -> None:
        if (
                self.bandwidth_mbps is not None
                and not 0.1 <= self.bandwidth_mbps <= 1000):
            raise ValueError("bandwidth_mbps must be between 0.1 and 1000")
        if not 0 <= self.latency_ms <= 60_000:
            raise ValueError("latency_ms must be between 0 and 60000")
        if not 0 <= self.jitter_ms <= 60_000:
            raise ValueError("jitter_ms must be between 0 and 60000")
        for name in (
                "loss_percent",
                "corruption_percent",
                "duplicate_percent",
                "reorder_percent"):
            value = getattr(self, name)
            if not 0 <= value <= 100:
                raise ValueError(f"{name} must be between 0 and 100")
        if self.jitter_ms and not self.latency_ms:
            raise ValueError("jitter_ms requires latency_ms")
        if self.reorder_percent and not self.latency_ms:
            raise ValueError("reorder_percent requires latency_ms")

    @property
    def has_impairments(self) -> bool:
        return any((
            self.latency_ms,
            self.loss_percent,
            self.corruption_percent,
            self.duplicate_percent,
            self.reorder_percent,
        ))

    def netem_arguments(self) -> List[str]:
        args: List[str] = []
        if self.latency_ms:
            args.extend(["delay", f"{self.latency_ms}ms"])
            if self.jitter_ms:
                args.extend([
                    f"{self.jitter_ms}ms",
                    "distribution",
                    "normal",
                ])
        if self.loss_percent:
            args.extend(["loss", f"{self.loss_percent:g}%"])
        if self.corruption_percent:
            args.extend(["corrupt", f"{self.corruption_percent:g}%"])
        if self.duplicate_percent:
            args.extend(["duplicate", f"{self.duplicate_percent:g}%"])
        if self.reorder_percent:
            args.extend(["reorder", f"{self.reorder_percent:g}%"])
        return args


class TrafficShaper:
    def __init__(self, interface: str):
        self.interface         = interface
        self._base_initialized = False
        self._root_qdisc_pending = False
        self._active_marks: Set[int] = set()
        self._target_filters: Set[Tuple[int, str]] = set()
        self._target_qdiscs: Set[int] = set()
        self._target_classes: Set[int] = set()
        self._tracked_mark_bases: Set[int] = set()

    @staticmethod
    def _journal_resource(journal: Optional[Callable[[], bool]]) -> bool:
        if not journal:
            return True
        return journal()

    @staticmethod
    def _is_implicit_root_qdisc(root_qdisc: str) -> bool:
        return root_qdisc.strip().startswith("qdisc noqueue ")

    def _inspect_root_qdisc(self) -> InspectionResult:
        result = inspect_resource(
            ["tc", "qdisc", "show", "dev", self.interface, "root"])
        if (
                result.status == InspectionStatus.PRESENT
                and (
                    not result.stdout.strip()
                    or self._is_implicit_root_qdisc(result.stdout))):
            return InspectionResult(
                InspectionStatus.ABSENT, result.stdout, result.stderr)
        return result

    def _root_qdisc(self) -> str:
        result = self._inspect_root_qdisc()
        if result.status == InspectionStatus.ERROR:
            detail = result.stderr.strip() or result.stdout.strip()
            message = f"Unable to inspect root qdisc on {self.interface}"
            if detail:
                message += f": {detail}"
            raise RuntimeError(message)
        if result.status == InspectionStatus.ABSENT:
            return ""
        return result.stdout.strip()

    def _owned_root_qdisc_status(self) -> InspectionResult:
        result = self._inspect_root_qdisc()
        if result.status != InspectionStatus.PRESENT:
            return result
        if "qdisc htb 1:" not in result.stdout:
            return InspectionResult(
                InspectionStatus.ABSENT, result.stdout, result.stderr)
        return result

    def _clear_root_ownership(self) -> None:
        self._base_initialized = False
        self._root_qdisc_pending = False
        self._active_marks.clear()
        self._target_filters.clear()
        self._target_qdiscs.clear()
        self._target_classes.clear()
        self._tracked_mark_bases.clear()

    def _journal_pending_root(
            self,
            journal: Optional[Callable[[], bool]]) -> bool:
        self._root_qdisc_pending = True
        if self._journal_resource(journal):
            return True
        self._root_qdisc_pending = False
        return False

    def _init_root(self, journal: Optional[Callable[[], bool]] = None) -> None:
        if not self._base_initialized:
            root_qdisc = self._root_qdisc()
            if root_qdisc:
                raise RuntimeError(
                    "Refusing to replace existing root qdisc on "
                    f"{self.interface}: {root_qdisc}"
                )
            if not self._journal_pending_root(journal):
                raise RuntimeError(
                    "Failed to journal pending NetShaper root qdisc on "
                    f"{self.interface}"
                )
            if not SubprocessRunner.run(
                ["tc", "qdisc", "add", "dev", self.interface,
                 "root", "handle", "1:", "htb"]):
                self._root_qdisc_pending = False
                raise RuntimeError(
                    f"Failed to create NetShaper root qdisc on {self.interface}"
                )
            root_status = self._owned_root_qdisc_status()
            if root_status.status is not InspectionStatus.PRESENT:
                self._root_qdisc_pending = False
                detail = root_status.stderr.strip() or root_status.stdout.strip()
                message = (
                    f"Could not verify NetShaper root qdisc on {self.interface}"
                )
                if detail:
                    message += f": {detail}"
                raise RuntimeError(message)
            self._base_initialized = True
            self._root_qdisc_pending = False
            if not self._journal_resource(journal):
                self.cleanup()
                raise RuntimeError(
                    f"Failed to journal NetShaper root qdisc on {self.interface}"
                )

    def apply_target(self, target_ip: str, mbps: Optional[float] = None,
                     mark_base: int = 10,
                     journal: Optional[Callable[[], bool]] = None,
                     profile: Optional[ShapingProfile] = None) -> None:
        if profile is None:
            if mbps is None:
                raise ValueError("mbps or profile is required")
            profile = ShapingProfile(bandwidth_mbps=mbps)
        rate_mbps = (
            profile.bandwidth_mbps
            if profile.bandwidth_mbps is not None
            else mbps
        )
        # HTB requires a class rate even when only netem is requested.
        if rate_mbps is None:
            rate_mbps = 1000.0
        if not 0.1 <= rate_mbps <= 1000:
            raise ValueError("mbps must be between 0.1 and 1000")
        k = int(rate_mbps * 1000)
        self._init_root(journal)
        created_classes: List[int] = []
        created_qdiscs: List[int] = []
        created_filters: List[Tuple[int, str]] = []
        for mark in [mark_base, mark_base + 10]:
            classid = f"1:{mark}"
            if not SubprocessRunner.run(
                ["tc", "class", "add", "dev", self.interface,
                 "parent", "1:", "classid", classid,
                 "htb", "rate", f"{k}kbit", "burst", "15k"]):
                rollback_ok = self._rollback_failed_target(
                    created_filters, created_qdiscs, created_classes)
                message = f"Failed to create traffic class {classid}"
                if not rollback_ok:
                    message += "; rollback incomplete"
                raise RuntimeError(message)
            created_classes.append(mark)
            self._target_classes.add(mark)
            if not self._journal_resource(journal):
                rollback_ok = self._rollback_failed_target(
                    created_filters, created_qdiscs, created_classes)
                message = f"Failed to journal traffic class {classid}"
                if not rollback_ok:
                    message += "; rollback incomplete"
                raise RuntimeError(message)
            if profile.has_impairments:
                if not SubprocessRunner.run(
                    ["tc", "qdisc", "add", "dev", self.interface,
                     "parent", classid, "handle", f"{mark}:",
                     "netem", *profile.netem_arguments()]
                ):
                    rollback_ok = self._rollback_failed_target(
                        created_filters, created_qdiscs, created_classes)
                    message = f"Failed to create netem qdisc for {classid}"
                    if not rollback_ok:
                        message += "; rollback incomplete"
                    raise RuntimeError(message)
                created_qdiscs.append(mark)
                self._target_qdiscs.add(mark)
                if not self._journal_resource(journal):
                    rollback_ok = self._rollback_failed_target(
                        created_filters, created_qdiscs, created_classes)
                    message = f"Failed to journal netem qdisc for {classid}"
                    if not rollback_ok:
                        message += "; rollback incomplete"
                    raise RuntimeError(message)
            for proto in ["ip", "ipv6"]:
                if not SubprocessRunner.run(
                    ["tc", "filter", "add", "dev", self.interface,
                     "parent", "1:", "protocol", proto,
                     "handle", str(mark), "fw", "flowid", classid],
                    silent=True):
                    rollback_ok = self._rollback_failed_target(
                        created_filters, created_qdiscs, created_classes)
                    message = f"Failed to create traffic filter for mark {mark}"
                    if not rollback_ok:
                        message += "; rollback incomplete"
                    raise RuntimeError(message)
                created_filters.append((mark, proto))
                self._target_filters.add((mark, proto))
                if not self._journal_resource(journal):
                    rollback_ok = self._rollback_failed_target(
                        created_filters, created_qdiscs, created_classes)
                    message = f"Failed to journal traffic filter for mark {mark}"
                    if not rollback_ok:
                        message += "; rollback incomplete"
                    raise RuntimeError(message)
        self._tracked_mark_bases.add(mark_base)
        self._active_marks.add(mark_base)
        log.info(
            f"Shaping {target_ip}: {rate_mbps} Mbps "
            f"(netem={'on' if profile.has_impairments else 'off'}, "
            f"marks {mark_base}/{mark_base + 10})")

    def _rollback_failed_target(
            self,
            filters: List[Tuple[int, str]],
            qdiscs: List[int],
            classes: List[int]) -> bool:
        ok = self._rollback_created(filters, qdiscs, classes)
        if self._base_initialized and not self._active_marks:
            ok = self.cleanup() and ok
        return ok

    def _rollback_created(
            self,
            filters: List[Tuple[int, str]],
            qdiscs: List[int],
            classes: List[int]) -> bool:
        ok = True
        for mark, proto in reversed(filters):
            status = self._delete_filter(mark, proto)
            if status in (InspectionStatus.PRESENT, InspectionStatus.ABSENT):
                self._target_filters.discard((mark, proto))
            else:
                ok = False
        for mark in reversed(qdiscs):
            status = self._delete_qdisc(mark)
            if status in (InspectionStatus.PRESENT, InspectionStatus.ABSENT):
                self._target_qdiscs.discard(mark)
            else:
                ok = False
        for mark in reversed(classes):
            status = self._delete_class(mark)
            if status in (InspectionStatus.PRESENT, InspectionStatus.ABSENT):
                self._target_classes.discard(mark)
            else:
                ok = False
        return ok

    def _filter_state(self, mark: int, proto: str) -> InspectionStatus:
        result = inspect_resource(
            ["tc", "filter", "show", "dev", self.interface,
             "parent", "1:", "protocol", proto])
        if result.status != InspectionStatus.PRESENT:
            return result.status
        output = result.stdout.lower()
        markers = (
            f"classid 1:{mark}",
            f"handle {mark} ",
            f"handle 0x{mark:x} ",
        )
        return (
            InspectionStatus.PRESENT
            if any(marker in output for marker in markers)
            else InspectionStatus.ABSENT
        )

    def _class_state(self, mark: int) -> InspectionStatus:
        result = inspect_resource(
            ["tc", "class", "show", "dev", self.interface])
        if result.status != InspectionStatus.PRESENT:
            return result.status
        return (
            InspectionStatus.PRESENT
            if f"1:{mark}" in result.stdout
            else InspectionStatus.ABSENT
        )

    def _qdisc_state(self, mark: int) -> InspectionStatus:
        result = inspect_resource(
            ["tc", "qdisc", "show", "dev", self.interface,
             "parent", f"1:{mark}"])
        if result.status != InspectionStatus.PRESENT:
            return result.status
        output = result.stdout.lower()
        return (
            InspectionStatus.PRESENT
            if f"qdisc netem {mark}:" in output
            else InspectionStatus.ABSENT
        )

    def _delete_filter(self, mark: int, proto: str) -> InspectionStatus:
        if SubprocessRunner.run(
                ["tc", "filter", "del", "dev", self.interface,
                 "parent", "1:", "protocol", proto,
                 "handle", str(mark), "fw"],
                check=False, silent=True):
            return InspectionStatus.PRESENT
        status = self._filter_state(mark, proto)
        if status is InspectionStatus.ABSENT:
            return InspectionStatus.ABSENT
        return InspectionStatus.ERROR

    def _delete_class(self, mark: int) -> InspectionStatus:
        if SubprocessRunner.run(
                ["tc", "class", "del", "dev", self.interface,
                 "classid", f"1:{mark}"],
                check=False, silent=True):
            return InspectionStatus.PRESENT
        status = self._class_state(mark)
        if status is InspectionStatus.ABSENT:
            return InspectionStatus.ABSENT
        return InspectionStatus.ERROR

    def _delete_qdisc(self, mark: int) -> InspectionStatus:
        if SubprocessRunner.run(
                ["tc", "qdisc", "del", "dev", self.interface,
                 "parent", f"1:{mark}", "handle", f"{mark}:", "netem"],
                check=False, silent=True):
            return InspectionStatus.PRESENT
        status = self._qdisc_state(mark)
        if status is InspectionStatus.ABSENT:
            return InspectionStatus.ABSENT
        return InspectionStatus.ERROR

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
        if not hasattr(self, "_target_qdiscs"):
            self._target_qdiscs = set()
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
            status = self._delete_filter(mark, proto)
            if status in (InspectionStatus.PRESENT, InspectionStatus.ABSENT):
                self._target_filters.discard((mark, proto))
            else:
                ok = False
        for mark in sorted(self._target_qdiscs.intersection(expected_classes)):
            status = self._delete_qdisc(mark)
            if status in (InspectionStatus.PRESENT, InspectionStatus.ABSENT):
                self._target_qdiscs.discard(mark)
            else:
                ok = False
        for mark in sorted(self._target_classes.intersection(expected_classes)):
            status = self._delete_class(mark)
            if status in (InspectionStatus.PRESENT, InspectionStatus.ABSENT):
                self._target_classes.discard(mark)
            else:
                ok = False
        remaining = (
            self._target_filters.intersection(expected_filters)
            or self._target_qdiscs.intersection(expected_classes)
            or self._target_classes.intersection(expected_classes)
        )
        if ok and not remaining:
            self._active_marks.discard(mark_base)
            self._tracked_mark_bases.discard(mark_base)
        return ok

    def cleanup(self) -> bool:
        if not self._base_initialized:
            return True
        root_qdisc = self._owned_root_qdisc_status()
        if root_qdisc.status == InspectionStatus.ERROR:
            detail = root_qdisc.stderr.strip() or root_qdisc.stdout.strip()
            if detail:
                log.error(
                    "Unable to inspect NetShaper root qdisc on %s: %s",
                    self.interface,
                    detail,
                )
            else:
                log.error(
                    "Unable to inspect NetShaper root qdisc on %s",
                    self.interface,
                )
            return False
        if root_qdisc.status == InspectionStatus.ABSENT:
            self._clear_root_ownership()
            return True
        ok = SubprocessRunner.run(
            ["tc", "qdisc", "del", "dev", self.interface, "root"],
            check=False, silent=True)
        if ok:
            self._clear_root_ownership()
        return ok
