"""
NetShaper — session-owned forwarding and NAT lifecycle management.

The manager creates one filter chain per address family and adds forwarding
and IPv4 NAT resources only for explicitly authorized targets.  Every
resource is journaled before mutation and verified after creation/deletion.
"""
from __future__ import annotations

import hashlib
from ipaddress import ip_address
import logging
import re
import shutil
from typing import Callable, List, Literal, Optional, TypedDict

from netshaper import config
from netshaper.exceptions import NetShaperError
from netshaper.system import InspectionStatus, SubprocessRunner, inspect_resource

log = logging.getLogger("netshaper")

_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
_SESSION_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

ResourceKind = Literal["chain", "rule"]
ResourceState = Literal["pending", "active", "delete_pending"]


class FirewallResource(TypedDict):
    """Persisted ownership record for one exact firewall resource."""

    resource_id: str
    kind: ResourceKind
    state: ResourceState
    binary: str
    description: str
    target_ip: Optional[str]
    apply: List[str]
    check: List[str]
    delete: List[str]


class FirewallError(NetShaperError):
    """Raised when firewall operations fail."""


class FirewallManager:
    """Manage session forwarding resources with target-level ownership."""

    FIREWALL_FORMAT = 2

    def __init__(
        self,
        interface: str,
        session_id: str,
        journal: Optional[Callable[[], bool]] = None,
        target_authorizer: Optional[Callable[[str], None]] = None,
    ):
        if interface and not _INTERFACE_RE.fullmatch(interface):
            raise ValueError(f"invalid network interface {interface!r}")
        if session_id and not _SESSION_RE.fullmatch(session_id):
            raise ValueError(f"invalid NetShaper session ID {session_id!r}")
        self.interface = interface
        self.session_id = session_id
        self._journal = journal
        self._target_authorizer = target_authorizer
        self._global_rules_applied = False
        self._global_firewall_binaries_applied: List[str] = []
        self._global_rules_created: List[FirewallResource] = []

    def _global_rule_comment(self) -> str:
        return f"netshaper:{self.session_id}:forward"

    def _forward_chain(self) -> str:
        digest = hashlib.sha256(self.session_id.encode("utf-8")).hexdigest()[:12]
        return f"NS-FWD-{digest.upper()}"

    @staticmethod
    def _inspect_rule(command: List[str]) -> InspectionStatus:
        return inspect_resource(command).status

    @staticmethod
    def _resource_id(check: List[str]) -> str:
        digest = hashlib.sha256("\0".join(check).encode("utf-8")).hexdigest()[:16]
        return f"firewall:{digest}"

    @classmethod
    def _resource(
        cls,
        *,
        kind: ResourceKind,
        binary: str,
        description: str,
        target_ip: Optional[str],
        apply: List[str],
        check: List[str],
        delete: List[str],
    ) -> FirewallResource:
        return {
            "resource_id": cls._resource_id(check),
            "kind": kind,
            "state": "pending",
            "binary": binary,
            "description": description,
            "target_ip": target_ip,
            "apply": apply,
            "check": check,
            "delete": delete,
        }

    def _shared_resource_specs(self, binary: str) -> List[FirewallResource]:
        chain = self._forward_chain()
        jump_comment = f"{self._global_rule_comment()}:jump"
        return_comment = f"{self._global_rule_comment()}:return"
        jump_args = [
            "-m",
            "comment",
            "--comment",
            jump_comment,
            "-j",
            chain,
        ]
        return_args = [
            "-m",
            "comment",
            "--comment",
            return_comment,
            "-j",
            "RETURN",
        ]
        return [
            self._resource(
                kind="chain",
                binary=binary,
                description=f"{binary} session forwarding chain {chain}",
                target_ip=None,
                apply=[binary, "-t", "filter", "-N", chain],
                check=[binary, "-t", "filter", "-L", chain],
                delete=[binary, "-t", "filter", "-X", chain],
            ),
            self._resource(
                kind="rule",
                binary=binary,
                description=f"{binary} session forwarding jump",
                target_ip=None,
                apply=[
                    binary,
                    "-t",
                    "filter",
                    "-I",
                    "FORWARD",
                    "1",
                    *jump_args,
                ],
                check=[
                    binary,
                    "-t",
                    "filter",
                    "-C",
                    "FORWARD",
                    *jump_args,
                ],
                delete=[
                    binary,
                    "-t",
                    "filter",
                    "-D",
                    "FORWARD",
                    *jump_args,
                ],
            ),
            self._resource(
                kind="rule",
                binary=binary,
                description=f"{binary} session forwarding return",
                target_ip=None,
                apply=[
                    binary,
                    "-t",
                    "filter",
                    "-A",
                    chain,
                    *return_args,
                ],
                check=[
                    binary,
                    "-t",
                    "filter",
                    "-C",
                    chain,
                    *return_args,
                ],
                delete=[
                    binary,
                    "-t",
                    "filter",
                    "-D",
                    chain,
                    *return_args,
                ],
            ),
        ]

    def _target_resource_specs(
        self,
        binary: str,
        target_ip: str,
    ) -> List[FirewallResource]:
        chain = self._forward_chain()
        target_comment = (
            f"netshaper:{self.session_id}:target:{target_ip}"
        )
        outbound_args = [
            "-i",
            self.interface,
            "-s",
            target_ip,
            "-m",
            "comment",
            "--comment",
            f"{target_comment}:out",
            "-j",
            "ACCEPT",
        ]
        return_args = [
            "-o",
            self.interface,
            "-d",
            target_ip,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-m",
            "comment",
            "--comment",
            f"{target_comment}:return",
            "-j",
            "ACCEPT",
        ]
        resources = [
            self._resource(
                kind="rule",
                binary=binary,
                description=f"{binary} outbound forwarding for {target_ip}",
                target_ip=target_ip,
                apply=[
                    binary,
                    "-t",
                    "filter",
                    "-I",
                    chain,
                    "1",
                    *outbound_args,
                ],
                check=[
                    binary,
                    "-t",
                    "filter",
                    "-C",
                    chain,
                    *outbound_args,
                ],
                delete=[
                    binary,
                    "-t",
                    "filter",
                    "-D",
                    chain,
                    *outbound_args,
                ],
            ),
            self._resource(
                kind="rule",
                binary=binary,
                description=f"{binary} return forwarding for {target_ip}",
                target_ip=target_ip,
                apply=[
                    binary,
                    "-t",
                    "filter",
                    "-I",
                    chain,
                    "1",
                    *return_args,
                ],
                check=[
                    binary,
                    "-t",
                    "filter",
                    "-C",
                    chain,
                    *return_args,
                ],
                delete=[
                    binary,
                    "-t",
                    "filter",
                    "-D",
                    chain,
                    *return_args,
                ],
            ),
        ]
        if binary == "iptables":
            nat_args = [
                "-s",
                target_ip,
                "-o",
                self.interface,
                "-m",
                "comment",
                "--comment",
                f"{target_comment}:nat",
                "-j",
                "MASQUERADE",
            ]
            resources.append(
                self._resource(
                    kind="rule",
                    binary=binary,
                    description=f"{binary} source NAT for {target_ip}",
                    target_ip=target_ip,
                    apply=[
                        binary,
                        "-t",
                        "nat",
                        "-A",
                        "POSTROUTING",
                        *nat_args,
                    ],
                    check=[
                        binary,
                        "-t",
                        "nat",
                        "-C",
                        "POSTROUTING",
                        *nat_args,
                    ],
                    delete=[
                        binary,
                        "-t",
                        "nat",
                        "-D",
                        "POSTROUTING",
                        *nat_args,
                    ],
                )
            )
        return resources

    def _journal_state(self) -> bool:
        if self._journal is None:
            return False
        try:
            return self._journal()
        except Exception as exc:
            log.error("Firewall journal callback failed: %s", exc)
            return False

    def _refresh_summary(self) -> None:
        binaries: List[str] = []
        for record in self._global_rules_created:
            binary = record["binary"]
            if binary not in binaries:
                binaries.append(binary)
        self._global_firewall_binaries_applied = binaries
        self._global_rules_applied = bool(self._global_rules_created)

    def _record_intent(self, record: FirewallResource) -> None:
        self._global_rules_created.append(record)
        self._refresh_summary()
        if not self._journal_state():
            self._global_rules_created.remove(record)
            self._refresh_summary()
            raise FirewallError(
                f"Could not persist recovery intent for {record['description']}"
            )

    def _create_resource(self, record: FirewallResource) -> None:
        initial = self._inspect_rule(record["check"])
        if initial is InspectionStatus.ERROR:
            raise FirewallError(
                f"Could not inspect {record['description']} before creation"
            )
        if initial is InspectionStatus.PRESENT:
            raise FirewallError(
                f"Refusing to adopt pre-existing {record['description']}"
            )

        self._record_intent(record)
        command_ok = SubprocessRunner.run(record["apply"], silent=True)
        verified = (
            InspectionStatus.PRESENT
            if config.DRY_RUN and command_ok
            else self._inspect_rule(record["check"])
        )
        if not command_ok or verified is not InspectionStatus.PRESENT:
            raise FirewallError(
                f"Could not create and verify {record['description']}"
            )

        record["state"] = "active"
        if not self._journal_state():
            raise FirewallError(
                f"Could not confirm ownership of {record['description']}"
            )

    def _remove_record(self, record: FirewallResource) -> bool:
        try:
            index = self._global_rules_created.index(record)
        except ValueError:
            return True

        status = self._inspect_rule(record["check"])
        if status is InspectionStatus.ERROR:
            log.error("Cannot inspect firewall resource: %s", record["description"])
            return False

        if status is InspectionStatus.PRESENT:
            previous_state = record["state"]
            record["state"] = "delete_pending"
            if not self._journal_state():
                record["state"] = previous_state
                return False
            SubprocessRunner.run(record["delete"], check=False, silent=True)
            status = (
                InspectionStatus.ABSENT
                if config.DRY_RUN
                else self._inspect_rule(record["check"])
            )
            if status is not InspectionStatus.ABSENT:
                if status is InspectionStatus.ERROR:
                    log.error(
                        "Cannot verify firewall resource deletion: %s",
                        record["description"],
                    )
                else:
                    log.error(
                        "Firewall resource remained after deletion: %s",
                        record["description"],
                    )
                return False

        self._global_rules_created.pop(index)
        self._refresh_summary()
        if not self._journal_state():
            record["state"] = "delete_pending"
            self._global_rules_created.insert(index, record)
            self._refresh_summary()
            return False
        return True

    def _records_for_binary(
        self,
        binary: str,
        *,
        target_ip: Optional[str],
    ) -> List[FirewallResource]:
        return [
            record
            for record in self._global_rules_created
            if record["binary"] == binary
            and record.get("target_ip") == target_ip
        ]

    def _ensure_shared_resources(self, binary: str) -> None:
        existing = self._records_for_binary(binary, target_ip=None)
        expected = self._shared_resource_specs(binary)
        if existing:
            expected_ids = {record["resource_id"] for record in expected}
            existing_ids = {record["resource_id"] for record in existing}
            if (
                existing_ids != expected_ids
                or any(record["state"] != "active" for record in existing)
            ):
                raise FirewallError(
                    f"Incomplete session forwarding resources for {binary}"
                )
            return
        for record in expected:
            self._create_resource(record)

    def _normalize_and_authorize_target(self, raw_target_ip: str) -> str:
        try:
            target_ip = str(ip_address(raw_target_ip))
        except ValueError as exc:
            raise FirewallError(f"Invalid forwarding target {raw_target_ip!r}") from exc
        if self._target_authorizer is None:
            raise FirewallError(
                "No authorization policy is attached to the firewall manager"
            )
        self._target_authorizer(target_ip)
        return target_ip

    def apply_global_rules(self) -> None:
        """Enable forwarding sysctls after durable recovery state exists.

        Firewall ACCEPT and NAT rules are deliberately not installed here;
        they are created by :meth:`add_target_rules` for one authorized target.
        """
        if not self._journal_state():
            raise FirewallError(
                "Could not persist recovery state before enabling forwarding"
            )
        commands = [
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
            ["sysctl", "-w", f"net.ipv4.conf.{self.interface}.route_localnet=1"],
        ]
        if not all(SubprocessRunner.run(command, silent=True) for command in commands):
            raise FirewallError("Failed to enable forwarding sysctls")
        log.info("Forwarding sysctls enabled; no target firewall scope added")

    def add_target_rules(self, raw_target_ip: str) -> None:
        """Add forwarding and version-valid NAT for one authorized target."""
        target_ip = self._normalize_and_authorize_target(raw_target_ip)
        binary = "ip6tables" if ":" in target_ip else "iptables"
        if not config.DRY_RUN and not shutil.which(binary):
            raise FirewallError(f"{binary} is unavailable")
        if self._records_for_binary(binary, target_ip=target_ip):
            raise FirewallError(f"Forwarding target {target_ip} is already tracked")

        try:
            self._ensure_shared_resources(binary)
            for record in self._target_resource_specs(binary, target_ip):
                self._create_resource(record)
        except Exception as exc:
            rollback_ok = self.remove_target_rules(target_ip)
            message = f"Failed to add forwarding resources for {target_ip}"
            if not rollback_ok:
                message += "; rollback incomplete"
            raise FirewallError(message) from exc
        log.info("Target-scoped forwarding resources added for %s", target_ip)

    def remove_target_rules(self, raw_target_ip: str) -> bool:
        """Remove exactly one target's resources and empty family chain."""
        try:
            target_ip = str(ip_address(raw_target_ip))
        except ValueError:
            log.error("Cannot remove invalid forwarding target %r", raw_target_ip)
            return False
        binary = "ip6tables" if ":" in target_ip else "iptables"
        if not config.DRY_RUN and not shutil.which(binary):
            if any(
                record["binary"] == binary
                for record in self._global_rules_created
            ):
                log.error("%s unavailable for forwarding cleanup", binary)
                return False
            return True

        target_records = self._records_for_binary(
            binary,
            target_ip=target_ip,
        )
        for record in reversed(target_records):
            if not self._remove_record(record):
                return False

        other_targets = any(
            record["binary"] == binary
            and record.get("target_ip") is not None
            for record in self._global_rules_created
        )
        if not other_targets:
            for record in reversed(
                self._records_for_binary(binary, target_ip=None)
            ):
                if not self._remove_record(record):
                    return False
        return True

    def remove_global_rules(self) -> bool:
        """Remove every persisted session-owned forwarding resource."""
        for record in reversed(list(self._global_rules_created)):
            binary = record["binary"]
            if not config.DRY_RUN and not shutil.which(binary):
                log.error(
                    "Cannot remove firewall resource: %s unavailable",
                    binary,
                )
                return False
            if not self._remove_record(record):
                return False
        log.info("Session-owned forwarding resources removed")
        return True

    def get_state_for_persistence(self) -> dict[str, object]:
        """Get complete target-scoped firewall ownership state."""
        self._refresh_summary()
        return {
            "global_firewall_format": self.FIREWALL_FORMAT,
            "global_rules_applied": self._global_rules_applied,
            "global_rule_comment": (
                self._global_rule_comment()
                if self._global_rules_applied
                else None
            ),
            "global_forward_chain": self._forward_chain(),
            "global_firewall_binaries": list(
                self._global_firewall_binaries_applied
            ),
            "global_rules_created": [
                {
                    **record,
                    "apply": list(record["apply"]),
                    "check": list(record["check"]),
                    "delete": list(record["delete"]),
                }
                for record in self._global_rules_created
            ],
        }
