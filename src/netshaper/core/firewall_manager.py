"""
NetShaper — Firewall rule lifecycle management.

Handles iptables/ip6tables rules for global forwarding and per-target interception.
Independently auditable and testable.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from typing import List, Optional

from netshaper import config
from netshaper.system import InspectionStatus, SubprocessRunner, inspect_resource

log = logging.getLogger("netshaper")


class FirewallError(RuntimeError):
    """Raised when firewall operations fail."""
    pass


class FirewallManager:
    """
    Manages iptables/ip6tables lifecycle for a session.
    Tracks applied rules and supports cleanup/rollback.
    """

    def __init__(self, interface: str, session_id: str):
        """
        Initialize firewall manager for an interface.
        
        Args:
            interface: Network interface name
            session_id: Session ID for rule comments
        """
        self.interface = interface
        self.session_id = session_id
        self._global_rules_applied = False
        self._global_firewall_binaries_applied: List[str] = []
        self._global_rules_created: List[dict] = []

    def _global_rule_comment(self) -> str:
        """Unique comment for firewall rules in this session."""
        return f"netshaper:{self.session_id}:global"

    @staticmethod
    def _global_firewall_rule_specs(
        binary: str,
        iface: str,
        comment: Optional[str],
    ) -> List[dict]:
        """Generate rule specifications for global forwarding."""
        comment_args = (
            ["-m", "comment", "--comment", comment] if comment else []
        )
        return [
            {
                "description": f"{binary} forward same-interface accept",
                "apply": [
                    binary,
                    "-I",
                    "FORWARD",
                    "1",
                    "-i",
                    iface,
                    "-o",
                    iface,
                    *comment_args,
                    "-j",
                    "ACCEPT",
                ],
                "delete": [
                    binary,
                    "-D",
                    "FORWARD",
                    "-i",
                    iface,
                    "-o",
                    iface,
                    *comment_args,
                    "-j",
                    "ACCEPT",
                ],
                "check": [
                    binary,
                    "-C",
                    "FORWARD",
                    "-i",
                    iface,
                    "-o",
                    iface,
                    *comment_args,
                    "-j",
                    "ACCEPT",
                ],
            },
            {
                "description": f"{binary} established forward accept",
                "apply": [
                    binary,
                    "-I",
                    "FORWARD",
                    "1",
                    "-m",
                    "state",
                    "--state",
                    "ESTABLISHED,RELATED",
                    *comment_args,
                    "-j",
                    "ACCEPT",
                ],
                "delete": [
                    binary,
                    "-D",
                    "FORWARD",
                    "-m",
                    "state",
                    "--state",
                    "ESTABLISHED,RELATED",
                    *comment_args,
                    "-j",
                    "ACCEPT",
                ],
                "check": [
                    binary,
                    "-C",
                    "FORWARD",
                    "-m",
                    "state",
                    "--state",
                    "ESTABLISHED,RELATED",
                    *comment_args,
                    "-j",
                    "ACCEPT",
                ],
            },
            {
                "description": f"{binary} masquerade",
                "apply": [
                    binary,
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-o",
                    iface,
                    *comment_args,
                    "-j",
                    "MASQUERADE",
                ],
                "delete": [
                    binary,
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-o",
                    iface,
                    *comment_args,
                    "-j",
                    "MASQUERADE",
                ],
                "check": [
                    binary,
                    "-t",
                    "nat",
                    "-C",
                    "POSTROUTING",
                    "-o",
                    iface,
                    *comment_args,
                    "-j",
                    "MASQUERADE",
                ],
            },
        ]

    @staticmethod
    def _inspect_rule(command: List[str]) -> InspectionStatus:
        """Check if a firewall rule exists."""
        return inspect_resource(command).status

    @staticmethod
    def _target_input_rule_spec(
        binary: str,
        iface: str,
        ip: str,
        proto: str,
        port: int,
        comment: Optional[str],
    ) -> dict:
        """Generate rule specification for per-target INPUT rules."""
        comment_args = (
            ["-m", "comment", "--comment", comment] if comment else []
        )
        base = [
            "-i",
            iface,
            "-s",
            ip,
            "-p",
            proto,
            "--dport",
            str(port),
            *comment_args,
            "-j",
            "ACCEPT",
        ]
        return {
            "delete": [binary, "-D", "INPUT", *base],
            "check": [binary, "-C", "INPUT", *base],
        }

    def apply_global_rules(self) -> None:
        """Apply global forwarding rules to the interface."""
        if self._global_rules_applied:
            return

        ok = True
        comment = self._global_rule_comment()

        # Apply sysctl settings
        for command in [
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
            ["sysctl", "-w", f"net.ipv4.conf.{self.interface}.route_localnet=1"],
        ]:
            if SubprocessRunner.run(command, silent=True):
                ok = ok and True
            else:
                ok = False

        # Apply firewall rules
        for binary in ["iptables", "ip6tables"]:
            if shutil.which(binary):
                for spec in self._global_firewall_rule_specs(
                    binary, self.interface, comment
                ):
                    if SubprocessRunner.run(spec["apply"], silent=True):
                        self._record_global_rule(binary, spec)
                    else:
                        ok = False

        if not ok:
            raise FirewallError("Failed to apply global forwarding rules")

        self._global_rules_applied = True
        log.info("Global dual-stack forwarding + MASQUERADE enabled")

    def _record_global_rule(self, binary: str, spec: dict) -> None:
        """Record a global rule for later cleanup."""
        record = {
            "binary": binary,
            "description": spec["description"],
            "delete": spec["delete"],
            "check": spec["check"],
        }
        self._global_rules_created.append(record)
        if binary not in self._global_firewall_binaries_applied:
            self._global_firewall_binaries_applied.append(binary)

    def _global_rule_records_for_cleanup(self) -> List[dict]:
        """Get all global rules that need cleanup."""
        records = list(self._global_rules_created)
        if records:
            return records

        if not self._global_rules_applied:
            return []

        records = []
        comment = self._global_rule_comment()
        for binary in self._global_firewall_binaries_applied:
            for spec in self._global_firewall_rule_specs(
                binary, self.interface, comment
            ):
                records.append(
                    {
                        "binary": binary,
                        "description": spec["description"],
                        "delete": spec["delete"],
                        "check": spec["check"],
                    }
                )
        return records

    def remove_global_rules(self) -> bool:
        """Remove all global forwarding rules."""
        ok = True
        records = self._global_rule_records_for_cleanup()

        if not records:
            return ok

        for record in list(records):
            binary = record["binary"]
            if not shutil.which(binary):
                if binary in self._global_firewall_binaries_applied:
                    log.error(
                        f"Cannot remove global firewall rules: {binary} unavailable"
                    )
                    ok = False
                continue

            status = self._inspect_rule(record["check"])
            if status is InspectionStatus.ABSENT:
                if record in self._global_rules_created:
                    self._global_rules_created.remove(record)
                continue

            if status is InspectionStatus.ERROR:
                log.error(
                    f"Cannot inspect global firewall rule: "
                    f"{record['description']}"
                )
                ok = False
                continue

            if SubprocessRunner.run(record["delete"], check=False, silent=True):
                if record in self._global_rules_created:
                    self._global_rules_created.remove(record)
            else:
                ok = False

        if ok:
            self._global_rules_applied = False
            self._global_firewall_binaries_applied = []
            self._global_rules_created = []
            log.info("Global forwarding + MASQUERADE removed")

        return ok

    def get_state_for_persistence(self) -> dict:
        """Get firewall state for persistence/recovery."""
        return {
            "global_rules_applied": self._global_rules_applied,
            "global_rule_comment": (
                self._global_rule_comment()
                if self._global_rules_applied
                else None
            ),
            "global_firewall_binaries": list(self._global_firewall_binaries_applied),
            "global_rules_created": list(self._global_rules_created),
        }
