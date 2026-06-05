"""Snapshot helpers for reversible network-state changes."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class NetworkStateSnapshot:
    session_id: str
    interface: str
    ipv4_forwarding: Optional[int]
    ipv6_forwarding: Optional[int]
    iptables_rules: str
    ip6tables_rules: str
    tc_configuration: str


class StateSnapshotManager:
    """Capture the pre-session network state for safer cleanup."""

    @staticmethod
    def _run(args: list[str]) -> str:
        try:
            completed = subprocess.run(args, capture_output=True, text=True, check=False)
            return completed.stdout.strip() if completed.returncode == 0 else ""
        except FileNotFoundError:
            return ""

    @classmethod
    def capture(cls, interface: str, session_id: str) -> NetworkStateSnapshot:
        ipv4_forwarding = None
        ipv6_forwarding = None

        try:
            ipv4_forwarding = int(cls._run(["sysctl", "-n", "net.ipv4.ip_forward"]) or 0)
        except ValueError:
            ipv4_forwarding = None

        try:
            ipv6_forwarding = int(cls._run(["sysctl", "-n", "net.ipv6.conf.all.forwarding"]) or 0)
        except ValueError:
            ipv6_forwarding = None

        return NetworkStateSnapshot(
            session_id=session_id,
            interface=interface,
            ipv4_forwarding=ipv4_forwarding,
            ipv6_forwarding=ipv6_forwarding,
            iptables_rules=cls._run(["iptables", "-S"]),
            ip6tables_rules=cls._run(["ip6tables", "-S"]),
            tc_configuration=cls._run(["tc", "qdisc", "show", "dev", interface]),
        )
