"""Snapshot helpers for reversible network-state changes."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional

from netshaper import config


@dataclass
class NetworkStateSnapshot:
    session_id: str
    interface: str
    ipv4_forwarding: Optional[int]
    ipv6_forwarding: Optional[int]
    route_localnet: Optional[int]
    iptables_rules: str
    ip6tables_rules: str
    tc_configuration: str


class StateSnapshotManager:
    """Capture and restore the pre-session network state for safer cleanup."""

    @staticmethod
    def _run(args: list[str]) -> str:
        try:
            completed = subprocess.run(args, capture_output=True, text=True, check=False)
            return completed.stdout.strip() if completed.returncode == 0 else ""
        except FileNotFoundError:
            return ""

    @staticmethod
    def _parse_optional_int(value: str) -> Optional[int]:
        if value == "":
            return None
        try:
            return int(value)
        except ValueError:
            return None

    @classmethod
    def restore(cls, snapshot: NetworkStateSnapshot,
                restore_firewall: bool = False) -> bool:
        """Restore the captured forwarding and iptables state."""
        ok = True

        def run_command(args: list[str]) -> bool:
            if config.DRY_RUN:
                print(f"[DRY-RUN] {' '.join(str(a) for a in args)}", flush=True)
                return True
            try:
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                return result.returncode == 0
            except FileNotFoundError:
                return False

        if snapshot.ipv4_forwarding is not None:
            ok = run_command(
                ["sysctl", "-w", f"net.ipv4.ip_forward={snapshot.ipv4_forwarding}"],
            ) and ok
        if snapshot.ipv6_forwarding is not None:
            ok = run_command(
                ["sysctl", "-w", f"net.ipv6.conf.all.forwarding={snapshot.ipv6_forwarding}"],
            ) and ok
        if snapshot.route_localnet is not None:
            ok = run_command(
                [
                    "sysctl", "-w",
                    f"net.ipv4.conf.{snapshot.interface}.route_localnet={snapshot.route_localnet}",
                ],
            ) and ok

        if restore_firewall:
            for binary, rules in (
                    ("iptables", snapshot.iptables_rules),
                    ("ip6tables", snapshot.ip6tables_rules),
            ):
                if rules and rules.strip():
                    if config.DRY_RUN:
                        print(f"[DRY-RUN] {binary}-restore < snapshot", flush=True)
                        continue
                    try:
                        result = subprocess.run(
                            [f"{binary}-restore"],
                            input=rules,
                            text=True,
                            check=False,
                        )
                    except FileNotFoundError:
                        ok = False
                    else:
                        ok = result.returncode == 0 and ok
        return ok

    @classmethod
    def capture(cls, interface: str, session_id: str) -> NetworkStateSnapshot:
        ipv4_forwarding = cls._parse_optional_int(
            cls._run(["sysctl", "-n", "net.ipv4.ip_forward"])
        )
        ipv6_forwarding = cls._parse_optional_int(
            cls._run(["sysctl", "-n", "net.ipv6.conf.all.forwarding"])
        )
        route_localnet = cls._parse_optional_int(
            cls._run(["sysctl", "-n", f"net.ipv4.conf.{interface}.route_localnet"])
        )

        return NetworkStateSnapshot(
            session_id=session_id,
            interface=interface,
            ipv4_forwarding=ipv4_forwarding,
            ipv6_forwarding=ipv6_forwarding,
            route_localnet=route_localnet,
            iptables_rules=cls._run(["iptables-save"]),
            ip6tables_rules=cls._run(["ip6tables-save"]),
            tc_configuration=cls._run(["tc", "qdisc", "show", "dev", interface]),
        )
