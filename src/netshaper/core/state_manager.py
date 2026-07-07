"""Snapshot helpers for reversible network-state changes."""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404
import tempfile
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
    """Capture and restore pre-session network state.

    Routine cleanup restores forwarding sysctls only. Full firewall snapshots
    are retained solely for explicit emergency recovery because replaying them
    can overwrite legitimate firewall changes made by other software while a
    NetShaper session was active. ``tc_configuration`` is captured as evidence
    for operators and recovery logs; it is not replayed.
    """

    @staticmethod
    def atomic_write_json(path: str, data: object) -> None:
        directory = os.path.dirname(path)
        tmp_path: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                dir=directory,
                delete=False,
                encoding="utf-8",
            ) as handle:
                json.dump(data, handle)
                handle.flush()
                os.fsync(handle.fileno())
                tmp_path = handle.name
            os.replace(tmp_path, path)
            dir_fd = os.open(directory, os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception:
            if tmp_path is not None and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise

    @staticmethod
    def _run(args: list[str]) -> str:
        try:
            # subprocess uses shell=False with pre-validated system commands.
            completed = subprocess.run(args, capture_output=True, text=True, check=False)  # nosec B603
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

    @staticmethod
    def snapshot_from_state(data: dict) -> NetworkStateSnapshot:
        snapshot = data.get("snapshot") or data
        return NetworkStateSnapshot(
            session_id=snapshot.get("session_id") or data.get("session_id", ""),
            interface=snapshot.get("interface") or data.get("interface", ""),
            ipv4_forwarding=snapshot.get("ipv4_forwarding"),
            ipv6_forwarding=snapshot.get("ipv6_forwarding"),
            route_localnet=snapshot.get("route_localnet"),
            iptables_rules=snapshot.get("iptables_rules", ""),
            ip6tables_rules=snapshot.get("ip6tables_rules", ""),
            tc_configuration=snapshot.get("tc_configuration", ""),
        )

    @classmethod
    def restore_from_state_file(
            cls,
            path: str,
            *,
            restore_firewall: bool = False) -> bool:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return cls.restore(
            cls.snapshot_from_state(data),
            restore_firewall=restore_firewall,
        )

    @classmethod
    def restore(cls, snapshot: NetworkStateSnapshot,
                restore_firewall: bool = False) -> bool:
        """Restore forwarding sysctls, and optionally full firewall snapshots."""
        ok = True

        def run_command(args: list[str]) -> bool:
            if config.DRY_RUN:
                print(f"[DRY-RUN] {' '.join(str(a) for a in args)}", flush=True)
                return True
            try:
                # subprocess uses shell=False with args from state file audit trail.
                result = subprocess.run(  # nosec B603
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
                        # subprocess uses shell=False with iptables/ip6tables restore.
                        result = subprocess.run(  # nosec B603
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
