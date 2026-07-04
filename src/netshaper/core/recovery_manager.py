"""
NetShaper — Stale session recovery and cleanup.

Handles detection and cleanup of abandoned sessions from crashed/orphaned processes.
Independently auditable for safety-critical rollback operations.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
from typing import Any, List, Optional

from netshaper import config
from netshaper.core.state_manager import StateSnapshotManager
from netshaper.system import InspectionStatus, SubprocessRunner, inspect_resource
from netshaper.exceptions import NetShaperError

log = logging.getLogger("netshaper")
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


class RecoveryError(NetShaperError):
    """Raised when recovery operations fail."""
    pass


class RecoveryManager:
    """
    Detects stale sessions (from crashed processes) and cleans up their rules.
    Handles iptables, firewall, traffic shaper, and sysctl restoration.
    """

    def __init__(self, interface: str):
        """
        Initialize recovery manager for an interface.

        Args:
            interface: Network interface name
        """
        self.interface = interface

    @staticmethod
    def _process_start_time(pid: int) -> Optional[str]:
        """Get process start time from /proc/pid/stat."""
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
                return fh.read().split()[21]
        except Exception:
            return None

    @staticmethod
    def _process_is_live(
        pid: Optional[int],
        start_time: Optional[str],
    ) -> bool:
        """Check if a process is still running with the same start time."""
        if not pid or not start_time:
            return False
        current_start = RecoveryManager._process_start_time(pid)
        return current_start == str(start_time)

    @staticmethod
    def _inspect_stale_resource(
        command: List[str],
        *,
        output_contains: Optional[str] = None,
    ) -> InspectionStatus:
        """Check if a stale firewall resource exists."""
        inspection = inspect_resource(command)
        if inspection.status is not InspectionStatus.PRESENT:
            return inspection.status
        if (
            output_contains is not None
            and output_contains not in inspection.stdout
        ):
            return InspectionStatus.ABSENT
        return InspectionStatus.PRESENT

    @staticmethod
    def _target_input_rule_spec(
        binary: str,
        iface: str,
        ip: str,
        proto: str,
        port: int,
        comment: Optional[str],
    ) -> dict[str, Any]:
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

    @staticmethod
    def _global_firewall_rule_specs(
        binary: str,
        iface: str,
        comment: Optional[str],
    ) -> List[dict[str, Any]]:
        """Generate global firewall rule specs for stale cleanup."""
        comment_args = (
            ["-m", "comment", "--comment", comment] if comment else []
        )
        return [
            {
                "description": f"{binary} forward same-interface accept",
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

    def recover_stale_state(self) -> bool:
        """
        Scan for stale sessions and clean them up.

        Returns:
            True if all recoveries succeeded, False if any failed
        """
        if not os.path.isdir(config.STATE_DIR):
            return True

        recovery_ok = True

        import glob

        for state_path in sorted(
            glob.glob(os.path.join(config.STATE_DIR, "*", "state.json"))
        ):
            cleanup_ok = self._cleanup_stale_session(state_path)
            if not cleanup_ok:
                recovery_ok = False

        return recovery_ok

    def _cleanup_stale_session(self, state_path: str) -> bool:
        """Clean up a single stale session file."""
        cleanup_ok = True
        try:
            with open(state_path, encoding="utf-8") as f:
                data = json.load(f)

            iface = data.get("interface")
            if not iface:
                return True

            owner = data.get("owner") or {}
            if self._process_is_live(
                owner.get("pid"), owner.get("process_start_time")
            ):
                log.info(f"Skipping live NetShaper session: {state_path}")
                return False

            log.info(f"[Recovery] Cleaning stale session on {iface}…")

            # Clean global rules
            cleanup_ok = self._cleanup_global_rules(data, iface) and cleanup_ok

            # Clean per-target rules
            cleanup_ok = self._cleanup_target_rules(data, iface) and cleanup_ok

            # Clean traffic shaper
            cleanup_ok = self._cleanup_traffic_shaper(data, iface) and cleanup_ok

            # Restore persistent resources owned by crashed plugins.
            cleanup_ok = self._cleanup_plugins(data) and cleanup_ok

            # Restore sysctl settings
            cleanup_ok = self._restore_sysctl_settings(data) and cleanup_ok

            if cleanup_ok:
                log.info("[Recovery] Stale rules cleaned")
                os.remove(state_path)
                try:
                    os.rmdir(os.path.dirname(state_path))
                except OSError:
                    pass
            else:
                log.error(f"[Recovery] Leaving recovery state in place: {state_path}")

        except Exception as exc:
            cleanup_ok = False
            log.error(f"[Recovery] Could not recover state file {state_path}: {exc}")

        return cleanup_ok

    def _cleanup_global_rules(self, data: dict[str, Any], iface: str) -> bool:
        """Clean global firewall rules from stale session."""
        cleanup_ok = True

        if not data.get("global_rules_applied"):
            return True

        binaries = data.get("global_firewall_binaries") or []
        if not binaries:
            binaries = [
                binary
                for binary in ["iptables", "ip6tables"]
                if shutil.which(binary)
            ]

        comment = data.get("global_rule_comment")
        rule_records = data.get("global_rules_created") or []

        if not rule_records:
            for binary in binaries:
                for spec in self._global_firewall_rule_specs(binary, iface, comment):
                    rule_records.append(
                        {
                            "binary": binary,
                            "description": spec["description"],
                            "delete": spec["delete"],
                            "check": spec["check"],
                        }
                    )

        for record in rule_records:
            binary = record.get("binary")
            if not binary or not shutil.which(binary):
                log.error(
                    "[Recovery] %s unavailable for global rules",
                    binary or "recorded firewall binary",
                )
                cleanup_ok = False
                continue

            status = self._inspect_stale_resource(record["check"])
            if status is InspectionStatus.ABSENT:
                log.info(
                    f"[Recovery] Skipped {record['description']} (already absent)"
                )
            elif status is InspectionStatus.ERROR:
                cleanup_ok = False
                log.error(
                    f"[Recovery] Cannot inspect {record['description']}"
                )
            else:
                if SubprocessRunner.run(record["delete"], check=False, silent=True):
                    log.info(f"[Recovery] Removed {record['description']}")
                else:
                    cleanup_ok = False
                    log.error(f"[Recovery] Failed to remove {record['description']}")

        return cleanup_ok

    def _cleanup_target_rules(self, data: dict[str, Any], iface: str) -> bool:
        """Clean per-target firewall rules from stale session."""
        cleanup_ok = True

        for target in data.get("targets", []):
            ip = target.get("ip")
            if not ip:
                continue

            binaries = ["ip6tables"] if ":" in ip else ["iptables"]
            suffix = ip.replace(".", "_").replace(":", "_")
            chain_specs = [
                ("mangle", "POSTROUTING", target.get("mangle_chain") or f"NS-MNG-{suffix}"),
                ("nat", "PREROUTING", target.get("nat_chain") or f"NS-NAT-{suffix}"),
            ]

            for binary in binaries:
                if not shutil.which(binary):
                    log.error(f"[Recovery] {binary} unavailable for target {ip}")
                    cleanup_ok = False
                    continue

                # Clean INPUT rules for DNS/HTTP
                if target.get("dns"):
                    rule_comment = target.get("firewall_rule_comment")
                    for proto in ["udp", "tcp"]:
                        rule_spec = self._target_input_rule_spec(
                            binary, iface, ip, proto, 53, rule_comment
                        )
                        rule_status = self._inspect_stale_resource(rule_spec["check"])
                        if rule_status is InspectionStatus.PRESENT:
                            if SubprocessRunner.run(
                                rule_spec["delete"], check=False, silent=True
                            ):
                                log.info(
                                    f"[Recovery] Removed {binary} DNS INPUT {ip}/{proto}"
                                )
                            else:
                                cleanup_ok = False
                                log.error(
                                    f"[Recovery] Failed to remove {binary} "
                                    f"DNS INPUT {ip}/{proto}"
                                )
                        elif rule_status is InspectionStatus.ERROR:
                            cleanup_ok = False
                            log.error(
                                f"[Recovery] Cannot inspect DNS INPUT rule for {ip}/{proto}"
                            )

                http_port = target.get("http_redirect_port")
                if http_port:
                    rule_comment = target.get("firewall_rule_comment")
                    rule_spec = self._target_input_rule_spec(
                        binary, iface, ip, "tcp", int(http_port), rule_comment
                    )
                    http_status = self._inspect_stale_resource(rule_spec["check"])
                    if http_status is InspectionStatus.PRESENT:
                        if SubprocessRunner.run(
                            rule_spec["delete"], check=False, silent=True
                        ):
                            log.info(f"[Recovery] Removed {binary} HTTP INPUT {ip}")
                        else:
                            cleanup_ok = False
                            log.error(
                                f"[Recovery] Failed to remove {binary} HTTP INPUT {ip}"
                            )
                    elif http_status is InspectionStatus.ERROR:
                        cleanup_ok = False
                        log.error(
                            f"[Recovery] Cannot inspect HTTP INPUT rule for {ip}"
                        )

                # Clean mangle/nat chains
                for table, hook, chain_name in chain_specs:
                    cleanup_ok = self._cleanup_target_chain(
                        binary, table, hook, chain_name
                    ) and cleanup_ok

        return cleanup_ok

    @staticmethod
    def _cleanup_plugins(data: dict[str, Any]) -> bool:
        """Restore persistent state left by crashed built-in plugins.

        BLE has no persistent host-side state. Unknown active plugins fail
        closed so their recovery manifest is retained for operator action.
        """
        cleanup_ok = True
        for record in data.get("plugins") or []:
            if not isinstance(record, dict):
                log.error("[Recovery] Invalid plugin recovery record")
                cleanup_ok = False
                continue
            if not (record.get("active") or record.get("start_pending")):
                continue

            plugin_id = record.get("plugin_id")
            if plugin_id == "ble-recon":
                continue
            if plugin_id != "wifi-recon":
                log.error(
                    "[Recovery] No stale-state recovery handler for active plugin %r",
                    plugin_id,
                )
                cleanup_ok = False
                continue

            plugin_config = record.get("config") or {}
            plugin_state = record.get("state") or {}
            iface = plugin_config.get("interface") or plugin_state.get("monitor_iface")
            if not isinstance(iface, str) or not _INTERFACE_RE.fullmatch(iface):
                log.error("[Recovery] Invalid Wi-Fi plugin interface %r", iface)
                cleanup_ok = False
                continue

            ip_binary = shutil.which("ip")
            iw_binary = shutil.which("iw")
            if not ip_binary or not iw_binary:
                log.error("[Recovery] ip/iw unavailable for Wi-Fi plugin recovery")
                cleanup_ok = False
                continue

            down_ok = SubprocessRunner.run(
                [ip_binary, "link", "set", iface, "down"],
                check=False,
                silent=True,
            )
            managed_ok = SubprocessRunner.run(
                [iw_binary, "dev", iface, "set", "type", "managed"],
                check=False,
                silent=True,
            )
            up_ok = SubprocessRunner.run(
                [ip_binary, "link", "set", iface, "up"],
                check=False,
                silent=True,
            )
            if down_ok and managed_ok and up_ok:
                log.info("[Recovery] Restored managed mode on %s", iface)
            else:
                log.error("[Recovery] Failed to restore managed mode on %s", iface)
                cleanup_ok = False

        return cleanup_ok

    def _cleanup_target_chain(
        self,
        binary: str,
        table: str,
        hook: str,
        chain_name: str,
    ) -> bool:
        """Clean a single target firewall chain."""
        cleanup_ok = True

        # Check chain existence
        _cst = self._inspect_stale_resource(
            [binary, "-t", table, "-L", chain_name]
        )
        if _cst is InspectionStatus.ABSENT:
            log.debug(f"[Recovery] Chain {chain_name} already absent")
            return True

        if _cst is InspectionStatus.ERROR:
            cleanup_ok = False
            log.error(f"[Recovery] Cannot inspect chain {chain_name}")
            return cleanup_ok

        # Check jump rule
        _jst = self._inspect_stale_resource(
            [binary, "-t", table, "-C", hook, "-j", chain_name]
        )
        if _jst is InspectionStatus.PRESENT:
            if SubprocessRunner.run(
                [binary, "-t", table, "-D", hook, "-j", chain_name],
                check=False,
                silent=True,
            ):
                log.info(f"[Recovery] Unlinked {chain_name} from {hook}")
            else:
                cleanup_ok = False

        # Flush chain
        if SubprocessRunner.run(
            [binary, "-t", table, "-F", chain_name], check=False, silent=True
        ):
            log.info(f"[Recovery] Flushed {chain_name}")
        else:
            cleanup_ok = False

        # Delete chain
        if SubprocessRunner.run(
            [binary, "-t", table, "-X", chain_name], check=False, silent=True
        ):
            log.info(f"[Recovery] Deleted {chain_name}")
        else:
            cleanup_ok = False

        return cleanup_ok

    def _cleanup_traffic_shaper(self, data: dict[str, Any], iface: str) -> bool:
        """Clean traffic shaper (tc) rules from stale session."""
        cleanup_ok = True

        if not (data.get("shaper_base_initialized") or data.get("shaper_root_qdisc_pending")):
            return True

        if not shutil.which("tc"):
            log.error("[Recovery] tc (traffic control) unavailable")
            return False

        status = self._inspect_stale_resource(
            ["tc", "qdisc", "show", "dev", iface, "root"],
            output_contains="qdisc htb 1:",
        )

        if status is InspectionStatus.ABSENT:
            log.debug("[Recovery] Traffic shaper already removed")
            return True

        if status is InspectionStatus.ERROR:
            cleanup_ok = False
            log.error("[Recovery] Cannot inspect traffic shaper")
            return cleanup_ok

        if SubprocessRunner.run(
            ["tc", "qdisc", "del", "dev", iface, "root"], check=False, silent=True
        ):
            log.info("[Recovery] Removed traffic shaper root qdisc")
        else:
            cleanup_ok = False
            log.error("[Recovery] Failed to remove traffic shaper")

        return cleanup_ok

    def _restore_sysctl_settings(self, data: dict[str, Any]) -> bool:
        """Restore sysctl settings to pre-session state."""
        snapshot_data = data.get("snapshot", {})
        snapshot = StateSnapshotManager.snapshot_from_state(snapshot_data)
        ok = StateSnapshotManager.restore(snapshot, restore_firewall=False)
        if ok:
            log.info("[Recovery] Restored sysctl settings")
        return ok
