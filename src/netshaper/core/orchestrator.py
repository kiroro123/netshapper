"""
NetShaper — main orchestrator.

Owns the session lifecycle (_lifecycle_lock guards add/remove),
global iptables forwarding rules, atomic state persistence,
sniffer management, and the bandwidth monitor thread.
"""
from __future__ import annotations

import glob
import fcntl
import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from typing import Dict, List, Optional, Union

import psutil

from netshaper import config
from netshaper.capture.sniffer import PacketSniffer, RollingPacketSniffer
from netshaper.core.session import TargetSession
from netshaper.core.state_manager import NetworkStateSnapshot, StateSnapshotManager
from netshaper.models import Device, MarkIDPool
from netshaper.network.discovery import NetworkDiscovery
from netshaper.network.shaper import TrafficShaper
from netshaper.system import (
    InspectionStatus,
    SubprocessRunner,
    SystemChecker,
    check_local_port,
    inspect_resource,
)
from netshaper.utils import print_flush

log = logging.getLogger("netshaper")


class NetShaper:
    def __init__(self, interface: str):
        SystemChecker.check()
        self.interface   = interface
        self.session_id  = f"NS-{uuid.uuid4().hex[:6].upper()}"
        self.disc        = NetworkDiscovery(interface)
        self.own_ip      = self.disc.get_own_ip()
        self.own_mac     = self.disc.get_own_mac()
        self.own_ipv6    = self.disc.get_own_ipv6()
        self.gw          = self.disc.get_default_gateway()
        self.gw_mac      = (
            None if config.DRY_RUN
            else self.disc.resolve_mac(self.gw) if self.gw else None
        )
        self.gw_ipv6     = self.disc.get_default_gateway_ipv6()
        self.shaper      = TrafficShaper(interface)
        self.mark_pool   = MarkIDPool()
        self.sessions:   Dict[str, TargetSession] = {}
        # RLock so remove_target() can be called re-entrantly from cleanup()
        self._lifecycle_lock   = threading.RLock()
        self.is_shutting_down  = False
        self.sniffer: Optional[Union[PacketSniffer, RollingPacketSniffer]] = None
        self.stop_event  = threading.Event()
        self._global_rules_applied = False
        self._global_firewall_binaries_applied: List[str] = []
        self._global_rules_created: List[dict] = []
        self._mitm_proc  = None
        self._cleanup_running = False
        self._cleanup_complete = False
        self._dry_run_state = None
        self._lock_file = None
        self._owner_metadata = self._current_owner_metadata()
        self._acquire_instance_lock()
        self.state_snapshot = StateSnapshotManager.capture(interface, self.session_id)

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _process_start_time(pid: int) -> Optional[str]:
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
                return fh.read().split()[21]
        except Exception:
            return None

    @classmethod
    def _process_is_live(cls, pid: Optional[int],
                         start_time: Optional[str]) -> bool:
        if not pid or not start_time:
            return False
        current_start = cls._process_start_time(pid)
        return current_start == str(start_time)

    def _current_owner_metadata(self) -> dict:
        pid = os.getpid()
        return {
            "pid": pid,
            "process_start_time": self._process_start_time(pid),
            "created_at": time.time(),
        }

    def _acquire_instance_lock(self) -> None:
        if config.DRY_RUN:
            return
        lock_path = os.path.join(config.STATE_DIR, "netshaper.lock")
        self._lock_file = open(lock_path, "a+", encoding="utf-8")
        try:
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._lock_file.seek(0)
            owner = self._lock_file.read().strip() or "another process"
            self._lock_file.close()
            self._lock_file = None
            raise RuntimeError(
                "Another NetShaper instance is already running: "
                f"{owner}"
            )
        self._lock_file.seek(0)
        self._lock_file.truncate()
        json.dump(self._owner_metadata, self._lock_file)
        self._lock_file.flush()
        os.fsync(self._lock_file.fileno())

    def _release_instance_lock(self) -> None:
        lock_file = getattr(self, "_lock_file", None)
        if not lock_file:
            return
        try:
            lock_file.seek(0)
            lock_file.truncate()
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()
        finally:
            self._lock_file = None

    @staticmethod
    def scale_bytes(val: float) -> str:
        for unit in ["KB", "MB", "GB"]:
            if val < 1024:
                return f"{val:.1f} {unit}"
            val /= 1024
        return f"{val:.1f} TB"

    # ── Global forwarding rules ───────────────────────────────────────────────
    def _global_rule_comment(self) -> str:
        return f"netshaper:{self.session_id}:global"

    @staticmethod
    def _global_firewall_rule_specs(
            binary: str,
            iface: str,
            comment: Optional[str]) -> List[dict]:
        comment_args = (
            ["-m", "comment", "--comment", comment]
            if comment else []
        )
        return [
            {
                "description": f"{binary} forward same-interface accept",
                "apply": [
                    binary, "-I", "FORWARD", "1",
                    "-i", iface, "-o", iface,
                    *comment_args,
                    "-j", "ACCEPT",
                ],
                "delete": [
                    binary, "-D", "FORWARD",
                    "-i", iface, "-o", iface,
                    *comment_args,
                    "-j", "ACCEPT",
                ],
                "check": [
                    binary, "-C", "FORWARD",
                    "-i", iface, "-o", iface,
                    *comment_args,
                    "-j", "ACCEPT",
                ],
            },
            {
                "description": f"{binary} established forward accept",
                "apply": [
                    binary, "-I", "FORWARD", "1",
                    "-m", "state", "--state", "ESTABLISHED,RELATED",
                    *comment_args,
                    "-j", "ACCEPT",
                ],
                "delete": [
                    binary, "-D", "FORWARD",
                    "-m", "state", "--state", "ESTABLISHED,RELATED",
                    *comment_args,
                    "-j", "ACCEPT",
                ],
                "check": [
                    binary, "-C", "FORWARD",
                    "-m", "state", "--state", "ESTABLISHED,RELATED",
                    *comment_args,
                    "-j", "ACCEPT",
                ],
            },
            {
                "description": f"{binary} masquerade",
                "apply": [
                    binary, "-t", "nat", "-A", "POSTROUTING",
                    "-o", iface,
                    *comment_args,
                    "-j", "MASQUERADE",
                ],
                "delete": [
                    binary, "-t", "nat", "-D", "POSTROUTING",
                    "-o", iface,
                    *comment_args,
                    "-j", "MASQUERADE",
                ],
                "check": [
                    binary, "-t", "nat", "-C", "POSTROUTING",
                    "-o", iface,
                    *comment_args,
                    "-j", "MASQUERADE",
                ],
            },
        ]

    @staticmethod
    def _inspect_rule(command: List[str]) -> InspectionStatus:
        return inspect_resource(command).status

    @staticmethod
    def _target_input_rule_spec(
            binary: str,
            iface: str,
            ip: str,
            proto: str,
            port: int,
            comment: Optional[str]) -> dict:
        comment_args = (
            ["-m", "comment", "--comment", comment]
            if comment else []
        )
        base = [
            "-i", iface, "-s", ip,
            "-p", proto, "--dport", str(port),
            *comment_args,
            "-j", "ACCEPT",
        ]
        return {
            "delete": [binary, "-D", "INPUT", *base],
            "check": [binary, "-C", "INPUT", *base],
        }

    def _journal_state_if_ready(self) -> bool:
        required = ("session_id", "interface", "state_snapshot", "sessions")
        if not all(hasattr(self, name) for name in required):
            return True
        return self.save_state()

    def _record_global_rule(self, binary: str, spec: dict) -> bool:
        if not hasattr(self, "_global_rules_created"):
            self._global_rules_created = []
        if not hasattr(self, "_global_firewall_binaries_applied"):
            self._global_firewall_binaries_applied = []
        record = {
            "binary": binary,
            "description": spec["description"],
            "delete": spec["delete"],
            "check": spec["check"],
        }
        self._global_rules_created.append(record)
        if binary not in self._global_firewall_binaries_applied:
            self._global_firewall_binaries_applied.append(binary)
        self._global_rules_applied = True
        return self._journal_state_if_ready()

    def _global_rule_records_for_cleanup(self) -> List[dict]:
        records = list(getattr(self, "_global_rules_created", []))
        if records:
            return records
        if not getattr(self, "_global_rules_applied", False):
            return []
        records = []
        comment = (
            self._global_rule_comment()
            if hasattr(self, "session_id") else None
        )
        for binary in getattr(self, "_global_firewall_binaries_applied", []):
            for spec in self._global_firewall_rule_specs(
                    binary, self.interface, comment):
                records.append({
                    "binary": binary,
                    "description": spec["description"],
                    "delete": spec["delete"],
                    "check": spec["check"],
                })
        return records

    def _apply_global_rules(self) -> None:
        if self._global_rules_applied:
            return
        ok = True
        comment = self._global_rule_comment()
        ok = SubprocessRunner.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"], silent=True) and ok
        ok = SubprocessRunner.run(
            ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
            silent=True) and ok
        ok = SubprocessRunner.run(
            ["sysctl", "-w",
             f"net.ipv4.conf.{self.interface}.route_localnet=1"],
            silent=True) and ok
        for binary in ["iptables", "ip6tables"]:
            if shutil.which(binary):
                for spec in self._global_firewall_rule_specs(
                        binary, self.interface, comment):
                    if SubprocessRunner.run(spec["apply"], silent=True):
                        ok = self._record_global_rule(binary, spec) and ok
                    else:
                        ok = False
        if not ok:
            raise RuntimeError("Failed to apply global forwarding rules")
        log.info("Global dual-stack forwarding + MASQUERADE enabled")

    def _restore_original_forwarding(self) -> bool:
        ok = True
        if self.state_snapshot.ipv4_forwarding is not None:
            ok = SubprocessRunner.run(
                ["sysctl", "-w", f"net.ipv4.ip_forward={self.state_snapshot.ipv4_forwarding}"],
                silent=True,
            ) and ok
        if self.state_snapshot.ipv6_forwarding is not None:
            ok = SubprocessRunner.run(
                ["sysctl", "-w", f"net.ipv6.conf.all.forwarding={self.state_snapshot.ipv6_forwarding}"],
                silent=True,
            ) and ok
        if self.state_snapshot.route_localnet is not None:
            ok = SubprocessRunner.run(
                [
                    "sysctl", "-w",
                    f"net.ipv4.conf.{self.interface}.route_localnet={self.state_snapshot.route_localnet}",
                ],
                silent=True,
            ) and ok
        return ok

    def _remove_global_rules(self) -> bool:
        ok = self._restore_original_forwarding()
        records = self._global_rule_records_for_cleanup()
        if not records:
            return ok
        for record in list(records):
            binary = record["binary"]
            if not shutil.which(binary):
                if binary in self._global_firewall_binaries_applied:
                    log.error(
                        f"Cannot remove global firewall rules: "
                        f"{binary} unavailable"
                    )
                    ok = False
                continue
            status = self._inspect_rule(record["check"])
            if status is InspectionStatus.ABSENT:
                if record in getattr(self, "_global_rules_created", []):
                    self._global_rules_created.remove(record)
                continue
            if status is InspectionStatus.ERROR:
                log.error(
                    f"Cannot inspect global firewall rule: "
                    f"{record['description']}"
                )
                ok = False
                continue
            if SubprocessRunner.run(
                    record["delete"], check=False, silent=True):
                if record in getattr(self, "_global_rules_created", []):
                    self._global_rules_created.remove(record)
            else:
                ok = False
        if ok:
            self._global_rules_applied = False
            self._global_firewall_binaries_applied = []
            self._global_rules_created = []
            log.info("Global forwarding + MASQUERADE removed")
        return ok

    # ── Discovery ─────────────────────────────────────────────────────────────
    def discover(self) -> List[Device]:
        import sys
        subnet = self.disc.get_subnet_v4()
        if not subnet:
            sys.exit("[NetShaper] Could not determine subnet.")
        devices = self.disc.arp_sweep(subnet, self.gw)
        self.disc.resolve_hostnames(devices)
        return devices

    # Backward-compatible alias (older CLI expects discover_devices())
    def discover_devices(self) -> List[Device]:
        return self.discover()


    # ── Session lifecycle ─────────────────────────────────────────────────────
    def add_target(
        self,
        target: Union[Device, str],
        arp_on: bool = True,
        dns_spoof: bool = False,
        captive_portal: bool = False,
        http_redirect_port: Optional[int] = None,
        limit: Optional[float] = None,
    ) -> None:
        """Add an interception session.

        Backward-compatibility: the CLI passes `target` as an IP string.
        Newer internal code may pass a `Device`.
        """
        target_ip = target if isinstance(target, str) else target.ip
        with self._lifecycle_lock:
            if target_ip in self.sessions:
                raise ValueError(f"Target {target_ip} is already active.")

        # Resolve IP -> Device if needed
        if isinstance(target, str):
            ip = target
            mac = (
                "00:00:00:00:00:00" if config.DRY_RUN
                else self.disc.resolve_mac(ip) if ip else None
            )
            if not mac:
                raise ValueError(
                    f"Could not resolve MAC for target IP {ip}. "
                    f"Run discovery first or ensure ARP reachability."
                )
            target = Device(ip=ip, mac=mac)

        with self._lifecycle_lock:
            if target.ip in self.sessions:
                raise ValueError(f"Target {target.ip} is already active.")
            mark_base = self.mark_pool.acquire(target.ip)
            session = TargetSession(
                target,
                self.interface,
                self.own_mac,
                self.own_ip,
                self.own_ipv6,
                self.gw,
                self.gw_mac,
                self.gw_ipv6,
                self.shaper,
                getattr(self, "session_id", None),
            )
            self.sessions[target.ip] = session

        try:
            session.setup(
                dns_spoof=dns_spoof,
                captive_portal=captive_portal,
                http_redirect_port=http_redirect_port,
                limit=limit,
                mark_base=mark_base,
            )
            session.start_spoof(arp_on=arp_on)
        except Exception as exc:
            cleanup_ok = False
            try:
                cleanup_ok = session.cleanup()
            except Exception as cleanup_exc:
                log.error(
                    f"Rollback cleanup for {target.ip} failed: {cleanup_exc}"
                )
            if cleanup_ok:
                with self._lifecycle_lock:
                    if self.sessions.get(target.ip) is session:
                        del self.sessions[target.ip]
                self.mark_pool.release(target.ip)
            else:
                log.error(
                    f"Keeping failed target {target.ip} in recovery state "
                    f"after setup error: {exc}"
                )
                self.save_state()
            raise

        log.info(
            f"Target {target.ip} added "
            f"(ARP={arp_on} DNS={dns_spoof} "
            f"Portal={captive_portal} HTTP→{http_redirect_port})"
        )


    def remove_target(self, ip: str) -> bool:
        with self._lifecycle_lock:
            session = self.sessions.get(ip)
            if not session:
                return True
            session.active           = False
            session.is_shutting_down = True
        # Cleanup outside lock — spoof threads exit naturally via flag check
        ok = session.cleanup()
        if ok:
            with self._lifecycle_lock:
                if self.sessions.get(ip) is session:
                    del self.sessions[ip]
            self.mark_pool.release(ip)
            log.info(f"Target {ip} removed")
        else:
            log.warning(f"Target {ip} removed with cleanup errors")
        return ok

    def cleanup(self) -> None:
        with self._lifecycle_lock:
            if getattr(self, "_cleanup_complete", False):
                return
            if getattr(self, "_cleanup_running", False):
                return
            self._cleanup_running = True
            self.is_shutting_down = True

        errors = []

        def cleanup_step(description: str, action) -> None:
            try:
                result = action()
                if result is False:
                    raise RuntimeError("cleanup command failed")
            except Exception as exc:
                errors.append((description, exc))
                log.error(f"Cleanup step failed ({description}): {exc}")

        try:
            print_flush("\n--- NetShaper Shutdown ---")
            self.stop_event.set()
            with self._lifecycle_lock:
                for s in self.sessions.values():
                    s.active           = False
                    s.is_shutting_down = True

            for ip in list(self.sessions.keys()):
                cleanup_step(f"target {ip}", lambda ip=ip: self.remove_target(ip))
            cleanup_step(
                "sniffer",
                lambda: self.sniffer.stop()
                if self.sniffer and hasattr(self.sniffer, "stop") else None,
            )
            cleanup_step(
                "mitmproxy",
                self._terminate_mitmproxy,
            )
            cleanup_step("global rules", self._remove_global_rules)
            cleanup_step(
                "state snapshot",
                lambda: (
                    StateSnapshotManager.restore(self.state_snapshot)
                    or (_ for _ in ()).throw(RuntimeError("state snapshot restore failed"))
                ),
            )
            cleanup_step("traffic shaper", self.shaper.cleanup)

            state_path = os.path.join(config.STATE_DIR, self.session_id, "state.json")
            if errors:
                log.warning(f"Network cleanup completed with {len(errors)} error(s).")
            else:
                if not config.DRY_RUN:
                    cleanup_step(
                        "state file",
                        lambda: self._remove_state_file(state_path),
                    )
                if errors:
                    log.warning(
                        f"Network cleanup completed with {len(errors)} error(s)."
                    )
                else:
                    log.info("Network restored.")
        finally:
            with self._lifecycle_lock:
                self._cleanup_complete = not errors
                self._cleanup_running = False
            self._release_instance_lock()

    # Backward-compatible alias (older CLI expects stop())
    def stop(self) -> None:
        self.cleanup()

    @staticmethod
    def _remove_state_file(state_path: str) -> None:
        if os.path.exists(state_path):
            os.remove(state_path)
        try:
            os.rmdir(os.path.dirname(state_path))
        except OSError:
            pass

    # ── Sniffer ───────────────────────────────────────────────────────────────
    def launch_sniffer(self, target_ips: Optional[List[str]] = None,
                       save_pcap: bool = False, rolling: bool = False) -> None:
        if config.DRY_RUN:
            print_flush("[DRY-RUN] Would launch packet sniffer")
            return
        if self.sniffer:
            self.sniffer.stop()
        if rolling:
            self.sniffer = RollingPacketSniffer(
                self.interface, target_ips=target_ips)
        else:
            self.sniffer = PacketSniffer(
                self.interface, target_ips=target_ips, save_pcap=save_pcap)
        self.sniffer.start()

    # ── mitmproxy ─────────────────────────────────────────────────────────────
    def launch_mitmproxy(self, port: int = 8088, web_port: int = 8083) -> bool:
        """Launch mitmweb and poll for readiness (no hard-coded sleep)."""
        if config.DRY_RUN:
            print_flush(
                "[DRY-RUN] mitmweb --mode transparent "
                f"--listen-port {port} --set web_port={web_port}"
            )
            return True
        if check_local_port(self.own_ip, port):
            log.info(f"mitmproxy already running on :{port}")
            return True
        try:
            self._mitm_proc = subprocess.Popen(
                ["mitmweb", "--mode", "transparent",
                 "--listen-port", str(port),
                 "--set", f"web_port={web_port}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for attempt in range(10):
                if check_local_port(self.own_ip, port):
                    print_flush(
                        f"  [+] mitmproxy ready → http://127.0.0.1:{web_port}")
                    return True
                log.debug(f"Waiting for mitmproxy… (attempt {attempt+1}/10)")
                time.sleep(0.5)
            log.error(f"mitmproxy did not bind to :{port} within 5 s")
            self._terminate_mitmproxy()
            return False
        except FileNotFoundError:
            print_flush("  [!] mitmweb not found.  pip install mitmproxy")
            return False

    def _terminate_mitmproxy(self) -> bool:
        proc = getattr(self, "_mitm_proc", None)
        if not proc:
            return True
        ok = True
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            if proc.poll() is None:
                ok = False
            else:
                log.info("mitmproxy terminated")
        except Exception as exc:
            ok = False
            log.error(f"mitmproxy cleanup failed: {exc}")
        if ok:
            self._mitm_proc = None
        return ok

    def close(self) -> None:
        """Release non-network resources when a session never started."""
        self._terminate_mitmproxy()
        self._release_instance_lock()

    # ── State persistence ─────────────────────────────────────────────────────
    @staticmethod
    def _snapshot_to_dict(snapshot: NetworkStateSnapshot) -> dict:
        return {
            "session_id": snapshot.session_id,
            "interface": snapshot.interface,
            "ipv4_forwarding": snapshot.ipv4_forwarding,
            "ipv6_forwarding": snapshot.ipv6_forwarding,
            "route_localnet": snapshot.route_localnet,
            "iptables_rules": snapshot.iptables_rules,
            "ip6tables_rules": snapshot.ip6tables_rules,
            "tc_configuration": snapshot.tc_configuration,
        }

    @staticmethod
    def _snapshot_from_state(data: dict) -> NetworkStateSnapshot:
        snapshot = data.get("snapshot") or {}
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

    @staticmethod
    def _session_dns_recorded(session: TargetSession) -> bool:
        firewall = session.firewall
        return (
            session.dns_on
            or bool(
                getattr(firewall, "_dns_input_rules", set())
                if firewall else False
            )
            or bool(
                getattr(firewall, "_dns_added", False)
                if firewall else False
            )
        )

    def save_state(self) -> bool:
        data = {
            "session_id": self.session_id,
            "interface": self.interface,
            "targets":   [{"ip": s.target.ip,
                           "dns": self._session_dns_recorded(s),
                           "limit": s.limit,
                           "http_redirect_port": (
                               getattr(s.firewall, "_http_redirect_port", None)
                               if s.firewall else None
                           ),
                           "firewall_rule_comment": (
                               getattr(s.firewall, "_rule_comment", None)
                               if s.firewall else None
                           ),
                           "mangle_chain": (
                               getattr(s.firewall, "MANGLE", None)
                               if s.firewall else None
                           ),
                           "nat_chain": (
                               getattr(s.firewall, "NAT", None)
                               if s.firewall else None
                           )}
                          for s in self.sessions.values()],
            "gw":     self.gw,
            "own_ip": self.own_ip,
            "global_rules_applied": self._global_rules_applied,
            "global_rule_comment": (
                self._global_rule_comment()
                if self._global_rules_applied else None
            ),
            "global_firewall_binaries": list(
                getattr(self, "_global_firewall_binaries_applied", [])),
            "global_rules_created": list(
                getattr(self, "_global_rules_created", [])),
            "shaper_base_initialized": getattr(
                getattr(self, "shaper", None), "_base_initialized", False),
            "owner": getattr(self, "_owner_metadata", {}),
            "snapshot": self._snapshot_to_dict(self.state_snapshot),
        }
        if config.DRY_RUN:
            self._dry_run_state = data
            return True
        try:
            state_dir = os.path.join(config.STATE_DIR, self.session_id)
            os.makedirs(state_dir, mode=0o700, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                    'w', dir=state_dir, delete=False) as tf:
                json.dump(data, tf)
                tmp = tf.name
            os.replace(tmp, os.path.join(state_dir, "state.json"))   # Atomic write
            return True
        except Exception as e:
            log.error(f"State save failed: {e}")
            return False

    def load_state_and_cleanup(self) -> bool:
        if not os.path.isdir(config.STATE_DIR):
            return True
        recovery_ok = True
        recovery_attempted = False
        for state_path in sorted(glob.glob(os.path.join(config.STATE_DIR, "*", "state.json"))):
            cleanup_ok = True
            try:
                with open(state_path, encoding="utf-8") as f:
                    data = json.load(f)
                iface = data.get("interface")
                if not iface:
                    continue
                owner = data.get("owner") or {}
                if self._process_is_live(
                        owner.get("pid"), owner.get("process_start_time")):
                    log.info(
                        f"Skipping live NetShaper session: {state_path}"
                    )
                    recovery_ok = False
                    continue
                print_flush(f"  [!] Stale session on {iface} — cleaning up…")
                recovery_attempted = True

                def run_recovery(description: str, command: list[str]) -> None:
                    nonlocal cleanup_ok
                    if not SubprocessRunner.run(
                            command, check=False, silent=True):
                        cleanup_ok = False
                        log.error(f"Stale cleanup failed ({description})")

                def inspect_stale_resource(
                        command: list[str],
                        *,
                        output_contains: Optional[str] = None,
                ) -> InspectionStatus:
                    inspection = inspect_resource(command)
                    if inspection.status is not InspectionStatus.PRESENT:
                        return inspection.status
                    if (
                            output_contains is not None
                            and output_contains not in inspection.stdout):
                        return InspectionStatus.ABSENT
                    return InspectionStatus.PRESENT

                def run_recovery_if_present(
                        description: str,
                        command: list[str],
                        exists_command: list[str],
                        *,
                        output_contains: Optional[str] = None) -> None:
                    nonlocal cleanup_ok
                    status = inspect_stale_resource(
                            exists_command,
                            output_contains=output_contains)
                    if status is InspectionStatus.ABSENT:
                        log.info(
                            f"Stale cleanup skipped ({description} already absent)"
                        )
                        return
                    if status is InspectionStatus.ERROR:
                        cleanup_ok = False
                        log.error(
                            f"Stale cleanup failed ({description}): "
                            "resource inspection failed"
                        )
                        return
                    run_recovery(description, command)

                def require_binary(binary: str, reason: str) -> bool:
                    nonlocal cleanup_ok
                    if shutil.which(binary):
                        return True
                    cleanup_ok = False
                    log.error(
                        f"Stale cleanup failed ({reason}): "
                        f"{binary} unavailable"
                    )
                    return False

                if data.get("global_rules_applied"):
                    binaries = data.get("global_firewall_binaries")
                    if binaries is None:
                        binaries = [
                            binary for binary in ["iptables", "ip6tables"]
                            if shutil.which(binary)
                        ]
                    comment = data.get("global_rule_comment")
                    rule_records = data.get("global_rules_created")
                    if rule_records is None:
                        rule_records = []
                        for binary in binaries:
                            for spec in self._global_firewall_rule_specs(
                                    binary, iface, comment):
                                rule_records.append({
                                    "binary": binary,
                                    "description": spec["description"],
                                    "delete": spec["delete"],
                                    "check": spec["check"],
                                })
                    for record in rule_records:
                        binary = record.get("binary")
                        if not binary:
                            continue
                        if not require_binary(binary, "global firewall rules"):
                            continue
                        run_recovery_if_present(
                            record.get("description")
                            or f"{binary} global firewall rule",
                            record["delete"],
                            record["check"],
                        )

                for target in data.get("targets", []):
                    ip = target.get("ip")
                    if not ip:
                        continue
                    binaries = ["ip6tables"] if ":" in ip else ["iptables"]
                    suffix = ip.replace(".", "_").replace(":", "_")
                    chain_specs = [
                        ("mangle", "POSTROUTING",
                         target.get("mangle_chain") or f"NS-MNG-{suffix}"),
                        ("nat", "PREROUTING",
                         target.get("nat_chain") or f"NS-NAT-{suffix}"),
                    ]
                    for binary in binaries:
                        if not require_binary(binary, f"target firewall {ip}"):
                            continue
                        if target.get("dns"):
                            rule_comment = target.get("firewall_rule_comment")
                            for proto in ["udp", "tcp"]:
                                rule_spec = self._target_input_rule_spec(
                                    binary, iface, ip, proto, 53,
                                    rule_comment)
                                run_recovery_if_present(
                                    f"{binary} DNS input {ip}/{proto}",
                                    rule_spec["delete"],
                                    rule_spec["check"],
                                )
                        http_port = target.get("http_redirect_port")
                        if http_port:
                            rule_comment = target.get("firewall_rule_comment")
                            rule_spec = self._target_input_rule_spec(
                                binary, iface, ip, "tcp", int(http_port),
                                rule_comment)
                            run_recovery_if_present(
                                f"{binary} HTTP input {ip}",
                                rule_spec["delete"],
                                rule_spec["check"],
                            )
                        for table, hook, chain_name in chain_specs:
                            run_recovery_if_present(
                                f"{binary} unlink {chain_name}",
                                [binary, "-t", table, "-D", hook,
                                 "-j", chain_name],
                                [binary, "-t", table, "-C", hook,
                                 "-j", chain_name],
                            )
                            run_recovery_if_present(
                                f"{binary} flush {chain_name}",
                                [binary, "-t", table, "-F", chain_name],
                                [binary, "-t", table, "-L", chain_name],
                            )
                            run_recovery_if_present(
                                f"{binary} delete {chain_name}",
                                [binary, "-t", table, "-X", chain_name],
                                [binary, "-t", table, "-L", chain_name],
                            )

                if data.get("shaper_base_initialized"):
                    if require_binary("tc", "traffic shaper"):
                        run_recovery_if_present(
                            "tc root qdisc",
                            ["tc", "qdisc", "del", "dev", iface, "root"],
                            ["tc", "qdisc", "show", "dev", iface, "root"],
                            output_contains="qdisc htb 1:",
                        )

                snapshot = self._snapshot_from_state(data)
                cleanup_ok = StateSnapshotManager.restore(snapshot) and cleanup_ok
                if cleanup_ok:
                    log.info("Stale rules cleaned.")
                    os.remove(state_path)
                    try:
                        os.rmdir(os.path.dirname(state_path))
                    except OSError:
                        pass
                else:
                    recovery_ok = False
                    log.error(f"Leaving recovery state in place: {state_path}")
            except Exception as exc:
                recovery_ok = False
                log.error(f"Could not recover state file {state_path}: {exc}")
        current_interface = getattr(self, "interface", None)
        if recovery_attempted and recovery_ok and current_interface:
            self.state_snapshot = StateSnapshotManager.capture(
                current_interface,
                getattr(self, "session_id", ""),
            )
        return recovery_ok

    # ── Bandwidth monitor ─────────────────────────────────────────────────────
    def monitor(self) -> None:
        # BUG FIX: psutil failures (containers, SELinux) no longer crash the thread
        old = None
        try:
            old = psutil.net_io_counters(pernic=True).get(self.interface)
        except Exception as e:
            log.warning(f"[Monitor] Could not read initial counters: {e}")

        while not self.stop_event.wait(2):
            try:
                new = psutil.net_io_counters(pernic=True).get(self.interface)
                if old and new:
                    tx = new.bytes_sent - old.bytes_sent
                    rx = new.bytes_recv - old.bytes_recv
                    print_flush(
                        f"\r  TX:{self.scale_bytes(tx)}"
                        f"  RX:{self.scale_bytes(rx)}   ",
                        end='')
                old = new
            except Exception as e:
                log.debug(f"[Monitor] Counter read error: {e}")
        print_flush()
