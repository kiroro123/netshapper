"""
NetShaper — main orchestrator.

Owns the session lifecycle (_lifecycle_lock guards add/remove),
global iptables forwarding rules, atomic state persistence,
sniffer management, and the bandwidth monitor thread.
"""
from __future__ import annotations

import fcntl
from ipaddress import ip_network
import json
import logging
import os
import socket
import tempfile
import threading
import time
import uuid
from dataclasses import asdict
from typing import Dict, List, Optional, Sequence, Union

import psutil

from netshaper import config
from netshaper.capture.sniffer import PacketSniffer, RollingPacketSniffer
from netshaper.core.authorization import AuthorizationPolicy
from netshaper.core.firewall_manager import FirewallManager
from netshaper.core.mitm_manager import MitmProxyManager, MitmProxyError
from netshaper.core.recovery_manager import RecoveryManager
from netshaper.core.session import TargetSession
from netshaper.core.state_manager import NetworkStateSnapshot, StateSnapshotManager
from netshaper.models import Device, MarkIDPool
from netshaper.network.discovery import NetworkDiscovery
from netshaper.network.shaper import ShapingProfile, TrafficShaper
from netshaper.system import (
    SystemChecker,
    check_local_port,
)
from netshaper.utils import print_flush

log = logging.getLogger("netshaper")


class NetShaper:
    def __init__(self, interface: str, authorized_cidrs: Sequence):
        normalized = self._normalize_authorized_cidrs(authorized_cidrs)
        self._auth_policy = AuthorizationPolicy(normalized)
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
        self.firewall_manager = FirewallManager(
            interface,
            self.session_id,
            journal=self._sync_firewall_state,
        )
        self.mitm_manager = MitmProxyManager(getattr(self, 'own_ip', None))
        self.recovery_manager = RecoveryManager(interface)
        self.sessions:   Dict[str, TargetSession] = {}
        # RLock so remove_target() can be called re-entrantly from cleanup()
        self._lifecycle_lock   = threading.RLock()
        self.is_shutting_down  = False
        self.sniffer: Optional[Union[PacketSniffer, RollingPacketSniffer]] = None
        self.stop_event  = threading.Event()
        self._mitm_log_path: Optional[str] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._runtime_errors: List[str] = []
        self._started_at: Optional[float] = None
        self._cleanup_running = False
        self._cleanup_complete = False
        self._dry_run_state = None
        self._lock_file = None
        self._owner_metadata = self._current_owner_metadata()
        self._acquire_instance_lock()
        self.state_snapshot = StateSnapshotManager.capture(interface, self.session_id)

    # ── Helpers ───────────────────────────────────────────────────────────────
    @property
    def authorized_cidrs(self) -> tuple:
        policy = getattr(self, "_auth_policy", None)
        return policy.cidrs if policy else ()

    @staticmethod
    def _normalize_authorized_cidrs(raw_values: Sequence) -> list:
        networks = []
        for token in raw_values or []:
            if isinstance(token, str):
                raw_items = token.split(",")
            else:
                raw_items = [token]
            for item in raw_items:
                if isinstance(item, str):
                    item = item.strip()
                    if not item:
                        continue
                    networks.append(ip_network(item, strict=False))
                else:
                    # Accept ipaddress network objects from the CLI parser.
                    if not (
                            hasattr(item, "version")
                            and hasattr(item, "network_address")
                            and hasattr(item, "prefixlen")):
                        raise ValueError(
                            f"invalid authorized CIDR object: {item!r}"
                        )
                    networks.append(item)
        if not networks:
            raise ValueError(
                "authorized_cidrs is required before creating NetShaper"
            )
        return networks

    def _assert_authorized_target(self, raw_ip: str) -> None:
        policy = getattr(self, "_auth_policy", None)
        if not policy:
            raise ValueError("authorized_cidrs is empty; refusing target")
        policy.assert_target_authorized(
            raw_ip,
            own_ip=getattr(self, "own_ip", None),
            own_ipv6=getattr(self, "own_ipv6", None),
            gateway=getattr(self, "gw", None),
            gateway_ipv6=getattr(self, "gw_ipv6", None),
        )

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
            ) from None
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
    def _timestamp() -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S %z")

    def _session_state_dir(self) -> str:
        return os.path.join(
            config.STATE_DIR,
            getattr(self, "session_id", "NS-UNKNOWN"),
        )

    def _state_path(self) -> str:
        return os.path.join(self._session_state_dir(), "state.json")

    def record_runtime_error(self, component: str, error) -> None:
        message = f"{self._timestamp()} {component}: {error}"
        self._runtime_errors.append(message)
        log.error(f"Runtime failure ({component}): {error}")

    def start_monitor_thread(self) -> threading.Thread:
        current = getattr(self, "_monitor_thread", None)
        if current and current.is_alive():
            return current

        def guarded_monitor() -> None:
            try:
                self.monitor()
            except Exception as exc:
                self.record_runtime_error("bandwidth monitor", exc)
                self.stop_event.set()

        self._monitor_thread = threading.Thread(
            target=guarded_monitor,
            name=f"netshaper-monitor-{getattr(self, 'session_id', 'NS-UNKNOWN')}",
            daemon=True,
        )
        self._started_at = time.time()
        self._monitor_thread.start()
        return self._monitor_thread

    def _sniffer_output_files(self) -> List[str]:
        sniffer = getattr(self, "sniffer", None)
        return list(getattr(sniffer, "output_files", []) or [])

    def runtime_evidence_lines(
            self,
            target_ips: Optional[List[str]] = None,
            *,
            expect_sniffer: bool = False,
            save_pcap: bool = False,
            rolling: bool = False) -> List[str]:
        started_at = self._started_at or time.time()
        lines = [
            f"Session ID: {self.session_id}",
            f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S %z', time.localtime(started_at))}",
            f"Interface: {self.interface}",
            f"Targets: {', '.join(target_ips or []) or '-'}",
            "State file: "
            + ("dry-run memory only" if config.DRY_RUN else self._state_path()),
            "Log file: "
            + ("console only" if config.DRY_RUN else config.LOG_FILE),
        ]

        monitor_thread = getattr(self, "_monitor_thread", None)
        lines.append(
            "Monitor thread: "
            + ("running" if monitor_thread and monitor_thread.is_alive()
               else "not running")
        )

        sniffer = getattr(self, "sniffer", None)
        if sniffer:
            if hasattr(sniffer, "is_running"):
                sniffer_status = (
                    "running" if sniffer.is_running() else "not running"
                )
            else:
                sniffer_status = "unknown"
            lines.append(f"Packet sniffer: {sniffer_status}")
            output_files = self._sniffer_output_files()
            if output_files:
                lines.append("PCAP files: " + ", ".join(output_files))
            elif rolling:
                lines.append("PCAP files: rolling writer started, no file recorded yet")
            elif save_pcap:
                lines.append("PCAP files: will be written during shutdown")
            else:
                lines.append("PCAP files: not requested")
        elif expect_sniffer:
            lines.append("Packet sniffer: not started")

        mitm_mgr = getattr(self, "mitm_manager", None)
        if mitm_mgr:
            mitm_state = mitm_mgr.get_state_for_persistence() or {}
            if mitm_state.get("mitm_log_path"):
                lines.append(f"mitmproxy log: {mitm_state.get('mitm_log_path')}")

        errors = getattr(self, "_runtime_errors", [])
        lines.append("Runtime errors: " + ("; ".join(errors) if errors else "none"))
        return lines

    def runtime_health_issues(
            self,
            *,
            expect_sniffer: bool = False,
            expect_monitor: bool = False,
            expected_tcp_ports: Optional[List[int]] = None,
            expected_udp_ports: Optional[List[int]] = None) -> List[str]:
        issues = list(getattr(self, "_runtime_errors", []))
        if self.stop_event.is_set():
            return issues

        if expect_monitor:
            monitor_thread = getattr(self, "_monitor_thread", None)
            if monitor_thread is None or not monitor_thread.is_alive():
                issues.append("bandwidth monitor thread is not running")

        if expect_sniffer and not config.DRY_RUN:
            sniffer = getattr(self, "sniffer", None)
            if sniffer is None:
                issues.append("packet sniffer was requested but is not started")
            elif hasattr(sniffer, "is_running") and not sniffer.is_running():
                detail = getattr(sniffer, "last_error", None)
                message = "packet sniffer stopped unexpectedly"
                if detail:
                    message += f": {detail}"
                issues.append(message)

        # mitmproxy lifecycle is managed by MitmProxyManager; rely on
        # monitor/port checks above rather than peeking at a subprocess.

        if not config.DRY_RUN:
            host = getattr(self, "own_ip", None)
            if host:
                for port in expected_tcp_ports or []:
                    if not check_local_port(host, port):
                        issues.append(f"TCP port {port} is no longer reachable")
                for port in expected_udp_ports or []:
                    if not check_local_port(host, port, socket.SOCK_DGRAM):
                        issues.append(f"UDP port {port} is no longer reachable")
            elif expected_tcp_ports or expected_udp_ports:
                issues.append("local host IP is unknown; cannot verify ports")

        return issues

    @staticmethod
    def scale_bytes(val: float) -> str:
        for unit in ["KB", "MB", "GB"]:
            if val < 1024:
                return f"{val:.1f} {unit}"
            val /= 1024
        return f"{val:.1f} TB"

    # ── Global forwarding rules ───────────────────────────────────────────────
    def _journal_state_if_ready(self) -> bool:
        required = ("session_id", "interface", "state_snapshot", "sessions")
        if not all(hasattr(self, name) for name in required):
            return True
        return self.save_state()

    def _sync_firewall_state(self, *, journal: bool = True) -> bool:
        manager = getattr(self, "firewall_manager", None)
        if manager is None:
            return True
        self._global_rules_applied = manager._global_rules_applied
        self._global_firewall_binaries_applied = list(
            manager._global_firewall_binaries_applied
        )
        self._global_rules_created = list(manager._global_rules_created)
        if not journal:
            return True
        return self._journal_state_if_ready()

    def _get_firewall_manager(self) -> FirewallManager:
        if hasattr(self, "firewall_manager") and self.firewall_manager is not None:
            return self.firewall_manager
        manager = FirewallManager(
            getattr(self, "interface", ""),
            getattr(self, "session_id", ""),
            journal=self._sync_firewall_state,
        )
        if getattr(self, "_global_rules_applied", False):
            manager._global_rules_applied = True
            manager._global_firewall_binaries_applied = list(
                getattr(self, "_global_firewall_binaries_applied", [])
            )
            manager._global_rules_created = list(
                getattr(self, "_global_rules_created", [])
            )
        self.firewall_manager = manager
        return manager

    def _apply_global_rules(self) -> None:
        manager = self._get_firewall_manager()
        try:
            manager.apply_global_rules()
        except Exception as exc:
            self._sync_firewall_state(journal=False)
            raise RuntimeError("Failed to apply global forwarding rules") from exc
        self._sync_firewall_state(journal=False)

    def _remove_global_rules(self) -> bool:
        manager = self._get_firewall_manager()
        result = manager.remove_global_rules()
        self._sync_firewall_state(journal=False)
        return result

    def _get_mitm_manager(self) -> MitmProxyManager:
        if hasattr(self, "mitm_manager") and self.mitm_manager is not None:
            return self.mitm_manager
        manager = MitmProxyManager(getattr(self, "own_ip", None))
        self.mitm_manager = manager
        return manager

    def _get_recovery_manager(self) -> RecoveryManager:
        if hasattr(self, "recovery_manager") and self.recovery_manager is not None:
            return self.recovery_manager
        manager = RecoveryManager(getattr(self, "interface", ""))
        self.recovery_manager = manager
        return manager

    # ── Discovery ─────────────────────────────────────────────────────────────
    def discover(self) -> List[Device]:
        from netshaper.exceptions import DiscoveryError
        # Ensure the immutable policy is present and use its CIDRs.
        if not getattr(self, "_auth_policy", None):
            raise ValueError("authorized_cidrs is empty; refusing discovery")
        authorized_cidrs = self._auth_policy.cidrs
        if config.DRY_RUN:
            print_flush("[DRY-RUN] Device discovery skipped")
            return []
        subnet = self.disc.get_subnet_v4()
        if not subnet:
            raise DiscoveryError("Could not determine subnet.")
        devices = self.disc.arp_sweep(subnet, self.gw, authorized_cidrs)
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
        shaping_profile: Optional[ShapingProfile] = None,
    ) -> None:
        """Add an interception session.

        Backward-compatibility: the CLI passes `target` as an IP string.
        Newer internal code may pass a `Device`.
        """
        target_ip = target if isinstance(target, str) else target.ip
        with self._lifecycle_lock:
            if target_ip in self.sessions:
                raise ValueError(f"Target {target_ip} is already active.")
        self._assert_authorized_target(target_ip)

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
                journal=self._journal_state_if_ready,
            )
            self.sessions[target.ip] = session

        try:
            session.setup(
                dns_spoof=dns_spoof,
                captive_portal=captive_portal,
                http_redirect_port=http_redirect_port,
                limit=limit,
                shaping_profile=shaping_profile,
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
                lambda: getattr(self, "mitm_manager", None) and self.mitm_manager.terminate(),
            )
            cleanup_step("global rules", self._remove_global_rules)
            cleanup_step(
                "state snapshot",
                lambda: (
                    StateSnapshotManager.restore(
                        self.state_snapshot,
                        restore_firewall=False,
                    )
                    or (_ for _ in ()).throw(RuntimeError("state snapshot restore failed"))
                ),
            )
            cleanup_step("traffic shaper", self.shaper.cleanup)

            state_path = self._state_path()
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
            manager = self._get_mitm_manager()
            ok = manager.launch(port=port, web_port=web_port)
            st = manager.get_state_for_persistence() or {}
            self._mitm_log_path = st.get("mitm_log_path")
            return ok
        except MitmProxyError:
            print_flush("  [!] mitmweb not found.  pip install mitmproxy")
            return False

    def _terminate_mitmproxy(self) -> bool:
        try:
            ok = getattr(self, "mitm_manager", None) and self.mitm_manager.terminate()
            return bool(ok)
        finally:
            self._mitm_log_path = None

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
        return StateSnapshotManager.snapshot_from_state(data)

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
        targets = [
            {
                "ip": s.target.ip,
                "dns": self._session_dns_recorded(s),
                "limit": s.limit,
                "shaping_profile": (
                    asdict(getattr(s, "shaping_profile"))
                    if getattr(s, "shaping_profile", None) is not None
                    else None
                ),
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
                ),
            }
            for s in self.sessions.values()
        ]

        firewall_state = (
            self._get_firewall_manager().get_state_for_persistence() or {}
        )

        data = {
            "session_id": self.session_id,
            "interface": self.interface,
            "targets": targets,
            "gw": self.gw,
            "own_ip": self.own_ip,
            **firewall_state,
            "shaper_base_initialized": getattr(
                getattr(self, "shaper", None), "_base_initialized", False),
            "shaper_root_qdisc_pending": getattr(
                getattr(self, "shaper", None), "_root_qdisc_pending", False),
            "owner": getattr(self, "_owner_metadata", {}),
            "snapshot": self._snapshot_to_dict(self.state_snapshot),
        }
        if config.DRY_RUN:
            self._dry_run_state = data
            return True
        try:
            state_dir = self._session_state_dir()
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
        # Delegate stale session recovery to the refactored RecoveryManager
        if not os.path.isdir(config.STATE_DIR):
            return True
        recovery_ok = self._get_recovery_manager().recover_stale_state()
        if recovery_ok and getattr(self, "interface", None):
            self.state_snapshot = StateSnapshotManager.capture(
                self.interface,
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
                        end='', flush=True)
                old = new
            except Exception as e:
                log.debug(f"[Monitor] Counter read error: {e}")
        # Erase the \r line so shutdown messages start on a clean line
        print_flush("\r" + " " * 40 + "\r", end='')
