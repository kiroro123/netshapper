"""
NetShaper — main orchestrator.

Owns the session lifecycle (_lifecycle_lock guards add/remove),
global iptables forwarding rules, atomic state persistence,
sniffer management, and the bandwidth monitor thread.
"""

from __future__ import annotations

import fcntl
import http.client
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
import json
import logging
import os
import secrets
import socket
import subprocess  # nosec B404
import sys
import threading
import time
import uuid
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Sequence, Union

import psutil

from netshaper import config
from netshaper.capture.sniffer import PacketSniffer, RollingPacketSniffer
from netshaper.core.authorization import AuthorizationPolicy
from netshaper.core.firewall_manager import FirewallManager
from netshaper.core.mitm_manager import MitmProxyManager, MitmProxyError
from netshaper.core.owner import current_owner_metadata
from netshaper.core.recovery_manager import RecoveryManager
from netshaper.core.session import TargetSession
from netshaper.core.plugin import PluginInterface, PluginManager
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
        self.interface = interface
        self.session_id = f"NS-{uuid.uuid4().hex[:6].upper()}"
        self.disc = NetworkDiscovery(interface)
        self.own_ip = self.disc.get_own_ip()
        self.own_mac = self.disc.get_own_mac()
        self.own_ipv6 = self.disc.get_own_ipv6()
        self.gw = self.disc.get_default_gateway()
        self.gw_mac = (
            None
            if config.DRY_RUN
            else self.disc.resolve_mac(self.gw)
            if self.gw
            else None
        )
        self.gw_ipv6 = self.disc.get_default_gateway_ipv6()
        self.shaper = TrafficShaper(interface, self.session_id)
        self.mark_pool = MarkIDPool()
        self.firewall_manager = FirewallManager(
            interface,
            self.session_id,
            journal=self._sync_firewall_state,
            target_authorizer=self._assert_authorized_target,
        )
        self.mitm_manager = MitmProxyManager(getattr(self, "own_ip", None))
        self.recovery_manager = RecoveryManager(interface)
        self.sessions: Dict[str, TargetSession] = {}
        self.plugins: Dict[str, PluginInterface] = {}
        # RLock so remove_target() can be called re-entrantly from cleanup()
        self._lifecycle_lock = threading.RLock()
        self.is_shutting_down = False
        self.sniffer: Optional[Union[PacketSniffer, RollingPacketSniffer]] = None
        self.stop_event = threading.Event()
        self._mitm_log_path: Optional[str] = None
        self._fake_server_proc: Optional[subprocess.Popen] = None
        self._fake_server_health_token: Optional[str] = None
        self._arp_amplifier = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._runtime_errors: List[str] = []
        self._started_at: Optional[float] = None
        self._cleanup_running = False
        self._cleanup_complete = False
        self._active_cleanup_attempted = False
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
                        and hasattr(item, "prefixlen")
                    ):
                        raise ValueError(f"invalid authorized CIDR object: {item!r}")
                    networks.append(item)
        if not networks:
            raise ValueError("authorized_cidrs is required before creating NetShaper")
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
            connected_networks=self._connected_networks_for_authorization(),
        )

    def _connected_networks_for_authorization(self) -> tuple:
        disc = getattr(self, "disc", None)
        if not disc or not hasattr(disc, "get_connected_networks"):
            return ()
        networks = disc.get_connected_networks()
        if not isinstance(networks, (list, tuple)):
            return ()
        return tuple(networks)

    def _current_owner_metadata(self) -> dict:
        return current_owner_metadata()

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
                f"Another NetShaper instance is already running: {owner}"
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

    def _capture_dir(self) -> str:
        return os.path.join(self._session_state_dir(), "captures")

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
        rolling: bool = False,
    ) -> List[str]:
        started_at = self._started_at or time.time()
        lines = [
            f"Session ID: {self.session_id}",
            f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S %z', time.localtime(started_at))}",
            f"Interface: {self.interface}",
            f"Targets: {', '.join(target_ips or []) or '-'}",
            "State file: "
            + ("dry-run memory only" if config.DRY_RUN else self._state_path()),
            "Log file: " + ("console only" if config.DRY_RUN else config.LOG_FILE),
        ]

        monitor_thread = getattr(self, "_monitor_thread", None)
        lines.append(
            "Monitor thread: "
            + (
                "running"
                if monitor_thread and monitor_thread.is_alive()
                else "not running"
            )
        )

        sniffer = getattr(self, "sniffer", None)
        if sniffer:
            if hasattr(sniffer, "is_running"):
                sniffer_status = "running" if sniffer.is_running() else "not running"
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
        if self.plugins:
            lines.append(
                "Plugins: "
                + ", ".join(
                    f"{plugin.instance_id}({type(plugin).__name__})"
                    for plugin in self.plugins.values()
                )
            )

        errors = getattr(self, "_runtime_errors", [])
        lines.append("Runtime errors: " + ("; ".join(errors) if errors else "none"))
        return lines

    def runtime_health_issues(
        self,
        *,
        expect_sniffer: bool = False,
        expect_monitor: bool = False,
        expected_tcp_ports: Optional[List[int]] = None,
        expected_udp_ports: Optional[List[int]] = None,
    ) -> List[str]:
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

        amplifier = getattr(self, "_arp_amplifier", None)
        if amplifier and hasattr(amplifier, "health_issues"):
            issues.extend(amplifier.health_issues())

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
        for unit in ("B", "KB", "MB", "GB"):
            if abs(val) < 1024:
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
            target_authorizer=self._assert_authorized_target,
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
    def discover(self, max_discovery_hosts: Optional[int] = None) -> List[Device]:
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
        arp_kwargs: dict[str, Any] = {}
        if max_discovery_hosts is not None:
            arp_kwargs["max_discovery_hosts"] = max_discovery_hosts
        devices = self.disc.arp_sweep(subnet, self.gw, authorized_cidrs, **arp_kwargs)
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
        arp_interval: float = 2.0,
        arp_burst: int = 1,
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
        if isinstance(target, Device) and target.ipv6:
            self._assert_authorized_target(target.ipv6)

        # Resolve IP -> Device if needed
        if isinstance(target, str):
            ip = target
            mac = (
                "00:00:00:00:00:00"
                if config.DRY_RUN
                else self.disc.resolve_mac(ip)
                if ip
                else None
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

        forwarding_addresses = [target.ip]
        if target.ipv6 and target.ipv6 != target.ip:
            forwarding_addresses.append(target.ipv6)
        forwarding_manager: Optional[FirewallManager] = None

        try:
            session.setup(
                dns_spoof=dns_spoof,
                captive_portal=captive_portal,
                http_redirect_port=http_redirect_port,
                limit=limit,
                shaping_profile=shaping_profile,
                mark_base=mark_base,
            )
            forwarding_manager = self._get_firewall_manager()
            for address in forwarding_addresses:
                forwarding_manager.add_target_rules(address)
            session.start_spoof(
                arp_on=arp_on,
                interval=arp_interval,
                burst=arp_burst,
            )
        except Exception as exc:
            cleanup_ok = True
            if forwarding_manager is not None:
                for address in reversed(forwarding_addresses):
                    try:
                        cleanup_ok = (
                            forwarding_manager.remove_target_rules(address)
                            and cleanup_ok
                        )
                    except Exception as cleanup_exc:
                        log.error(
                            "Forwarding rollback for %s failed: %s",
                            address,
                            cleanup_exc,
                        )
                        cleanup_ok = False
            try:
                cleanup_ok = session.cleanup() and cleanup_ok
            except Exception as cleanup_exc:
                log.error(f"Rollback cleanup for {target.ip} failed: {cleanup_exc}")
                cleanup_ok = False
            if cleanup_ok:
                with self._lifecycle_lock:
                    if self.sessions.get(target.ip) is session:
                        del self.sessions[target.ip]
                if self._journal_state_if_ready():
                    self.mark_pool.release(target.ip)
                else:
                    with self._lifecycle_lock:
                        self.sessions[target.ip] = session
                    cleanup_ok = False
                    log.error(
                        "Keeping failed target %s because rollback state "
                        "could not be persisted",
                        target.ip,
                    )
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
            f"Portal={captive_portal} HTTP→{http_redirect_port} "
            f"ARP-burst={arp_burst}@{arp_interval:.2f}s)"
        )

    def remove_target(self, ip: str) -> bool:
        with self._lifecycle_lock:
            session = self.sessions.get(ip)
            if not session:
                return True
            session.active = False
            session.is_shutting_down = True
        # Cleanup outside lock — spoof threads exit naturally via flag check.
        # Remove forwarding first so its incremental journal writes retain the
        # target firewall chain metadata needed for exact crash recovery.
        ok = True
        forwarding_manager = self._get_firewall_manager()
        forwarding_addresses = [ip]
        target_ipv6 = getattr(getattr(session, "target", None), "ipv6", None)
        if isinstance(target_ipv6, str) and target_ipv6 and target_ipv6 != ip:
            forwarding_addresses.append(target_ipv6)
        for address in reversed(forwarding_addresses):
            ok = forwarding_manager.remove_target_rules(address) and ok
        ok = session.cleanup() and ok
        if ok:
            with self._lifecycle_lock:
                if self.sessions.get(ip) is session:
                    del self.sessions[ip]
            if self._journal_state_if_ready():
                self.mark_pool.release(ip)
                log.info(f"Target {ip} removed")
            else:
                with self._lifecycle_lock:
                    self.sessions[ip] = session
                ok = False
                log.error(
                    "Target %s cleanup completed but state removal "
                    "could not be persisted",
                    ip,
                )
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
            self._active_cleanup_attempted = True
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
                    s.active = False
                    s.is_shutting_down = True

            for ip in list(self.sessions.keys()):
                cleanup_step(f"target {ip}", lambda ip=ip: self.remove_target(ip))
            cleanup_step(
                "sniffer",
                lambda: (
                    self.sniffer.stop()
                    if self.sniffer and hasattr(self.sniffer, "stop")
                    else None
                ),
            )
            cleanup_step(
                "mitmproxy",
                lambda: (
                    getattr(self, "mitm_manager", None)
                    and self.mitm_manager.terminate()
                ),
            )
            cleanup_step("fake server", self._terminate_fake_server)
            cleanup_step("plugins", self._cleanup_plugins)
            cleanup_step("ARP amplification", self._stop_arp_amplification)
            cleanup_step("global rules", self._remove_global_rules)
            cleanup_step(
                "state snapshot",
                lambda: (
                    StateSnapshotManager.restore(
                        self.state_snapshot,
                        restore_firewall=False,
                    )
                    or (_ for _ in ()).throw(
                        RuntimeError("state snapshot restore failed")
                    )
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

    def register_plugin(
        self,
        plugin_id: str,
        scope: dict[str, Any],
        config: dict[str, Any] | None = None,
    ) -> str:
        plugin_cls = PluginManager.get(plugin_id)
        config = config or {}
        plugin_cls.validate_scope(scope, self._auth_policy)
        plugin = plugin_cls.new_instance(scope, config, self._auth_policy)
        self.plugins[plugin.instance_id] = plugin
        return plugin.instance_id

    def start_plugin(self, instance_id: str) -> bool:
        plugin = self.plugins.get(instance_id)
        if plugin is None:
            raise ValueError(f"unknown plugin instance {instance_id}")
        if config.DRY_RUN:
            print_flush(f"[DRY-RUN] Would start plugin {instance_id}")
            return True

        # Persist a pending marker before a plugin can mutate host state. Crash
        # recovery treats this marker like an active plugin.
        plugin._start_pending = True
        if not self.save_state():
            plugin._start_pending = False
            log.error("Refusing to start plugin %s without recovery state", instance_id)
            return False

        try:
            result = plugin.start()
        except Exception:
            try:
                stopped = plugin.stop()
            except Exception as exc:
                log.error("Plugin rollback failed (%s): %s", instance_id, exc)
                stopped = False
            plugin._start_pending = not stopped
            if stopped:
                plugin.active = False
            self.save_state()
            raise

        if not result:
            try:
                stopped = plugin.stop()
            except Exception as exc:
                log.error("Plugin rollback failed (%s): %s", instance_id, exc)
                stopped = False
            plugin._start_pending = not stopped
            if stopped:
                plugin.active = False
            self.save_state()
            return False

        plugin._start_pending = False
        plugin.active = True
        if self.save_state():
            return True

        log.error("Plugin %s started but final state persistence failed", instance_id)
        try:
            stopped = plugin.stop()
        except Exception as exc:
            log.error("Plugin rollback failed (%s): %s", instance_id, exc)
            stopped = False
        if stopped:
            plugin.active = False
            self.save_state()
        return False

    def stop_plugin(self, instance_id: str) -> bool:
        plugin = self.plugins.get(instance_id)
        if plugin is None:
            return True
        result = plugin.stop()
        if result:
            self.plugins.pop(instance_id, None)
            self.save_state()
        return result

    def _cleanup_plugins(self) -> bool:
        ok = True
        removed_any = False
        for instance_id in list(self.plugins):
            plugin = self.plugins[instance_id]
            try:
                if plugin.stop():
                    self.plugins.pop(instance_id, None)
                    removed_any = True
                else:
                    ok = False
            except Exception as exc:
                log.error("Plugin cleanup failed (%s): %s", instance_id, exc)
                ok = False
        if removed_any and not self.save_state():
            log.error("Could not persist plugin cleanup state")
            ok = False
        return ok

    @staticmethod
    def _remove_state_file(state_path: str) -> None:
        if os.path.exists(state_path):
            os.remove(state_path)
        try:
            os.rmdir(os.path.dirname(state_path))
        except OSError:
            pass

    # ── Sniffer ───────────────────────────────────────────────────────────────
    def _ipv4_subnet_for_amplification(self):
        if not self.own_ip:
            raise RuntimeError(
                "ARP amplification requires an IPv4 address on the selected "
                "interface."
            )
        own = ip_address(self.own_ip)
        if not isinstance(own, IPv4Address):
            raise RuntimeError(
                "ARP amplification requires an IPv4 address on the selected "
                "interface."
            )

        connected_raw = self.disc.get_subnet_v4() if self.disc else None
        if not connected_raw:
            raise RuntimeError(
                "ARP amplification requires an IPv4 network directly connected "
                "to the selected interface."
            )
        connected = ip_network(connected_raw, strict=False)
        if not isinstance(connected, IPv4Network) or own not in connected:
            raise RuntimeError(
                "ARP amplification requires the selected interface IPv4 address "
                "to belong to its directly connected network."
            )

        if self.gw:
            gateway = ip_address(self.gw)
            if not isinstance(gateway, IPv4Address) or gateway not in connected:
                raise RuntimeError(
                    "ARP amplification requires a gateway directly connected to "
                    "the selected interface."
                )

        v4_networks = [
            network for network in self.authorized_cidrs if network.version == 4
        ]
        for network in v4_networks:
            if network.subnet_of(connected):
                return network
            if connected.subnet_of(network):
                return connected
        raise RuntimeError(
            "ARP amplification requires an authorized IPv4 network directly "
            "connected to the selected interface."
        )

    def start_arp_amplification(
        self,
        *,
        phantom_count: int = 0,
        burst: int = 5,
        interval: float = 0.1,
        cam_exhaust: int = 0,
    ) -> None:
        if not phantom_count and not cam_exhaust:
            return
        if config.DRY_RUN:
            print_flush(
                "[DRY-RUN] Would start ARP amplification "
                f"(phantoms={phantom_count}, cam={cam_exhaust})"
            )
            return
        if not self.gw or not self.gw_mac:
            raise RuntimeError(
                "ARP amplification requires a reachable gateway IP and MAC."
            )

        from netshaper.network.exploit.arp_amplification import (
            ARPAmplificationProfile,
            ARPAmplifier,
        )

        subnet = self._ipv4_subnet_for_amplification()
        amplifier = ARPAmplifier(self.interface, self.own_mac)
        bounded_burst = max(1, min(burst, ARPAmplifier.MAX_BURST))
        bounded_interval = max(ARPAmplifier.MIN_INTERVAL, interval)

        if phantom_count:
            profile = ARPAmplificationProfile(
                gateway_ip=self.gw,
                gateway_mac=self.gw_mac,
                attacker_mac=self.own_mac,
                subnet=subnet,
                phantom_count=phantom_count,
                burst_size=bounded_burst,
                cycle_interval=bounded_interval,
            )
            amplifier.add_subnet_profile(profile)
            amplifier.start()

        if cam_exhaust:
            amplifier.start_cam_exhaustion(
                self.gw,
                subnet,
                phantom_count=cam_exhaust,
                burst=bounded_burst,
                interval=bounded_interval,
            )

        self._arp_amplifier = amplifier
        log.info(
            f"ARP amplification started (phantoms={phantom_count}, cam={cam_exhaust})"
        )

    def launch_fake_server(
        self,
        *,
        suppress_dnssec: bool = False,
        dnssec_mode: str = "off",
        web_security_demo: bool = False,
        dns_upstream: str = "8.8.8.8",
        smart_spoof_all: bool = False,
    ) -> bool:
        """Launch netshaper-fake-server when DNS/HTTP services are required."""
        if dnssec_mode not in {
            "off",
            "fail-closed",
            "fail-open",
            "nxdomain",
            "timeout",
        }:
            raise ValueError(f"invalid DNSSEC mode: {dnssec_mode}")
        if suppress_dnssec and dnssec_mode == "off":
            dnssec_mode = "fail-open"
        if config.DRY_RUN:
            print_flush(
                "[DRY-RUN] Would launch netshaper-fake-server "
                f"(dnssec={dnssec_mode}, hsts={web_security_demo}, "
                f"smart-spoof-all={smart_spoof_all})"
            )
            return True

        health_token = self._fake_server_token()
        if self.fake_server_ready():
            log.info("netshaper-fake-server already ready for this session")
            return True

        if self._fake_server_proc and self._fake_server_proc.poll() is None:
            log.debug("Waiting for existing netshaper-fake-server child")
        else:
            dns_claimed = check_local_port(self.own_ip, 53, socket.SOCK_DGRAM)
            http_claimed = check_local_port(self.own_ip, 80)
            if dns_claimed or http_claimed:
                log.error(
                    "Refusing to adopt unverified fake-server listener "
                    "(dns=%s, http=%s). Stop the existing listener or relaunch "
                    "it with the session health token printed by NetShaper.",
                    dns_claimed,
                    http_claimed,
                )
                return False

            cmd = [
                sys.executable,
                "-m",
                "netshaper.fake_server3",
                "--host-ip",
                self.own_ip,
                "--upstream",
                dns_upstream,
                "--health-token",
                health_token,
            ]
            if smart_spoof_all:
                cmd.append("--smart-spoof-all")
            if dnssec_mode != "off":
                cmd.extend(["--dnssec-mode", dnssec_mode])
            allowed_cidrs = {
                str(network) for network in self.authorized_cidrs
            }
            allowed_cidrs.add(f"{self.own_ip}/32")
            for allowed_cidr in sorted(allowed_cidrs):
                cmd.extend(["--allow-cidr", allowed_cidr])
            if web_security_demo:
                cmd.append("--web-security-demo")

            try:
                self._fake_server_proc = subprocess.Popen(  # nosec B603
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError as exc:
                log.error(f"fake server launch failed: {exc}")
                return False

        for _ in range(20):
            if self.fake_server_ready():
                log.info("netshaper-fake-server ready")
                return True
            if self._fake_server_proc.poll() is not None:
                log.error(
                    "netshaper-fake-server exited during startup "
                    f"with code {self._fake_server_proc.returncode}"
                )
                self._terminate_fake_server()
                return False
            time.sleep(0.25)

        log.error("netshaper-fake-server did not become reachable within 5s")
        self._terminate_fake_server()
        return False

    def _fake_server_token(self) -> str:
        token = getattr(self, "_fake_server_health_token", None)
        if not token:
            token = secrets.token_urlsafe(32)
            self._fake_server_health_token = token
        return token

    def fake_server_health_token(self) -> str:
        """Return the token required to verify a manually launched fake server."""
        return self._fake_server_token()

    def fake_server_ready(self) -> bool:
        return self._fake_server_health_ready(self._fake_server_token())

    def _fake_server_health_ready(self, token: str) -> bool:
        conn: Optional[http.client.HTTPConnection] = None
        try:
            conn = http.client.HTTPConnection(self.own_ip, 80, timeout=1.0)
            conn.request(
                "GET",
                "/_netshaper/health",
                headers={"X-NetShaper-Session": token},
            )
            response = conn.getresponse()
            body = response.read(256).decode("utf-8", errors="replace")
            return (
                response.status == 200
                and response.getheader("X-NetShaper-Session") == token
                and body == token
            )
        except Exception:
            return False
        finally:
            if conn is not None:
                conn.close()

    def _terminate_fake_server(self) -> bool:
        proc = getattr(self, "_fake_server_proc", None)
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
                log.info("netshaper-fake-server terminated")
        except Exception as exc:
            ok = False
            log.error(f"fake server cleanup failed: {exc}")

        if ok:
            self._fake_server_proc = None
        return ok

    def _stop_arp_amplification(self) -> None:
        amplifier = getattr(self, "_arp_amplifier", None)
        if not amplifier:
            return
        try:
            amplifier.shutdown()
        except Exception as exc:
            log.error(f"ARP amplification cleanup failed: {exc}")
        finally:
            self._arp_amplifier = None

    def launch_sniffer(
        self,
        target_ips: Optional[List[str]] = None,
        save_pcap: bool = False,
        rolling: bool = False,
        packet_verbose: bool = False,
    ) -> None:
        if config.DRY_RUN:
            print_flush("[DRY-RUN] Would launch packet sniffer")
            return
        if self.sniffer:
            self.sniffer.stop()
        if rolling:
            self.sniffer = RollingPacketSniffer(
                self.interface,
                target_ips=target_ips,
                capture_dir=self._capture_dir(),
                packet_verbose=packet_verbose,
            )
        else:
            self.sniffer = PacketSniffer(
                self.interface,
                target_ips=target_ips,
                save_pcap=save_pcap,
                capture_dir=self._capture_dir(),
                packet_verbose=packet_verbose,
            )
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
            log.error(
                "Refusing to adopt existing listener on mitmproxy port :%s",
                port,
            )
            return False
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
        try:
            self._terminate_mitmproxy()
            self._terminate_fake_server()
            self._stop_arp_amplification()
            had_plugins = bool(getattr(self, "plugins", {}))
            plugins_ok = self._cleanup_plugins()
            if (
                had_plugins
                and plugins_ok
                and not getattr(self, "_active_cleanup_attempted", False)
            ):
                # A plugin may have created a pre-session recovery manifest.
                # Once it is stopped successfully there are no network
                # resources to recover, so remove that manifest.
                state_path = self._state_path()
                if not config.DRY_RUN and os.path.exists(state_path):
                    self._remove_state_file(state_path)
        finally:
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
    def _json_safe(value):
        """Convert supported structured values to JSON-safe equivalents."""
        if isinstance(value, (IPv4Address, IPv6Address, IPv4Network, IPv6Network)):
            return str(value)
        if isinstance(value, dict):
            return {str(key): NetShaper._json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [NetShaper._json_safe(item) for item in value]
        return value

    @staticmethod
    def _session_dns_recorded(session: TargetSession) -> bool:
        firewall = session.firewall
        return (
            session.dns_on
            or bool(getattr(firewall, "_dns_input_rules", set()) if firewall else False)
            or bool(getattr(firewall, "_dns_added", False) if firewall else False)
        )

    def save_state(self) -> bool:
        lifecycle_lock = getattr(self, "_lifecycle_lock", None)
        if lifecycle_lock is None:
            sessions = tuple(self.sessions.values())
        else:
            with lifecycle_lock:
                sessions = tuple(self.sessions.values())

        targets = [
            {
                "ip": s.target.ip,
                "ipv6": getattr(s.target, "ipv6", None),
                "dns": self._session_dns_recorded(s),
                "limit": s.limit,
                "shaping_profile": (
                    asdict(s.shaping_profile)
                    if getattr(s, "shaping_profile", None) is not None
                    else None
                ),
                "http_redirect_port": (
                    getattr(s.firewall, "_http_redirect_port", None)
                    if s.firewall
                    else None
                ),
                "firewall_rule_comment": (
                    getattr(s.firewall, "_rule_comment", None) if s.firewall else None
                ),
                "mangle_chain": (
                    getattr(s.firewall, "MANGLE", None) if s.firewall else None
                ),
                "nat_chain": (getattr(s.firewall, "NAT", None) if s.firewall else None),
            }
            for s in sessions
        ]

        firewall_state = self._get_firewall_manager().get_state_for_persistence() or {}
        shaper = getattr(self, "shaper", None)
        shaper_state: dict[str, Any] = {}
        shaper_state_method = getattr(shaper, "get_state_for_persistence", None)
        if callable(shaper_state_method):
            try:
                candidate = shaper_state_method()
            except Exception:
                candidate = {}
            if isinstance(candidate, dict):
                shaper_state = candidate

        data = {
            "session_id": self.session_id,
            "interface": self.interface,
            "targets": targets,
            "gw": self.gw,
            "own_ip": self.own_ip,
            **firewall_state,
            "shaper_base_initialized": getattr(
                getattr(self, "shaper", None), "_base_initialized", False
            ),
            "shaper_root_qdisc_pending": getattr(
                getattr(self, "shaper", None), "_root_qdisc_pending", False
            ),
            "shaper_root_qdisc": shaper_state,
            "owner": getattr(self, "_owner_metadata", {}),
            "snapshot": self._snapshot_to_dict(self.state_snapshot),
            "plugins": [
                {
                    "instance_id": plugin.instance_id,
                    "plugin_id": type(plugin).PLUGIN_ID,
                    "scope": self._json_safe(plugin.scope),
                    "config": self._json_safe(plugin.config),
                    "active": plugin.active,
                    "start_pending": bool(
                        getattr(plugin, "_start_pending", False)
                    ),
                    "state": self._json_safe(plugin.get_state_for_persistence()),
                }
                for plugin in self.plugins.values()
            ],
        }
        if config.DRY_RUN:
            self._dry_run_state = data
            return True
        try:
            state_dir = self._session_state_dir()
            os.makedirs(state_dir, mode=0o700, exist_ok=True)
            StateSnapshotManager.atomic_write_json(
                os.path.join(state_dir, "state.json"),
                data,
            )
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
                        f"\r  TX:{self.scale_bytes(tx)}  RX:{self.scale_bytes(rx)}   ",
                        end="",
                        flush=True,
                    )
                old = new
            except Exception as e:
                log.debug(f"[Monitor] Counter read error: {e}")
        # Erase the \r line so shutdown messages start on a clean line
        print_flush("\r" + " " * 40 + "\r", end="")
