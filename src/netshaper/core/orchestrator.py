"""
NetShaper — main orchestrator.

Owns the session lifecycle (_lifecycle_lock guards add/remove),
global iptables forwarding rules, atomic state persistence,
sniffer management, and the bandwidth monitor thread.
"""
from __future__ import annotations

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
from netshaper.core.state_manager import StateSnapshotManager
from netshaper.models import Device, MarkIDPool
from netshaper.network.discovery import NetworkDiscovery
from netshaper.network.shaper import TrafficShaper
from netshaper.system import SubprocessRunner, SystemChecker, check_local_port
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
        self.gw_mac      = self.disc.resolve_mac(self.gw) if self.gw else None
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
        self._mitm_proc  = None
        self.state_snapshot = StateSnapshotManager.capture(interface, self.session_id)

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def scale_bytes(val: float) -> str:
        for unit in ["KB", "MB", "GB"]:
            if val < 1024:
                return f"{val:.1f} {unit}"
            val /= 1024
        return f"{val:.1f} TB"

    # ── Global forwarding rules ───────────────────────────────────────────────
    def _apply_global_rules(self) -> None:
        if self._global_rules_applied:
            return
        SubprocessRunner.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"], silent=True)
        SubprocessRunner.run(
            ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], silent=True)
        SubprocessRunner.run(
            ["sysctl", "-w",
             f"net.ipv4.conf.{self.interface}.route_localnet=1"],
            silent=True)
        for binary in ["iptables", "ip6tables"]:
            if shutil.which(binary):
                SubprocessRunner.run(
                    [binary, "-I", "FORWARD", "1",
                     "-i", self.interface, "-o", self.interface,
                     "-j", "ACCEPT"], silent=True)
                SubprocessRunner.run(
                    [binary, "-I", "FORWARD", "1", "-m", "state",
                     "--state", "ESTABLISHED,RELATED",
                     "-j", "ACCEPT"], silent=True)
                SubprocessRunner.run(
                    [binary, "-t", "nat", "-A", "POSTROUTING",
                     "-o", self.interface, "-j", "MASQUERADE"],
                    silent=True)
        self._global_rules_applied = True
        log.info("Global dual-stack forwarding + MASQUERADE enabled")

    def _restore_original_forwarding(self) -> None:
        if self.state_snapshot.ipv4_forwarding is not None:
            SubprocessRunner.run(
                ["sysctl", "-w", f"net.ipv4.ip_forward={self.state_snapshot.ipv4_forwarding}"],
                silent=True,
            )
        if self.state_snapshot.ipv6_forwarding is not None:
            SubprocessRunner.run(
                ["sysctl", "-w", f"net.ipv6.conf.all.forwarding={self.state_snapshot.ipv6_forwarding}"],
                silent=True,
            )

    def _remove_global_rules(self) -> None:
        self._restore_original_forwarding()
        for binary in ["iptables", "ip6tables"]:
            if shutil.which(binary):
                SubprocessRunner.run(
                    [binary, "-D", "FORWARD",
                     "-i", self.interface, "-o", self.interface,
                     "-j", "ACCEPT"], check=False, silent=True)
                SubprocessRunner.run(
                    [binary, "-D", "FORWARD", "-m", "state",
                     "--state", "ESTABLISHED,RELATED",
                     "-j", "ACCEPT"], check=False, silent=True)
                SubprocessRunner.run(
                    [binary, "-t", "nat", "-D", "POSTROUTING",
                     "-o", self.interface, "-j", "MASQUERADE"],
                    check=False, silent=True)
        self._global_rules_applied = False
        log.info("Global forwarding + MASQUERADE removed")

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
        # Resolve IP -> Device if needed
        if isinstance(target, str):
            ip = target
            mac = self.disc.resolve_mac(ip) if ip else None
            if not mac:
                raise ValueError(
                    f"Could not resolve MAC for target IP {ip}. "
                    f"Run discovery first or ensure ARP reachability."
                )
            target = Device(ip=ip, mac=mac)

        with self._lifecycle_lock:
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
            )
            session.setup(
                dns_spoof=dns_spoof,
                captive_portal=captive_portal,
                http_redirect_port=http_redirect_port,
                limit=limit,
                mark_base=mark_base,
            )
            session.start_spoof(arp_on=arp_on)
            self.sessions[target.ip] = session

        log.info(
            f"Target {target.ip} added "
            f"(ARP={arp_on} DNS={dns_spoof} "
            f"Portal={captive_portal} HTTP→{http_redirect_port})"
        )


    def remove_target(self, ip: str) -> None:
        with self._lifecycle_lock:
            session = self.sessions.get(ip)
            if not session:
                return
            session.active           = False
            session.is_shutting_down = True
            del self.sessions[ip]
        # Cleanup outside lock — spoof threads exit naturally via flag check
        session.cleanup()
        self.mark_pool.release(ip)
        log.info(f"Target {ip} removed")

    def cleanup(self) -> None:
        print_flush("\n--- NetShaper Shutdown ---")
        self.stop_event.set()
        with self._lifecycle_lock:
            self.is_shutting_down = True
            for s in self.sessions.values():
                s.active           = False
                s.is_shutting_down = True
        for ip in list(self.sessions.keys()):
            self.remove_target(ip)
        if self.sniffer and hasattr(self.sniffer, 'stop'):
            self.sniffer.stop()
        if self._mitm_proc:
            self._mitm_proc.terminate()
            log.info("mitmproxy terminated")
        self._remove_global_rules()
        self.shaper.cleanup()
        state_path = os.path.join(config.STATE_DIR, self.session_id, "state.json")
        if os.path.exists(state_path):
            os.remove(state_path)
        log.info("Network restored.")

    # Backward-compatible alias (older CLI expects stop())
    def stop(self) -> None:
        self.cleanup()


    # ── Sniffer ───────────────────────────────────────────────────────────────
    def launch_sniffer(self, target_ips: Optional[List[str]] = None,
                       save_pcap: bool = False, rolling: bool = False) -> None:
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
            return False
        except FileNotFoundError:
            print_flush("  [!] mitmweb not found.  pip install mitmproxy")
            return False

    # ── State persistence ─────────────────────────────────────────────────────
    def save_state(self) -> None:
        data = {
            "interface": self.interface,
            "targets":   [{"ip": s.target.ip, "dns": s.dns_on,
                           "limit": s.limit}
                          for s in self.sessions.values()],
            "gw":     self.gw,
            "own_ip": self.own_ip,
        }
        try:
            state_dir = os.path.join(config.STATE_DIR, self.session_id)
            os.makedirs(state_dir, mode=0o700, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                    'w', dir=state_dir, delete=False) as tf:
                json.dump(data, tf)
                tmp = tf.name
            os.replace(tmp, os.path.join(state_dir, "state.json"))   # Atomic write
        except Exception as e:
            log.error(f"State save failed: {e}")

    def load_state_and_cleanup(self) -> None:
        if not os.path.exists(config.STATE_FILE):
            return
        try:
            with open(config.STATE_FILE) as f:
                data = json.load(f)
            iface = data.get("interface")
            if iface:
                print_flush(f"  [!] Stale session on {iface} — cleaning up…")
                for binary in ["iptables", "ip6tables"]:
                    if not shutil.which(binary):
                        continue
                    for table in ["nat", "mangle"]:
                        # BUG FIX: grep "Chain NS-" header lines instead of
                        # tokenising every line (original could match rule targets)
                        result = subprocess.run(
                            [binary, "-t", table, "-n", "-L"],
                            capture_output=True, text=True)
                        for line in result.stdout.splitlines():
                            if line.startswith("Chain NS-"):
                                chain_name = line.split()[1]
                                SubprocessRunner.run(
                                    [binary, "-t", table, "-F", chain_name],
                                    check=False, silent=True)
                                SubprocessRunner.run(
                                    [binary, "-t", table, "-X", chain_name],
                                    check=False, silent=True)
                SubprocessRunner.run(
                    ["tc", "qdisc", "del", "dev", iface, "root"],
                    check=False, silent=True)
                SubprocessRunner.run(
                    ["sysctl", "-w", "net.ipv4.ip_forward=0"], silent=True)
                log.info("Stale rules cleaned.")
            os.remove(config.STATE_FILE)
        except Exception:
            log.debug("No valid state file to recover.")

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
