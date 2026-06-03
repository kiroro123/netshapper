"""
netshaper.core
──────────────
Central orchestrator and per-target session container.

TargetSession — holds all per-target runtime state (spoofers, firewall,
                shaper references). active and is_shutting_down are plain
                booleans read locklessly by spoof threads (CPython atomic).
                Write only from within NetShaper._lifecycle_lock.

NetShaper     — top-level controller: discovers devices, manages sessions,
                launches auxiliary services (mitmproxy, sniffer), saves/
                loads state, and performs graceful shutdown.
"""

import os
import sys
import json
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import logging
from typing import Dict, List, Optional

import psutil

from .models    import Device
from .discovery import NetworkDiscovery
from .spoof     import ARPSpoofer, NDPSpoofer
from .firewall  import FirewallManager
from .shaper    import TrafficShaper, MarkIDPool
from .sniffer   import PacketSniffer, RollingPacketSniffer
from .system    import SubprocessRunner, check_local_port, print_flush, safe_input

log = logging.getLogger("netshaper")

STATE_FILE = "/tmp/netshaper.state"


# ── Target Session ────────────────────────────────────────────────────────────

class TargetSession:
    """
    All per-target runtime state in one place.

    active / is_shutting_down — lockless boolean flags read by spoof threads.
    Write these only while holding NetShaper._lifecycle_lock.
    """

    def __init__(self, target: Device, interface: str,
                 own_mac: str, own_ip: str, own_ipv6: Optional[str],
                 gateway_ip: str, gateway_mac: str, gateway_ipv6: Optional[str],
                 shaper: TrafficShaper):
        self.target           = target
        self.interface        = interface
        self.own_mac          = own_mac
        self.own_ip           = own_ip
        self.own_ipv6         = own_ipv6
        self.gateway_ip       = gateway_ip
        self.gateway_mac      = gateway_mac
        self.gateway_ipv6     = gateway_ipv6
        self.shaper           = shaper
        self.active           = True   # Lockless read by spoof loops
        self.is_shutting_down = False
        self.arp_spoof        = None
        self.ndp_spoof        = None
        self.firewall         = None
        self.dns_on           = False
        self.throttle_on      = False
        self.limit            = None
        self._mark_id         = None

    def setup(self, dns_spoof: bool = False,
              captive_portal: bool = False,
              http_redirect_port: Optional[int] = None,
              limit=None,
              mark_base: int = 10):
        self.firewall = FirewallManager(self.target.ip, self.interface)
        if dns_spoof or captive_portal or http_redirect_port:
            self.firewall.add_redirect_rules(
                dns_spoof=dns_spoof,
                captive_portal=captive_portal,
                http_redirect_port=http_redirect_port,
            )
            self.dns_on = dns_spoof
        if limit is not None:
            self.shaper.apply_target(self.target.ip, limit, mark_base)
            self.firewall.add_shaping(self.target.ip, mark_base)
            self.throttle_on = True
            self.limit        = limit
            self._mark_id     = mark_base

    def start_spoof(self, arp_on: bool = True):
        if arp_on and self.arp_spoof is None:
            self.arp_spoof = ARPSpoofer(
                self.interface, self.target.ip, self.target.mac,
                self.gateway_ip, self.gateway_mac, self.own_mac,
                self,  # pass self for lockless active check
            )
            self.arp_spoof.start()
        if (self.target.ipv6 and self.gateway_ipv6
                and self.ndp_spoof is None and arp_on):
            self.ndp_spoof = NDPSpoofer(
                self.interface, self.target.ipv6, self.target.mac,
                self.gateway_ipv6, self.gateway_mac, self.own_mac,
                self,
            )
            self.ndp_spoof.start()

    def stop_spoof(self):
        if self.arp_spoof:
            self.arp_spoof.shutdown()
        if self.ndp_spoof:
            self.ndp_spoof.shutdown()

    def cleanup(self):
        self.active = False
        self.stop_spoof()
        if self.firewall:
            self.firewall.cleanup()
        if self.throttle_on and self._mark_id is not None:
            self.shaper.cleanup_target(self._mark_id)


# ── Main Orchestrator ─────────────────────────────────────────────────────────

class NetShaper:
    def __init__(self, interface: str):
        self.interface  = interface
        self.disc       = NetworkDiscovery(interface)
        self.own_ip     = self.disc.get_own_ip()
        self.own_mac    = self.disc.get_own_mac()
        self.own_ipv6   = self.disc.get_own_ipv6()
        self.gw         = self.disc.get_default_gateway()
        self.gw_mac     = self.disc.resolve_mac(self.gw) if self.gw else None
        self.gw_ipv6    = self.disc.get_default_gateway_ipv6()
        self.shaper     = TrafficShaper(interface)
        self.mark_pool  = MarkIDPool()
        self.sessions:  Dict[str, TargetSession] = {}
        self._lifecycle_lock  = threading.RLock()  # RLock: remove_target re-entrant from cleanup_all
        self.is_shutting_down = False
        self.sniffer    = None
        self.stop       = threading.Event()
        self._global_rules_applied = False
        self._mitm_proc = None

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def scale_bytes(val: float) -> str:
        for unit in ["KB", "MB", "GB"]:
            if val < 1024:
                return f"{val:.1f} {unit}"
            val /= 1024
        return f"{val:.1f} TB"

    # ── Global iptables rules ─────────────────────────────────────────────────

    def _apply_global_rules(self):
        if self._global_rules_applied:
            return
        SubprocessRunner.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"], silent=True
        )
        SubprocessRunner.run(
            ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], silent=True
        )
        SubprocessRunner.run(
            ["sysctl", "-w",
             f"net.ipv4.conf.{self.interface}.route_localnet=1"],
            silent=True,
        )
        for binary in ["iptables", "ip6tables"]:
            if shutil.which(binary):
                SubprocessRunner.run(
                    [binary, "-A", "FORWARD",
                     "-i", self.interface, "-o", self.interface,
                     "-j", "ACCEPT"],
                    silent=True,
                )
                SubprocessRunner.run(
                    [binary, "-A", "FORWARD", "-m", "state",
                     "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                    silent=True,
                )
                SubprocessRunner.run(
                    [binary, "-t", "nat", "-A", "POSTROUTING",
                     "-o", self.interface, "-j", "MASQUERADE"],
                    silent=True,
                )
        self._global_rules_applied = True
        log.info("Global dual-stack forwarding + MASQUERADE enabled")

    def _remove_global_rules(self):
        SubprocessRunner.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=0"], silent=True
        )
        SubprocessRunner.run(
            ["sysctl", "-w", "net.ipv6.conf.all.forwarding=0"], silent=True
        )
        for binary in ["iptables", "ip6tables"]:
            if shutil.which(binary):
                SubprocessRunner.run(
                    [binary, "-D", "FORWARD",
                     "-i", self.interface, "-o", self.interface,
                     "-j", "ACCEPT"],
                    check=False, silent=True,
                )
                SubprocessRunner.run(
                    [binary, "-D", "FORWARD", "-m", "state",
                     "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                    check=False, silent=True,
                )
                SubprocessRunner.run(
                    [binary, "-t", "nat", "-D", "POSTROUTING",
                     "-o", self.interface, "-j", "MASQUERADE"],
                    check=False, silent=True,
                )
        self._global_rules_applied = False
        log.info("Global forwarding + MASQUERADE removed")

    # ── Discovery ─────────────────────────────────────────────────────────────

    def discover(self) -> List[Device]:
        subnet = self.disc.get_subnet_v4()
        if not subnet:
            sys.exit("[NetShaper] Could not determine subnet.")
        devices = self.disc.arp_sweep(subnet, self.gw)
        self.disc.resolve_hostnames(devices)
        return devices

    # ── Session lifecycle ─────────────────────────────────────────────────────

    def add_target(self, target: Device, arp_on: bool = True,
                   dns_spoof: bool = False,
                   captive_portal: bool = False,
                   http_redirect_port: Optional[int] = None,
                   limit=None):
        with self._lifecycle_lock:
            mark_base = self.mark_pool.acquire(target.ip)
            session   = TargetSession(
                target, self.interface, self.own_mac,
                self.own_ip, self.own_ipv6,
                self.gw, self.gw_mac, self.gw_ipv6,
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

    def remove_target(self, ip: str):
        with self._lifecycle_lock:
            session = self.sessions.get(ip)
            if not session:
                return
            # Signal spoof loops to exit (lockless read in their while conditions)
            session.active           = False
            session.is_shutting_down = True
            del self.sessions[ip]

        # Cleanup outside the lock — spoof threads exit naturally
        session.cleanup()
        self.mark_pool.release(ip)
        log.info(f"Target {ip} removed")

    # ── Full shutdown ─────────────────────────────────────────────────────────

    def cleanup(self):
        print_flush("\n--- NetShaper Shutdown ---")
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

        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
        log.info("Network restored.")

    # ── Auxiliary services ────────────────────────────────────────────────────

    def launch_sniffer(self, target_ips=None,
                       save_pcap: bool = False,
                       rolling: bool = False):
        if self.sniffer:
            self.sniffer.stop()
        if rolling:
            self.sniffer = RollingPacketSniffer(
                self.interface, target_ips=target_ips
            )
        else:
            self.sniffer = PacketSniffer(
                self.interface, target_ips=target_ips, save_pcap=save_pcap
            )
        self.sniffer.start()

    def launch_mitmproxy(self, port: int = 8088,
                         web_port: int = 8083) -> bool:
        """Launch mitmweb and poll for readiness (replaces hard sleep)."""
        if check_local_port(self.own_ip, port):
            log.info(f"mitmproxy already running on :{port}")
            return True
        try:
            self._mitm_proc = subprocess.Popen(
                ["mitmweb", "--mode", "transparent",
                 "--listen-port", str(port),
                 "--set", f"web_port={web_port}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for attempt in range(10):
                if check_local_port(self.own_ip, port):
                    print_flush(
                        f"  [+] mitmproxy ready → http://127.0.0.1:{web_port}"
                    )
                    return True
                log.debug(f"Waiting for mitmproxy… (attempt {attempt + 1}/10)")
                time.sleep(0.5)
            log.error(f"mitmproxy did not bind to :{port} within 5 s")
            return False
        except FileNotFoundError:
            print_flush("  [!] mitmweb not found.  pip install mitmproxy")
            return False

    # ── Bandwidth monitor ─────────────────────────────────────────────────────

    def monitor(self):
        old = psutil.net_io_counters(pernic=True).get(self.interface)
        while not self.stop.wait(2):
            new = psutil.net_io_counters(pernic=True).get(self.interface)
            if old and new:
                tx = new.bytes_sent - old.bytes_sent
                rx = new.bytes_recv - old.bytes_recv
                print_flush(
                    f"\r  TX:{self.scale_bytes(tx)}  RX:{self.scale_bytes(rx)}   ",
                    end='',
                )
            old = new
        print_flush()

    # ── State persistence ─────────────────────────────────────────────────────

    def save_state(self):
        data = {
            "interface": self.interface,
            "targets":   [
                {"ip": s.target.ip, "dns": s.dns_on, "limit": s.limit}
                for s in self.sessions.values()
            ],
            "gw":     self.gw,
            "own_ip": self.own_ip,
        }
        dir_name = os.path.dirname(STATE_FILE)
        try:
            with tempfile.NamedTemporaryFile(
                'w', dir=dir_name, delete=False
            ) as tf:
                json.dump(data, tf)
                tmp = tf.name
            os.replace(tmp, STATE_FILE)   # Atomic write
        except Exception as e:
            log.error(f"State save failed: {e}")

    def load_state_and_cleanup(self):
        """Recover and flush stale NS-* iptables chains left from a previous run."""
        if not os.path.exists(STATE_FILE):
            return
        try:
            with open(STATE_FILE) as f:
                data = json.load(f)
            iface = data.get("interface")
            if iface:
                print_flush(f"  [!] Stale session on {iface} — cleaning up…")
                for binary in ["iptables", "ip6tables"]:
                    if not shutil.which(binary):
                        continue
                    for table in ["nat", "mangle"]:
                        result = subprocess.run(
                            [binary, "-t", table, "-L", "--line-numbers"],
                            capture_output=True, text=True,
                        )
                        for line in result.stdout.splitlines():
                            for token in line.split():
                                if token.startswith("NS-"):
                                    SubprocessRunner.run(
                                        [binary, "-t", table, "-F", token],
                                        check=False, silent=True,
                                    )
                                    SubprocessRunner.run(
                                        [binary, "-t", table, "-X", token],
                                        check=False, silent=True,
                                    )
                SubprocessRunner.run(
                    ["tc", "qdisc", "del", "dev", iface, "root"],
                    check=False, silent=True,
                )
                SubprocessRunner.run(
                    ["sysctl", "-w", "net.ipv4.ip_forward=0"], silent=True
                )
                log.info("Stale rules cleaned.")
            os.remove(STATE_FILE)
        except Exception:
            log.debug("No valid state file to recover.")
