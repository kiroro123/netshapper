"""
netshaper.discovery
───────────────────
Network discovery: ARP sweep, passive sniffing, hostname resolution,
interface introspection, and gateway detection.

Reusable standalone — import NetworkDiscovery into any recon script
without pulling in spoof, firewall, or shaper logic.
"""

import socket
import struct
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Network
from typing import Dict, List, Optional

import psutil
from scapy.all import ARP, Ether, srp, sniff

from .models import Device
from .system import print_flush

log = logging.getLogger("netshaper")


class NetworkDiscovery:
    def __init__(self, interface: str):
        self.interface     = interface
        self.devices_dict: Dict[str, Device] = {}
        self.lock          = threading.Lock()  # Guards all devices_dict mutations

    # ── Interface introspection ───────────────────────────────────────────────

    def get_own_mac(self) -> str:
        for a in psutil.net_if_addrs().get(self.interface, []):
            if a.family == psutil.AF_LINK:
                return a.address.lower()
        try:
            return Ether().src.lower()
        except Exception:
            return ""

    def get_own_ip(self) -> Optional[str]:
        for a in psutil.net_if_addrs().get(self.interface, []):
            if a.family == socket.AF_INET:
                return a.address
        return None

    def get_own_ipv6(self) -> Optional[str]:
        for a in psutil.net_if_addrs().get(self.interface, []):
            if (a.family == socket.AF_INET6
                    and not a.address.startswith("fe80")):
                return a.address.split('%')[0]
        return None

    def get_subnet_v4(self) -> Optional[str]:
        for a in psutil.net_if_addrs().get(self.interface, []):
            if a.family == socket.AF_INET and a.netmask:
                try:
                    return str(
                        IPv4Network(f"{a.address}/{a.netmask}", strict=False)
                    )
                except ValueError:
                    pass
        return None

    def get_default_gateway(self) -> Optional[str]:
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if parts[1] == '00000000':
                        return socket.inet_ntoa(
                            struct.pack("<L", int(parts[2], 16))
                        )
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
                        blocks = [parts[4][i:i + 4] for i in range(0, 32, 4)]
                        return ':'.join(blocks)
        except Exception:
            pass
        return None

    def resolve_mac(self, ip: str) -> Optional[str]:
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=self.interface, timeout=3, verbose=0
            )
            if ans:
                return ans[0][1].src.lower()
        except Exception:
            pass
        return None

    # ── Passive ARP sniff callback ────────────────────────────────────────────

    def _passive_sniff_callback(self, pkt):
        """Thread-safe write to devices_dict from the passive sniff thread."""
        if ARP not in pkt:
            return
        for src_ip, src_mac in [
            (pkt[ARP].psrc, pkt[Ether].src.lower()),
            (pkt[ARP].pdst, pkt[Ether].dst.lower()),
        ]:
            if src_ip and src_ip != '0.0.0.0':
                with self.lock:
                    if src_ip not in self.devices_dict:
                        self.devices_dict[src_ip] = Device(
                            ip=src_ip, mac=src_mac, os_hint=""
                        )

    # ── Active ARP sweep + passive sniff ─────────────────────────────────────

    def arp_sweep(self, subnet: str, gateway_ip: str) -> List[Device]:
        log.info(f"ARP sweep on {subnet}")
        try:
            net     = IPv4Network(subnet, strict=False)
            targets = [str(ip) for ip in net.hosts() if str(ip) != gateway_ip]
            if not targets:
                return []

            for timeout_val in [2, 3, 4]:
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets),
                    iface=self.interface, timeout=timeout_val, verbose=0
                )
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
                    iface=self.interface,
                    filter="arp",
                    prn=self._passive_sniff_callback,
                    stop_filter=lambda _: stop_sniff.is_set(),
                    store=False,
                    timeout=15,
                ),
                daemon=True,
            )
            t.start()

            for remaining in range(15, 0, -1):
                if stop_sniff.is_set():
                    break
                with self.lock:
                    count = len(self.devices_dict)
                print_flush(
                    f"\r  Passive sniff: {remaining:2d}s | {count:2d} devices",
                    end='',
                )
                time.sleep(1)
            print_flush()
            stop_sniff.set()
            t.join(timeout=2)

        except Exception as e:
            log.error(f"ARP sweep failed: {e}")

        with self.lock:
            devices = list(self.devices_dict.values())
        return sorted(devices, key=lambda d: [int(i) for i in d.ip.split(".")])

    # ── Hostname resolution ───────────────────────────────────────────────────

    def resolve_hostnames(self, devices: List[Device]):
        """
        Non-blocking hostname resolution via a flat ThreadPoolExecutor.

        NOTE: gethostbyaddr() is a synchronous libc call that ignores Python
        socket timeouts. The future.result(timeout=0.5) boundary only stops
        *waiting* for the result — the worker thread stays alive until the OS
        resolves or times out (up to ~30 s).  For large subnets consider
        replacing resolve_worker with a subprocess call to `getent hosts`
        which respects a hard OS timeout.
        """
        def resolve_worker(d: Device) -> str:
            name, _, _ = socket.gethostbyaddr(d.ip)
            return name.lower() if name != d.ip else ""

        with ThreadPoolExecutor(max_workers=20) as pool:
            future_to_device = {pool.submit(resolve_worker, d): d
                                for d in devices}
            for future in as_completed(future_to_device, timeout=5.0):
                device = future_to_device[future]
                try:
                    device.hostname = future.result(timeout=0.5)
                except Exception:
                    device.hostname = ""
