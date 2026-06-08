"""
NetShaper — network discovery: ARP sweep + passive sniff + hostname resolution.
"""
import logging
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Network
from typing import Dict, List, Optional

import psutil

from netshaper.models import Device
from netshaper.utils import print_flush

log = logging.getLogger("netshaper")

ARP = None
Ether = None
_sniff = None
_srp = None


def _ensure_scapy_layers() -> None:
    global ARP, Ether
    if ARP is None or Ether is None:
        from scapy.all import ARP as scapy_ARP, Ether as scapy_Ether

        if ARP is None:
            ARP = scapy_ARP
        if Ether is None:
            Ether = scapy_Ether


def _ensure_scapy_io() -> None:
    global _sniff, _srp
    if _sniff is None or _srp is None:
        from scapy.all import sniff as scapy_sniff, srp as scapy_srp

        if _sniff is None:
            _sniff = scapy_sniff
        if _srp is None:
            _srp = scapy_srp


def sniff(*args, **kwargs):
    _ensure_scapy_io()
    return _sniff(*args, **kwargs)


def srp(*args, **kwargs):
    _ensure_scapy_io()
    return _srp(*args, **kwargs)


class NetworkDiscovery:
    def __init__(self, interface: str):
        self.interface     = interface
        self.devices_dict: Dict[str, Device] = {}
        self.lock          = threading.Lock()   # Guards all devices_dict mutations

    # ── Own-interface queries ─────────────────────────────────────────────────
    def get_own_mac(self) -> str:
        for a in psutil.net_if_addrs().get(self.interface, []):
            if a.family == psutil.AF_LINK:
                return a.address.lower()
        try:
            _ensure_scapy_layers()
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
                    return str(IPv4Network(
                        f"{a.address}/{a.netmask}", strict=False))
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
                            struct.pack("<L", int(parts[2], 16)))
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
            _ensure_scapy_layers()
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=self.interface, timeout=3, verbose=0)
            if ans:
                return ans[0][1].src.lower()
        except Exception:
            pass
        return None

    # ── ARP sweep ────────────────────────────────────────────────────────────
    def _passive_sniff_callback(self, pkt) -> None:
        """
        ARP passive-sniff callback — thread-safe write to devices_dict.

        BUG FIX (v3.8.1): original code also added pdst/Ether.dst as a device,
        which injected ghost entries (ff:ff:ff:ff:ff:ff) for every probed IP.
        Now only the *source* IP/MAC is registered.
        """
        _ensure_scapy_layers()
        if ARP not in pkt:
            return
        src_ip  = pkt[ARP].psrc
        src_mac = pkt[Ether].src.lower()
        # Skip ARP probes (sender IP = 0.0.0.0) and broadcast MACs
        if not src_ip or src_ip == '0.0.0.0':
            return
        if src_mac == 'ff:ff:ff:ff:ff:ff':
            return
        with self.lock:
            if src_ip not in self.devices_dict:
                self.devices_dict[src_ip] = Device(ip=src_ip, mac=src_mac)

    def arp_sweep(self, subnet: str, gateway_ip: str) -> List[Device]:
        log.info(f"ARP sweep on {subnet}")
        try:
            _ensure_scapy_layers()
            net     = IPv4Network(subnet, strict=False)
            targets = [str(ip) for ip in net.hosts()
                       if str(ip) != gateway_ip]
            if not targets:
                return []

            # Three passes with increasing timeouts to catch slow responders
            for timeout_val in [2, 3, 4]:
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets),
                    iface=self.interface, timeout=timeout_val, verbose=0)
                for _, rcv in ans:
                    ip  = rcv[ARP].psrc
                    mac = rcv[Ether].src.lower()
                    if ip != gateway_ip:
                        with self.lock:
                            if ip not in self.devices_dict:
                                self.devices_dict[ip] = Device(ip=ip, mac=mac)

            # Passive ARP sniff for 15 s to catch quiet devices
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
                with self.lock:
                    count = len(self.devices_dict)
                print_flush(
                    f"\r  Passive sniff: {remaining:2d}s | {count:2d} devices",
                    end='')
                time.sleep(1)
            print_flush()
            stop_sniff.set()
            t.join(timeout=2)

        except Exception as e:
            log.error(f"ARP sweep failed: {e}")

        with self.lock:
            devices = list(self.devices_dict.values())
        return sorted(devices,
                      key=lambda d: [int(i) for i in d.ip.split(".")])

    # ── Hostname resolution ───────────────────────────────────────────────────
    def resolve_hostnames(self, devices: List[Device]) -> None:
        """
        Async hostname resolution — single flat ThreadPoolExecutor.

        BUG FIX (v3.8.1): the as_completed() TimeoutError was not caught at
        the for-loop level, causing it to propagate to the caller when the
        5-second wall-clock budget expired before all futures completed.
        The try/except is now correctly wrapped around the for statement.
        """
        def resolve_worker(d: Device) -> str:
            name, _, _ = socket.gethostbyaddr(d.ip)
            return name.lower() if name != d.ip else ""

        with ThreadPoolExecutor(max_workers=20) as pool:
            future_to_device = {pool.submit(resolve_worker, d): d
                                for d in devices}
            try:
                for future in as_completed(future_to_device, timeout=5.0):
                    device = future_to_device[future]
                    try:
                        device.hostname = future.result(timeout=0.5)
                    except Exception:
                        device.hostname = ""
            except TimeoutError:
                # Remaining futures haven't resolved — leave hostname=""
                pass
