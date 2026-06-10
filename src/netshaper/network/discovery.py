"""
NetShaper — network discovery: ARP sweep + passive sniff + hostname resolution.
"""
import glob
import logging
import os
import re
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Address, IPv4Network, ip_address, summarize_address_range
from typing import Dict, List, Optional, Sequence

import psutil

from netshaper.models import Device
from netshaper.utils import print_flush

log = logging.getLogger("netshaper")

LEASE_FILE_PATTERNS = (
    "/var/lib/misc/dnsmasq.leases",
    "/var/lib/NetworkManager/dnsmasq-*.leases",
    "/var/lib/libvirt/dnsmasq/*.leases",
    "/var/lib/dhcp/dhclient*.leases",
    "/var/lib/dhcp/dhcpd.leases",
)

ARP_BATCH_SIZE = 64
ARP_SEND_INTERVAL = 0.006
ARP_BATCH_TIMEOUTS = (0.35, 0.45)

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
            best = None
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if (len(parts) >= 7
                            and parts[0] == self.interface
                            and parts[1] == '00000000'):
                        gateway = socket.inet_ntoa(
                            struct.pack("<L", int(parts[2], 16)))
                        try:
                            metric = int(parts[6])
                        except ValueError:
                            metric = 0
                        if best is None or metric < best[0]:
                            best = (metric, gateway)
            if best is not None:
                return best[1]
        except Exception:
            pass
        return None

    def get_default_gateway_ipv6(self) -> Optional[str]:
        try:
            best = None
            with open("/proc/net/ipv6_route") as f:
                for line in f:
                    parts = line.strip().split()
                    if (len(parts) >= 10
                            and parts[-1] == self.interface
                            and parts[0] == '00000000000000000000000000000000'
                            and parts[1] == '00'):
                        blocks = [parts[4][i:i+4] for i in range(0, 32, 4)]
                        gateway = ':'.join(blocks)
                        try:
                            metric = int(parts[5], 16)
                        except ValueError:
                            metric = 0
                        if best is None or metric < best[0]:
                            best = (metric, gateway)
            if best is not None:
                return best[1]
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
    @staticmethod
    def _valid_mac(mac: str) -> bool:
        mac = (mac or "").lower()
        if mac in {"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
            return False
        return bool(re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac))

    @staticmethod
    def _target_batches(targets: List[str],
                        batch_size: int = ARP_BATCH_SIZE) -> List[List[str]]:
        return [
            targets[idx:idx + batch_size]
            for idx in range(0, len(targets), batch_size)
        ]

    @staticmethod
    def _ipv4_scope_networks(
            connected_subnet: IPv4Network,
            authorized_cidrs: Optional[Sequence]) -> List[IPv4Network]:
        if not authorized_cidrs:
            return [connected_subnet]

        scoped_networks: List[IPv4Network] = []
        for network in authorized_cidrs:
            if getattr(network, "version", None) != 4:
                continue
            if not connected_subnet.overlaps(network):
                continue
            start = max(
                int(connected_subnet.network_address),
                int(network.network_address),
            )
            end = min(
                int(connected_subnet.broadcast_address),
                int(network.broadcast_address),
            )
            scoped_networks.extend(
                summarize_address_range(IPv4Address(start), IPv4Address(end))
            )

        unique = {
            str(network): network
            for network in scoped_networks
        }
        return sorted(
            unique.values(),
            key=lambda network: (
                int(network.network_address),
                network.prefixlen,
            ),
        )

    @staticmethod
    def _targets_from_scopes(
            scope_networks: Sequence[IPv4Network],
            gateway_ip: Optional[str]) -> List[str]:
        targets: List[str] = []
        seen = set()
        for network in scope_networks:
            for ip in network.hosts():
                candidate = str(ip)
                if candidate == gateway_ip or candidate in seen:
                    continue
                seen.add(candidate)
                targets.append(candidate)
        return targets

    @staticmethod
    def _ip_in_scopes(ip: str, scope_networks: Sequence[IPv4Network]) -> bool:
        try:
            parsed = ip_address(ip)
        except ValueError:
            return False
        return (
            parsed.version == 4
            and any(parsed in network for network in scope_networks)
        )

    def _remember_device(
            self,
            ip: str,
            mac: str,
            gateway_ip: Optional[str] = None,
            subnet: Optional[IPv4Network] = None,
            scope_networks: Optional[Sequence[IPv4Network]] = None) -> None:
        if not ip or ip == gateway_ip:
            return
        scopes = list(scope_networks or ([] if subnet is None else [subnet]))
        if scopes:
            if not self._ip_in_scopes(ip, scopes):
                return
        mac = (mac or "").lower()
        if not self._valid_mac(mac):
            return
        with self.lock:
            if ip not in self.devices_dict:
                self.devices_dict[ip] = Device(ip=ip, mac=mac)

    def _device_count(self) -> int:
        with self.lock:
            return len(self.devices_dict)

    def _merge_proc_arp_cache(
            self,
            subnet: IPv4Network,
            gateway_ip: Optional[str],
            scope_networks: Optional[Sequence[IPv4Network]] = None) -> None:
        scopes = scope_networks or [subnet]
        try:
            with open("/proc/net/arp", encoding="utf-8") as fh:
                for raw_line in fh.readlines()[1:]:
                    parts = raw_line.split()
                    if len(parts) < 6:
                        continue
                    ip, _, _, mac, _, device = parts[:6]
                    if device != self.interface:
                        continue
                    self._remember_device(
                        ip,
                        mac,
                        gateway_ip,
                        scope_networks=scopes,
                    )
        except OSError:
            pass

    def _merge_ip_neighbor_cache(
            self,
            subnet: IPv4Network,
            gateway_ip: Optional[str],
            scope_networks: Optional[Sequence[IPv4Network]] = None) -> None:
        scopes = scope_networks or [subnet]
        try:
            result = subprocess.run(
                ["ip", "-4", "neigh", "show", "dev", self.interface],
                capture_output=True,
                text=True,
                check=False,
                timeout=1.0,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return
        if result.returncode != 0:
            return
        for raw_line in result.stdout.splitlines():
            parts = raw_line.split()
            if not parts:
                continue
            ip = parts[0]
            if "lladdr" not in parts:
                continue
            mac_index = parts.index("lladdr") + 1
            if mac_index >= len(parts):
                continue
            self._remember_device(
                ip,
                parts[mac_index],
                gateway_ip,
                scope_networks=scopes,
            )

    def _merge_neighbor_caches(
            self,
            subnet: IPv4Network,
            gateway_ip: Optional[str],
            scope_networks: Optional[Sequence[IPv4Network]] = None) -> int:
        scopes = scope_networks or [subnet]
        self._merge_proc_arp_cache(subnet, gateway_ip, scopes)
        self._merge_ip_neighbor_cache(subnet, gateway_ip, scopes)
        return self._device_count()

    def _passive_sniff_callback(
            self,
            pkt,
            gateway_ip: Optional[str] = None,
            scope_networks: Optional[Sequence[IPv4Network]] = None) -> None:
        """
        ARP passive-sniff callback — thread-safe write to devices_dict.

        Historical bug fix: original code also added pdst/Ether.dst as a device,
        which injected ghost entries (ff:ff:ff:ff:ff:ff) for every probed IP.
        Now only the *source* IP/MAC is registered.
        """
        _ensure_scapy_layers()
        if ARP not in pkt:
            return
        src_ip  = pkt[ARP].psrc
        src_mac = pkt[Ether].src.lower()
        self._remember_device(
            src_ip,
            src_mac,
            gateway_ip,
            scope_networks=scope_networks,
        )

    def arp_sweep(
            self,
            subnet: str,
            gateway_ip: str,
            authorized_cidrs: Optional[Sequence] = None) -> List[Device]:
        log.info(f"ARP sweep on {subnet}")
        scope_networks: List[IPv4Network] = []
        try:
            _ensure_scapy_layers()
            net = IPv4Network(subnet, strict=False)
            scope_networks = self._ipv4_scope_networks(net, authorized_cidrs)
            targets = self._targets_from_scopes(scope_networks, gateway_ip)
            if not targets:
                print_flush("  No authorized IPv4 probe targets in interface subnet.")
                return []

            cached_count = self._merge_neighbor_caches(
                net,
                gateway_ip,
                scope_networks,
            )
            if cached_count:
                print_flush(f"  Cached neighbors: {cached_count} devices")

            batches = self._target_batches(targets)
            # Short visible passes avoid long silent waits on Wi-Fi while still
            # refreshing the cached neighbor list with live replies.
            for pass_idx, timeout_val in enumerate(
                    ARP_BATCH_TIMEOUTS, 1):
                for batch_idx, batch in enumerate(batches, 1):
                    print_flush(
                        "\r  ARP sweep: "
                        f"pass {pass_idx}/{len(ARP_BATCH_TIMEOUTS)} "
                        f"batch {batch_idx}/{len(batches)} | "
                        f"{self._device_count():2d} devices",
                        end='',
                    )
                    ans, _ = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=batch),
                        iface=self.interface,
                        timeout=timeout_val,
                        inter=ARP_SEND_INTERVAL,
                        verbose=0)
                    for _, rcv in ans:
                        self._remember_device(
                            rcv[ARP].psrc,
                            rcv[Ether].src,
                            gateway_ip,
                            scope_networks=scope_networks,
                        )
            print_flush()
            self._merge_neighbor_caches(net, gateway_ip, scope_networks)

            # Passive ARP sniff for 15 s to catch quiet devices
            stop_sniff = threading.Event()
            t = threading.Thread(
                target=lambda: sniff(
                    iface=self.interface, filter="arp",
                    prn=lambda pkt: self._passive_sniff_callback(
                        pkt,
                        gateway_ip,
                        scope_networks,
                    ),
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
            devices = [
                device for device in self.devices_dict.values()
                if not scope_networks
                or self._ip_in_scopes(device.ip, scope_networks)
            ]
        return sorted(devices,
                      key=lambda d: [int(i) for i in d.ip.split(".")])

    # ── Hostname resolution ───────────────────────────────────────────────────
    @staticmethod
    def _clean_hostname(name: str, ip: str) -> str:
        name = (name or "").strip().strip('"').strip("'").rstrip(".")
        if not name or name == ip:
            return ""
        if name.lower() in {"*", "-", "(none)", "(unknown)"}:
            return ""
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", name):
            return ""
        return name.lower()

    def _hostname_from_reverse_dns(self, ip: str) -> str:
        name, _, _ = socket.gethostbyaddr(ip)
        return self._clean_hostname(name, ip)

    def _hostname_from_getnameinfo(self, ip: str) -> str:
        name = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)[0]
        return self._clean_hostname(name, ip)

    def _hostname_from_hosts_file(self, ip: str) -> str:
        try:
            with open("/etc/hosts", encoding="utf-8") as fh:
                for raw_line in fh:
                    line = raw_line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) < 2 or parts[0] != ip:
                        continue
                    for candidate in parts[1:]:
                        name = self._clean_hostname(candidate, ip)
                        if name:
                            return name
        except OSError:
            pass
        return ""

    @staticmethod
    def _strip_lease_value(value: str) -> str:
        return value.strip().strip(";").strip('"').strip("'")

    def _hostname_from_lease_files(self, ip: str) -> str:
        for pattern in LEASE_FILE_PATTERNS:
            for path in glob.glob(pattern):
                name = self._hostname_from_lease_file(path, ip)
                if name:
                    return name
        return ""

    def _hostname_from_lease_file(self, path: str, ip: str) -> str:
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                lease_ip = ""
                lease_name = ""
                for raw_line in fh:
                    line = raw_line.strip()
                    parts = line.split()

                    # dnsmasq: expiry mac ip hostname client-id
                    if len(parts) >= 4 and parts[2] == ip:
                        name = self._clean_hostname(parts[3], ip)
                        if name:
                            return name

                    # ISC dhclient/dhcpd lease blocks.
                    if line.startswith("lease "):
                        lease_ip = (
                            self._strip_lease_value(parts[1])
                            if len(parts) > 1 else ""
                        )
                        if lease_ip == "{":
                            lease_ip = ""
                        lease_name = ""
                    elif line.startswith("fixed-address "):
                        lease_ip = self._strip_lease_value(
                            line.split(None, 1)[1])
                    elif line.startswith("option host-name "):
                        lease_name = self._strip_lease_value(
                            line.split(None, 2)[2])
                    elif line.startswith("}") and lease_ip == ip:
                        name = self._clean_hostname(lease_name, ip)
                        if name:
                            return name
        except OSError:
            pass
        return ""

    def _hostname_from_system_resolvers(self, ip: str) -> str:
        commands = (
            ["getent", "hosts", ip],
            ["resolvectl", "query", "--legend=no", ip],
        )
        for command in commands:
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=0.8,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                continue
            if result.returncode != 0:
                continue
            name = self._parse_resolver_output(result.stdout, ip)
            if name:
                return name
        return ""

    def _parse_resolver_output(self, output: str, ip: str) -> str:
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if ":" in line and line.split(":", 1)[0].strip() == ip:
                line = line.split(":", 1)[1].strip()
            parts = [part for part in line.split() if part != ip]
            for candidate in parts:
                name = self._clean_hostname(candidate, ip)
                if name:
                    return name
        return ""

    @staticmethod
    def _encode_netbios_name(name: str) -> bytes:
        raw_name = name.encode("ascii", errors="ignore")[:15].ljust(15, b" ")
        raw_name += b"\x00"
        encoded = bytearray()
        for char in raw_name:
            encoded.append(ord("A") + ((char >> 4) & 0x0F))
            encoded.append(ord("A") + (char & 0x0F))
        return bytes([len(encoded)]) + bytes(encoded) + b"\x00"

    @staticmethod
    def _skip_dns_name(data: bytes, offset: int) -> int:
        while offset < len(data):
            length = data[offset]
            if length & 0xC0 == 0xC0:
                return offset + 2
            offset += 1
            if length == 0:
                return offset
            offset += length
        return offset

    def _hostname_from_nbns(self, ip: str) -> str:
        transaction_id = os.urandom(2)
        query = (
            transaction_id
            + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            + self._encode_netbios_name("*")
            + b"\x00\x21\x00\x01"
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.6)
                sock.sendto(query, (ip, 137))
                data, _ = sock.recvfrom(1024)
        except OSError:
            return ""
        return self._parse_nbns_response(data, ip)

    def _parse_nbns_response(self, data: bytes, ip: str) -> str:
        if len(data) < 12:
            return ""
        qdcount = int.from_bytes(data[4:6], "big")
        ancount = int.from_bytes(data[6:8], "big")
        offset = 12

        for _ in range(qdcount):
            offset = self._skip_dns_name(data, offset) + 4
            if offset > len(data):
                return ""

        candidates: List[str] = []
        for _ in range(ancount):
            offset = self._skip_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rr_type = int.from_bytes(data[offset:offset + 2], "big")
            rdlength = int.from_bytes(data[offset + 8:offset + 10], "big")
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength
            if rr_type != 0x21 or len(rdata) < 1:
                continue

            name_count = rdata[0]
            for idx in range(name_count):
                start = 1 + idx * 18
                entry = rdata[start:start + 18]
                if len(entry) < 18:
                    break
                raw_name = entry[:15].decode("ascii", errors="ignore").strip()
                suffix = entry[15]
                flags = int.from_bytes(entry[16:18], "big")
                if not raw_name or raw_name == "__MSBROWSE__":
                    continue
                name = self._clean_hostname(raw_name, ip)
                if not name:
                    continue
                is_group = bool(flags & 0x8000)
                if suffix in (0x00, 0x20) and not is_group:
                    return name
                candidates.append(name)

        return candidates[0] if candidates else ""

    def _resolve_hostname(self, ip: str) -> str:
        resolvers = (
            self._hostname_from_reverse_dns,
            self._hostname_from_getnameinfo,
            self._hostname_from_hosts_file,
            self._hostname_from_lease_files,
            self._hostname_from_system_resolvers,
            self._hostname_from_nbns,
        )
        for resolver in resolvers:
            try:
                name = self._clean_hostname(resolver(ip), ip)
            except Exception:
                continue
            if name:
                return name
        return ""

    def resolve_hostnames(self, devices: List[Device]) -> None:
        """
        Async hostname resolution — single flat ThreadPoolExecutor.

        Historical bug fix: the as_completed() TimeoutError was not caught at
        the for-loop level, causing it to propagate to the caller when the
        5-second wall-clock budget expired before all futures completed.
        The try/except is now correctly wrapped around the for statement.
        """
        def resolve_worker(d: Device) -> str:
            return self._resolve_hostname(d.ip)

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
