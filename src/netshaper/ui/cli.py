"""
NetShaper — Command Line Interface.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
from ipaddress import ip_address, ip_network
import os
import shlex
import signal
import socket
import sys
from typing import List, Optional, Union

# When this file is executed directly from inside the package directory,
# absolute imports such as netshaper.config need the package parent on sys.path.
PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE_PARENT = os.path.dirname(PACKAGE_DIR)
if PACKAGE_PARENT not in sys.path:
    sys.path.insert(0, PACKAGE_PARENT)

import psutil

from netshaper import config

from netshaper.config import VERSION
from netshaper.core.authorization import AuthorizationError, AuthorizationPolicy
from netshaper.core.plugin_loader import PluginLoadError, PluginLoader
from netshaper.core.session_plan import (
    ArpOptions,
    CaptureOptions,
    DnsOptions,
    MitmOptions,
    ModuleID,
    PortalOptions,
    SessionPlan,
)
from netshaper.core.session_runner import SessionRunner
from netshaper.models import Device
from netshaper.network.shaper import ShapingProfile
from netshaper.network.spoofers import validate_spoof_timing
from netshaper.system import SystemChecker, check_local_port
from netshaper.utils import bold, cyan, green, print_flush, safe_input


@dataclass(frozen=True)
class ExploitOptions:
    arp_amplify: int = 0
    arp_amplify_burst: int = 5
    arp_amplify_interval: float = 0.1
    cam_exhaust: int = 0
    dnssec_mode: str = "off"
    dnssec_upstream: str = "8.8.8.8"
    hsts_idn_demo: bool = False

    @property
    def arp_amplification_enabled(self) -> bool:
        return self.arp_amplify > 0 or self.cam_exhaust > 0

    @property
    def dnssec_enabled(self) -> bool:
        return self.dnssec_mode != "off"

    @property
    def portal_suppress_dnssec(self) -> bool:
        return self.dnssec_enabled

    @property
    def portal_web_security_demo(self) -> bool:
        return self.hsts_idn_demo


MODULE_BY_NUMBER = {
    1: ModuleID.ARP,
    2: ModuleID.DNS,
    3: ModuleID.PORTAL,
    4: ModuleID.SHAPING,
    5: ModuleID.CAPTURE,
    6: ModuleID.MITM,
    7: ModuleID.ARP_AMPLIFICATION,
    8: ModuleID.DNSSEC,
    9: ModuleID.HSTS_IDN_DEMO,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=f"NetShaper v{VERSION}")
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show NetShaper version and exit.",
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to bind (e.g. eth0, wlan0). "
        "If omitted, NetShaper prompts when multiple interfaces exist.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without applying system changes",
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        help="Skip discovery and use these IPs directly (comma-separated values allowed).",
    )
    parser.add_argument(
        "--modules",
        help=(
            "Offensive network module numbers to enable without the interactive prompt "
            "(e.g. 1,2,3,5)."
        ),
    )
    parser.add_argument(
        "--allow-cidr",
        action="append",
        default=[],
        help=(
            "Authorized target CIDR. Required before starting a session; "
            "may be repeated or comma-separated."
        ),
    )
    parser.add_argument(
        "--max-discovery-hosts",
        type=int,
        default=4096,
        help="Maximum authorized IPv4 hosts to actively probe during discovery.",
    )
    parser.add_argument(
        "--limit",
        type=float,
        help="Set bandwidth throttling in Mbps without using the interactive prompt.",
    )
    parser.add_argument(
        "--arp-interval",
        type=float,
        default=2.0,
        help="Seconds between ARP/NDP training cycles (0.25-10).",
    )
    parser.add_argument(
        "--arp-burst",
        type=int,
        default=1,
        help="Packets sent per ARP/NDP training cycle (1-5).",
    )
    parser.add_argument(
        "--arp-amplify",
        type=int,
        default=0,
        help="Enable ARP amplification with N phantom IPs per target.",
    )
    parser.add_argument(
        "--arp-amplify-burst",
        type=int,
        default=5,
        help="Packets per amplification cycle (1-50).",
    )
    parser.add_argument(
        "--arp-amplify-interval",
        type=float,
        default=0.1,
        help="Seconds between amplification cycles (0.01-5.0).",
    )
    parser.add_argument(
        "--cam-exhaust",
        type=int,
        default=0,
        help="Enable CAM table exhaustion with N phantom IPs.",
    )
    parser.add_argument(
        "--dnssec-suppression",
        choices=["off", "fail-closed", "fail-open", "nxdomain", "timeout"],
        default="off",
        help="DNSSEC suppression failure mode.",
    )
    parser.add_argument(
        "--dnssec-upstream",
        default="8.8.8.8",
        help="Upstream DNS for DNSSEC suppression.",
    )
    parser.add_argument(
        "--hsts-idn-demo",
        dest="hsts_idn_demo",
        action="store_true",
        help="Enable HSTS/IDN first-visit offensive demo.",
    )
    parser.add_argument(
        "--packet-verbose",
        action="store_true",
        help="Print per-packet sniffer lines while capturing.",
    )
    parser.add_argument(
        "--latency-ms",
        type=int,
        default=0,
        help="Add target latency with tc netem (0-60000 ms).",
    )
    parser.add_argument(
        "--jitter-ms",
        type=int,
        default=0,
        help="Add normally distributed delay variation; requires --latency-ms.",
    )
    for option, destination, description in (
        ("--loss-percent", "loss_percent", "random packet loss"),
        ("--corruption-percent", "corruption_percent", "random corruption"),
        ("--duplicate-percent", "duplicate_percent", "packet duplication"),
        ("--reorder-percent", "reorder_percent", "packet reordering"),
    ):
        parser.add_argument(
            option,
            dest=destination,
            type=float,
            default=0.0,
            help=f"Add {description} with tc netem (0-100 percent).",
        )
    parser.add_argument(
        "--emergency-restore-state",
        metavar="PATH",
        help=(
            "Emergency only: restore forwarding sysctls and full firewall "
            "snapshots from a NetShaper state.json file."
        ),
    )
    parser.add_argument(
        "--yes-really-restore-firewall-snapshot",
        action="store_true",
        help=(
            "Required with --emergency-restore-state; acknowledges that full "
            "firewall snapshot replay can overwrite unrelated live changes."
        ),
    )
    parser.add_argument(
        "--plugin",
        action="append",
        default=[],
        help=(
            "Load a built-in or installed plugin by ID (e.g. wifi-recon). "
            "May be repeated."
        ),
    )
    parser.add_argument(
        "--plugin-config",
        metavar="FILE",
        help=(
            "JSON file containing per-plugin scope and configuration. "
            "Ignored if no plugins are specified."
        ),
    )
    args = parser.parse_args()
    if args.targets:
        args.targets = [
            item.strip()
            for token in args.targets
            for item in token.split(",")
            if item.strip()
        ]
    if args.limit is not None and not 0.1 <= args.limit <= 1000:
        parser.error("--limit must be between 0.1 and 1000 Mbps")
    if not 1 <= args.max_discovery_hosts <= 65536:
        parser.error("--max-discovery-hosts must be between 1 and 65536")
    try:
        validate_spoof_timing(args.arp_interval, args.arp_burst)
    except ValueError as exc:
        parser.error(str(exc))
    if not 0 <= args.arp_amplify <= 4096:
        parser.error("--arp-amplify must be between 0 and 4096")
    if not 1 <= args.arp_amplify_burst <= 50:
        parser.error("--arp-amplify-burst must be between 1 and 50")
    if not 0.01 <= args.arp_amplify_interval <= 5.0:
        parser.error("--arp-amplify-interval must be between 0.01 and 5.0")
    if not 0 <= args.cam_exhaust <= 4096:
        parser.error("--cam-exhaust must be between 0 and 4096")
    try:
        ShapingProfile(
            bandwidth_mbps=args.limit,
            latency_ms=args.latency_ms,
            jitter_ms=args.jitter_ms,
            loss_percent=args.loss_percent,
            corruption_percent=args.corruption_percent,
            duplicate_percent=args.duplicate_percent,
            reorder_percent=args.reorder_percent,
        )
    except ValueError as exc:
        parser.error(str(exc))
    return args


def _net_if_addrs_or_exit() -> dict:
    try:
        return psutil.net_if_addrs()
    except Exception as exc:
        sys.exit(f"[NetShaper] Could not inspect network interfaces: {exc}")


def _net_if_stats_or_empty() -> dict:
    try:
        return psutil.net_if_stats()
    except Exception:
        return {}


def _usable_interface_ipv4s(
    name: str, addrs_by_name: Optional[dict] = None
) -> list[str]:
    addrs = (addrs_by_name or _net_if_addrs_or_exit()).get(name, [])
    result = []
    for addr in addrs:
        if addr.family != socket.AF_INET:
            continue
        parsed = ip_address(addr.address)
        if parsed.is_loopback or parsed.is_unspecified:
            continue
        result.append(addr.address)
    return result


def choose_interface(requested: Optional[str] = None) -> str:
    if requested:
        addrs = _net_if_addrs_or_exit()
        if requested not in addrs:
            sys.exit(f"[NetShaper] Interface not found: {requested}")
        stats = _net_if_stats_or_empty().get(requested)
        if stats is not None and not stats.isup:
            sys.exit(f"[NetShaper] Interface is down: {requested}")
        if not _usable_interface_ipv4s(requested, addrs):
            sys.exit(
                f"[NetShaper] Interface has no usable non-loopback IPv4: {requested}"
            )
        return requested

    stats = _net_if_stats_or_empty()
    addrs_by_name = _net_if_addrs_or_exit()
    ifaces = [
        (name, addr.address)
        for name, addrs in addrs_by_name.items()
        for addr in addrs
        if (
            addr.family == socket.AF_INET
            and not addr.address.startswith("127.")
            and (stats.get(name) is None or stats[name].isup)
        )
    ]
    if not ifaces:
        sys.exit("[NetShaper] No active interface.")
    if len(ifaces) == 1:
        name, ip = ifaces[0]
        print_flush(f"  Interface: {name} ({ip})")
        return name

    print_flush("\n  Interfaces:")
    for idx, (name, ip) in enumerate(ifaces, 1):
        print_flush(f"  [{idx}] {name} ({ip})")
    while True:
        choice = safe_input(f"\n  Select (1-{len(ifaces)}): ")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(ifaces):
                return ifaces[idx][0]
            print_flush("  [!] Out of range.")
        except ValueError:
            print_flush("  [!] Invalid number.")


def pick_targets_ui(devices: List[Device]) -> List[Device]:
    if not devices:
        sys.exit("[NetShaper] No devices discovered.")

    print_flush("\n" + "=" * 90)
    print_flush(f"  {'#':<4} {'IP':<16} {'Hostname':<28} MAC")
    print_flush("-" * 90)
    for idx, dev in enumerate(devices, 1):
        hostname = (dev.hostname or "-")[:28]
        print_flush(f"  {idx:<4} {dev.ip:<16} {hostname:<28} {dev.mac}")
    print_flush("=" * 90)

    while True:
        choice = safe_input("\n  Select devices (e.g. 1,2,5  1-3  all): ").lower()
        if not choice:
            continue
        if choice == "all":
            return devices

        selected: List[Device] = []
        try:
            for part in choice.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = part.split("-", 1)
                    first, last = int(start), int(end)
                    if 1 <= first <= last <= len(devices):
                        selected.extend(devices[first - 1 : last])
                    else:
                        print_flush(f"  [!] Range {start}-{end} out of bounds.")
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


def normalize_module_choices(raw: str) -> tuple[set[ModuleID], list[str]]:
    """Parse module numbers and return valid module choices plus invalid tokens."""
    modules: set[ModuleID] = set()
    invalid: list[str] = []

    # Accept both "1 3 5" and "1,3,5" and "1, 3, 5"
    for token in raw.replace(",", " ").split():
        try:
            value = int(token)
        except ValueError:
            invalid.append(token)
            continue

        module = MODULE_BY_NUMBER.get(value)
        if module is not None:
            modules.add(module)
        else:
            invalid.append(token)

    return modules, invalid


def print_module_menu() -> None:
    print_flush("\n  -- Offensive network toolkit modules (enter numbers e.g. 1 3 5) --")
    print_flush("  [1] ARP spoofing (core MITM)")
    print_flush("  [2] DNS spoofing (lab redirect)")
    print_flush("  [3] Captive portal (HTTP index.html)")
    print_flush("  [4] Bandwidth throttle / netem impairment")
    print_flush("  [5] Packet sniffer")
    print_flush("  [6] mitmproxy HTTPS inspection")
    print_flush(
        "  [7] ARP amplification (requires [1], default 256 phantom IPs)"
    )
    print_flush(
        "  [8] DNSSEC suppression (requires [2], default fail-closed)"
    )
    print_flush("  [9] HSTS/IDN first-visit offensive demo (requires [3])")


def resolve_exploit_options(
    args: argparse.Namespace, modules: set[ModuleID]
) -> ExploitOptions:
    """Merge module picks with explicit CLI exploit flags."""
    arp_amplify = args.arp_amplify
    if ModuleID.ARP_AMPLIFICATION in modules and arp_amplify == 0:
        arp_amplify = 256

    dnssec_mode = args.dnssec_suppression
    if ModuleID.DNSSEC in modules and dnssec_mode == "off":
        dnssec_mode = "fail-closed"

    hsts_idn_demo = args.hsts_idn_demo or ModuleID.HSTS_IDN_DEMO in modules

    return ExploitOptions(
        arp_amplify=arp_amplify,
        arp_amplify_burst=args.arp_amplify_burst,
        arp_amplify_interval=args.arp_amplify_interval,
        cam_exhaust=args.cam_exhaust,
        dnssec_mode=dnssec_mode,
        dnssec_upstream=args.dnssec_upstream,
        hsts_idn_demo=hsts_idn_demo,
    )


def apply_module_dependencies(
    modules: set[ModuleID], exploit: ExploitOptions
) -> tuple[set[ModuleID], ExploitOptions]:
    """Prompt for required base modules or disable dependent advanced modules."""
    modules = set(modules)

    if exploit.arp_amplification_enabled and ModuleID.ARP not in modules:
        print_flush("  [!] ARP amplification requires ARP spoofing.")
        if safe_input("  Enable ARP spoofing too? (y/n): ").lower() == "y":
            modules.add(ModuleID.ARP)
        else:
            modules.discard(ModuleID.ARP_AMPLIFICATION)
            exploit = replace(exploit, arp_amplify=0, cam_exhaust=0)
            print_flush("  [-] ARP amplification disabled.")

    if exploit.dnssec_enabled and ModuleID.DNS not in modules:
        print_flush("  [!] DNSSEC suppression requires DNS spoofing.")
        if safe_input("  Enable DNS spoofing too? (y/n): ").lower() == "y":
            modules.add(ModuleID.DNS)
        else:
            modules.discard(ModuleID.DNSSEC)
            exploit = replace(exploit, dnssec_mode="off")
            print_flush("  [-] DNSSEC suppression disabled.")

    if exploit.hsts_idn_demo and ModuleID.PORTAL not in modules:
        print_flush(
            "  [!] HSTS/IDN first-visit offensive demo requires the "
            "captive portal HTTP service."
        )
        if safe_input("  Enable captive portal too? (y/n): ").lower() == "y":
            modules.add(ModuleID.PORTAL)
        else:
            modules.discard(ModuleID.HSTS_IDN_DEMO)
            exploit = replace(exploit, hsts_idn_demo=False)
            print_flush("  [-] HSTS/IDN offensive demo disabled.")

    return modules, exploit


def portal_launch_hint(
    exploit: ExploitOptions,
    *,
    host_ip: str,
    authorized_cidrs: Optional[list] = None,
    smart_spoof_all: bool = False,
    health_token: Optional[str] = None,
) -> str:
    flags = [f"--host-ip {shlex.quote(host_ip)}"]
    if health_token:
        flags.extend(["--health-token", shlex.quote(health_token)])
    if smart_spoof_all:
        flags.append("--smart-spoof-all")
    for network in authorized_cidrs or []:
        flags.append(f"--allow-cidr {shlex.quote(str(network))}")
    flags.append(f"--allow-cidr {shlex.quote(f'{host_ip}/32')}")
    if exploit.portal_suppress_dnssec:
        flags.append(f"--dnssec-mode {shlex.quote(exploit.dnssec_mode)}")
    if exploit.portal_web_security_demo:
        flags.append("--hsts-idn-demo")
    if exploit.dnssec_enabled:
        flags.append(f"--upstream {shlex.quote(exploit.dnssec_upstream)}")

    project_root = os.path.dirname(PACKAGE_PARENT)
    running_from_source = (
        os.path.isfile(os.path.join(project_root, "pyproject.toml"))
        and os.path.isdir(os.path.join(PACKAGE_PARENT, "netshaper"))
    )
    if running_from_source:
        command = (
            "sudo env PYTHONPATH="
            f"{shlex.quote(PACKAGE_PARENT)} "
            f"{shlex.quote(sys.executable)} -m netshaper.portal"
        )
    else:
        command = "sudo netshaper-portal"
    return command + " " + " ".join(flags)


def pick_limit_ui() -> float:
    presets = {"1": 1.0, "2": 2.0, "3": 3.0, "4": 5.0, "5": 10.0}
    print_flush("\n  Bandwidth presets:")
    print_flush(
        "  [1] 1 Mbps  [2] 2 Mbps  [3] 3 Mbps  [4] 5 Mbps  [5] 10 Mbps  [6] Custom"
    )
    while True:
        choice = safe_input("  Select (1-6): ")
        if choice in presets:
            return presets[choice]
        if choice == "6":
            try:
                value = float(safe_input("  Enter Mbps: "))
                if 0.1 <= value <= 1000:
                    return value
                print_flush("  [!] 0.1 - 1000 Mbps only.")
            except ValueError:
                print_flush("  [!] Invalid number.")


def target_ip(target: Union[Device, str]) -> str:
    return target if isinstance(target, str) else target.ip


def parse_authorized_cidrs(raw_values: list[str]) -> list:
    networks = []
    for token in raw_values:
        for item in token.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                networks.append(ip_network(item, strict=False))
            except ValueError as exc:
                raise ValueError(f"invalid --allow-cidr value {item!r}: {exc}") from exc
    if not networks:
        raise ValueError("--allow-cidr is required before starting a session")
    return networks


def _interface_networks(interface: str) -> tuple:
    networks = []
    for addr in _net_if_addrs_or_exit().get(interface, []):
        if addr.family not in (socket.AF_INET, socket.AF_INET6):
            continue
        netmask = getattr(addr, "netmask", None)
        if not netmask:
            continue
        try:
            networks.append(
                ip_network(f"{addr.address.split('%', 1)[0]}/{netmask}", strict=False)
            )
        except ValueError:
            continue
    return tuple(networks)


def validate_targets(
    targets: List[Union[Device, str]],
    authorized_cidrs: list,
    *,
    interface: str,
    own_ip: Optional[str],
    own_ipv6: Optional[str],
    gateway_ip: Optional[str],
    gateway_ipv6: Optional[str],
) -> List[Union[Device, str]]:
    policy = AuthorizationPolicy(authorized_cidrs)
    connected_networks = _interface_networks(interface)
    validated: List[Union[Device, str]] = []

    for target in targets:
        raw_ip = target_ip(target)
        try:
            policy.assert_target_authorized(
                raw_ip,
                own_ip=own_ip,
                own_ipv6=own_ipv6,
                gateway=gateway_ip,
                gateway_ipv6=gateway_ipv6,
                connected_networks=connected_networks,
            )
            parsed = ip_address(raw_ip)
        except AuthorizationError as exc:
            raise ValueError(str(exc)) from exc
        validated.append(str(parsed) if isinstance(target, str) else target)

    return validated


def build_session_plan(
    *,
    interface: str,
    authorized_cidrs: list,
    targets: List[Union[Device, str]],
    arp_on: bool,
    dns_spoof_on: bool,
    captive_portal: bool,
    http_redirect_port: Optional[int],
    sniff_on: bool,
    mitm_on: bool,
    save_pcap: bool,
    rolling: bool,
    packet_verbose: bool = False,
    shaping_profile: Optional[ShapingProfile] = None,
    arp_interval: float = 2.0,
    arp_burst: int = 1,
    exploit: Optional[ExploitOptions] = None,
    portal_auto_launch: bool = False,
    portal_smart_spoof_all: bool = False,
    mitm_auto_launch: bool = False,
) -> SessionPlan:
    exploit = exploit or ExploitOptions()
    return SessionPlan(
        interface=interface,
        authorized_cidrs=tuple(str(network) for network in authorized_cidrs),
        targets=tuple(targets),
        arp=ArpOptions(
            enabled=arp_on,
            interval=arp_interval,
            burst=arp_burst,
            amplify=exploit.arp_amplify,
            amplify_burst=exploit.arp_amplify_burst,
            amplify_interval=exploit.arp_amplify_interval,
            cam_exhaust=exploit.cam_exhaust,
        ),
        dns=DnsOptions(
            enabled=dns_spoof_on,
            dnssec_mode=exploit.dnssec_mode,
            upstream=exploit.dnssec_upstream,
        ),
        portal=PortalOptions(
            enabled=captive_portal,
            http_redirect_port=http_redirect_port,
            hsts_idn_demo=exploit.hsts_idn_demo,
            auto_launch=portal_auto_launch,
            smart_spoof_all=portal_smart_spoof_all,
        ),
        capture=CaptureOptions(
            enabled=sniff_on,
            save_pcap=save_pcap,
            rolling=rolling,
            packet_verbose=packet_verbose,
        ),
        shaping=shaping_profile,
        mitm=MitmOptions(enabled=mitm_on, auto_launch=mitm_auto_launch),
    )


def main() -> None:
    args = parse_args()
    if args.version:
        print(VERSION)
        return

    config.DRY_RUN = args.dry_run
    if args.emergency_restore_state:
        if not args.yes_really_restore_firewall_snapshot:
            sys.exit(
                "[NetShaper] Emergency restore requires "
                "--yes-really-restore-firewall-snapshot because it can "
                "overwrite unrelated firewall changes."
            )
        SystemChecker.check()
        config.configure_logging(console_only=config.DRY_RUN)
        from netshaper.core.state_manager import StateSnapshotManager

        if not StateSnapshotManager.restore_from_state_file(
            args.emergency_restore_state, restore_firewall=True
        ):
            sys.exit("[NetShaper] Emergency snapshot restore failed.")
        print_flush("[+] Emergency snapshot restore complete.")
        return

    SystemChecker.check()
    try:
        authorized_cidrs = parse_authorized_cidrs(args.allow_cidr)
    except ValueError as exc:
        sys.exit(f"[NetShaper] {exc}")
    config.configure_logging(console_only=config.DRY_RUN)
    if config.DRY_RUN:
        print_flush("[*] DRY RUN MODE - no system changes.\n")

    print_flush(config.BANNER)
    interface = choose_interface(args.interface)

    from netshaper.core.orchestrator import NetShaper

    try:
        ns = NetShaper(interface, authorized_cidrs=authorized_cidrs)
    except (RuntimeError, ValueError) as exc:
        sys.exit(f"[NetShaper] {exc}")

    registered_plugins: list[tuple[str, str]] = []
    try:
        if not config.DRY_RUN:
            if not ns.load_state_and_cleanup():
                raise RuntimeError(
                    "A stale NetShaper session could not be fully recovered."
                )

        # Load and discover plugins
        if args.plugin:
            try:
                plugin_config = PluginLoader.parse_plugin_config(args.plugin_config)
                PluginLoader.load_and_register(
                    discover_builtins=True,
                    discover_entry_points=True,
                    discover_filesystem=False,
                    requested_plugin_ids=args.plugin,
                )
                for plugin_id in args.plugin:
                    try:
                        scope, specific_config = PluginLoader.settings_for_plugin(
                            plugin_id,
                            plugin_config,
                            {
                                "type": "cidr",
                                "cidrs": [str(network) for network in authorized_cidrs],
                            },
                        )
                        if plugin_id == "wifi-recon":
                            specific_config.setdefault("interface", interface)
                        instance_id = ns.register_plugin(
                            plugin_id,
                            scope,
                            config=specific_config,
                        )
                        registered_plugins.append((plugin_id, instance_id))
                        print_flush(
                            f"  [+] Plugin {plugin_id} ready ({instance_id})"
                        )
                    except Exception as exc:
                        print_flush(f"  [!] Failed to load plugin {plugin_id}: {exc}")
                        if not config.DRY_RUN:
                            raise
            except PluginLoadError as exc:
                sys.exit(f"[NetShaper] Plugin loading failed: {exc}")

        if not ns.own_ip:
            sys.exit("[NetShaper] Could not determine own IP.")
        if not ns.gw:
            ns.gw = safe_input("  Gateway IP: ")
        print_flush(f"  Your IP : {ns.own_ip}\n  Gateway : {ns.gw}")
        if ns.gw_ipv6:
            print_flush(f"  IPv6 GW : {ns.gw_ipv6}")

        if args.targets:
            raw_targets = list(args.targets)
            try:
                targets = validate_targets(
                    raw_targets,
                    authorized_cidrs,
                    interface=interface,
                    own_ip=ns.own_ip,
                    own_ipv6=ns.own_ipv6,
                    gateway_ip=ns.gw,
                    gateway_ipv6=ns.gw_ipv6,
                )
            except ValueError as exc:
                sys.exit(f"[NetShaper] {exc}")
            print_flush(f"  Targets from --targets: {', '.join(targets)}")
        else:
            devices = ns.discover(max_discovery_hosts=args.max_discovery_hosts)
            selected_targets = pick_targets_ui(devices)
            try:
                targets = validate_targets(
                    selected_targets,
                    authorized_cidrs,
                    interface=interface,
                    own_ip=ns.own_ip,
                    own_ipv6=ns.own_ipv6,
                    gateway_ip=ns.gw,
                    gateway_ipv6=ns.gw_ipv6,
                )
            except ValueError as exc:
                sys.exit(f"[NetShaper] {exc}")
        target_ips = [target_ip(target) for target in targets]

        if args.modules:
            raw_choices = args.modules
            print_flush(f"  Offensive network modules from CLI: {raw_choices}")
        else:
            print_module_menu()
            raw_choices = safe_input("  Choices: ")
        modules, invalid = normalize_module_choices(raw_choices)
        if invalid:
            print_flush("  [!] Ignoring invalid module choices: " + ", ".join(invalid))
        if not modules:
            print_flush("  [!] No valid offensive network modules selected.")
            sys.exit(0)

        exploit = resolve_exploit_options(args, modules)
        modules, exploit = apply_module_dependencies(modules, exploit)
        if not modules and not (
            exploit.arp_amplification_enabled
            or exploit.dnssec_enabled
            or exploit.hsts_idn_demo
        ):
            print_flush("  [!] No offensive network modules remain enabled.")
            sys.exit(0)

        arp_on = ModuleID.ARP in modules
        dns_spoof_on = ModuleID.DNS in modules
        captive_portal = ModuleID.PORTAL in modules
        throttle_on = ModuleID.SHAPING in modules
        sniff_on = ModuleID.CAPTURE in modules
        mitm_on = ModuleID.MITM in modules

        if dns_spoof_on and not captive_portal:
            print_flush("  [!] DNS spoofing without captive portal can break HTTP.")
            if safe_input("  Enable captive portal too? (y/n): ").lower() == "y":
                captive_portal = True
                modules.add(ModuleID.PORTAL)

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
            print_flush(
                "      For HTTPS, install the mitmproxy CA on the target device."
            )

        limit = (
            args.limit
            if throttle_on and args.limit is not None
            else pick_limit_ui()
            if throttle_on
            else None
        )
        shaping_profile = (
            ShapingProfile(
                bandwidth_mbps=limit,
                latency_ms=args.latency_ms,
                jitter_ms=args.jitter_ms,
                loss_percent=args.loss_percent,
                corruption_percent=args.corruption_percent,
                duplicate_percent=args.duplicate_percent,
                reorder_percent=args.reorder_percent,
            )
            if throttle_on
            else None
        )
        save_pcap = False
        rolling = False
        if sniff_on:
            save_pcap = safe_input("  Save to .pcap? (y/n): ").lower() == "y"
            if save_pcap:
                rolling = (
                    safe_input("  Use rolling 50 MB files? (y/n): ").lower() == "y"
                )

        portal_auto_launch = False
        portal_smart_spoof_all = dns_spoof_on
        portal_required = (
            dns_spoof_on
            or http_redirect_port == 80
            or exploit.portal_web_security_demo
        )
        if portal_required and not ns.fake_server_ready():
            if dns_spoof_on:
                print_flush(
                    "  [!] Fake DNS (port 53) is not verified for this session."
                )
                portal_required_error = (
                    "[NetShaper] DNS spoofing requires verified fake DNS."
                )
                portal_hint_smart_spoof = True
            elif http_redirect_port == 80:
                print_flush(
                    "  [!] Fake HTTP (port 80) is not verified for this session."
                )
                portal_required_error = (
                    "[NetShaper] Captive portal requires verified fake HTTP."
                )
                portal_hint_smart_spoof = dns_spoof_on
            else:
                print_flush(
                    "  [!] HSTS demo HTTP service (port 80) is not verified "
                    "for this session."
                )
                portal_required_error = (
                    "[NetShaper] HSTS demo requires verified fake HTTP."
                )
                portal_hint_smart_spoof = dns_spoof_on

            print_flush(
                "      "
                + portal_launch_hint(
                    exploit,
                    host_ip=ns.own_ip,
                    authorized_cidrs=authorized_cidrs,
                    smart_spoof_all=portal_hint_smart_spoof,
                    health_token=ns.fake_server_health_token(),
                )
            )
            if (
                safe_input(
                    "  Auto-launch netshaper-portal after confirmation? (y/n): "
                ).lower()
                == "y"
            ):
                portal_auto_launch = True
                portal_smart_spoof_all = portal_hint_smart_spoof
            else:
                sys.exit(portal_required_error)

        mitm_auto_launch = False
        if http_redirect_port == 8088:
            if check_local_port(ns.own_ip, 8088):
                sys.exit(
                    "[NetShaper] Port 8088 is already in use by an "
                    "unverified listener."
                )
            print_flush("  [!] mitmproxy (port 8088) not running.")
            if (
                safe_input(
                    "  Auto-launch mitmproxy after confirmation? (y/n): "
                ).lower()
                == "y"
            ):
                mitm_auto_launch = True
            else:
                print_flush(
                    "      mitmweb --mode transparent --listen-port 8088 "
                    "--set web_port=8083"
                )
                sys.exit("[NetShaper] mitmproxy is required for HTTPS inspection.")

        plan = build_session_plan(
            interface=interface,
            authorized_cidrs=authorized_cidrs,
            targets=targets,
            arp_on=arp_on,
            dns_spoof_on=dns_spoof_on,
            captive_portal=captive_portal,
            http_redirect_port=http_redirect_port,
            sniff_on=sniff_on,
            mitm_on=mitm_on,
            save_pcap=save_pcap,
            rolling=rolling,
            packet_verbose=args.packet_verbose,
            shaping_profile=shaping_profile,
            arp_interval=args.arp_interval,
            arp_burst=args.arp_burst,
            exploit=exploit,
            portal_auto_launch=portal_auto_launch,
            portal_smart_spoof_all=portal_smart_spoof_all,
            mitm_auto_launch=mitm_auto_launch,
        )

        W = 58

        def _yn(flag: bool) -> str:
            return green("Yes") if flag else "No"

        print_flush(f"\n{cyan('=' * W)}")
        print_flush(bold(f"  {'Offensive Network Session'}"))
        print_flush(cyan("-" * W))
        print_flush(
            f"  Scope CIDRs   : "
            f"{cyan(', '.join(str(network) for network in authorized_cidrs))}"
        )
        print_flush(f"  Targets       : {cyan(', '.join(target_ips))}")
        print_flush(f"  ARP spoof     : {_yn(arp_on)}")
        if arp_on:
            print_flush(
                f"    Burst/timing: {args.arp_burst} packet(s) "
                f"every {args.arp_interval:g}s"
            )
        print_flush(f"  DNS spoof     : {_yn(dns_spoof_on)}")
        print_flush(f"  Captive portal: {_yn(captive_portal)}")
        if captive_portal:
            print_flush(f"    HTTP -> port: {http_redirect_port}")
        if portal_auto_launch:
            print_flush("    Portal start: after confirmation")
        print_flush(
            f"  Throttle      : {green(f'{limit} Mbps') if throttle_on else 'No'}"
        )
        if shaping_profile and shaping_profile.has_impairments:
            print_flush(
                "    Netem       : " + " ".join(shaping_profile.netem_arguments())
            )
        print_flush(f"  mitmproxy     : {_yn(mitm_on)}")
        if mitm_on:
            print_flush(f"    Auto-start  : {_yn(mitm_auto_launch)}")
        print_flush(f"  Sniffer       : {_yn(sniff_on)}")
        if sniff_on and save_pcap:
            print_flush(f"    Rolling pcap: {_yn(rolling)}")
        print_flush(f"  ARP amplify   : {_yn(exploit.arp_amplify > 0)}")
        if exploit.arp_amplify > 0:
            print_flush(
                f"    Phantom IPs : {exploit.arp_amplify} "
                f"({exploit.arp_amplify_burst} pkts / "
                f"{exploit.arp_amplify_interval:g}s)"
            )
        print_flush(f"  CAM exhaust   : {_yn(exploit.cam_exhaust > 0)}")
        if exploit.cam_exhaust > 0:
            print_flush(f"    Phantom IPs : {exploit.cam_exhaust}")
        print_flush(
            f"  DNSSEC mode   : "
            f"{exploit.dnssec_mode if exploit.dnssec_enabled else 'off'}"
        )
        print_flush(f"  HSTS/IDN demo : {_yn(exploit.hsts_idn_demo)}")
        print_flush(f"{cyan('=' * W)}")
        print_flush(
            "  Proceeding confirms authorization for the listed scope and targets."
        )

        if safe_input(f"\n  {bold('Proceed?')} (y/n): ").lower() != "y":
            sys.exit(0)

        def sig_handler(_sig, _frame):
            ns.stop_event.set()

        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)

        try:
            SessionRunner(
                ns,
                registered_plugins=tuple(registered_plugins),
            ).execute(plan)
        except KeyboardInterrupt:
            ns.stop_event.set()
    except RuntimeError as exc:
        sys.exit(f"[NetShaper] {exc}")
    finally:
        ns.close()


if __name__ == "__main__":
    main()
