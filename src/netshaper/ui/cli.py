"""
NetShaper — Command Line Interface.
"""
from __future__ import annotations

import argparse
import os
import signal
import socket
import sys
import threading
from typing import List, Optional

# When this file is executed directly from inside the package directory,
# absolute imports such as netshaper.config need the package parent on sys.path.
PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE_PARENT = os.path.dirname(PACKAGE_DIR)
if PACKAGE_PARENT not in sys.path:
    sys.path.insert(0, PACKAGE_PARENT)

import psutil

from netshaper import config

VERSION = "3.8.0"
from netshaper.models import Device
from netshaper.system import check_local_port
from netshaper.utils import print_flush, safe_input


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NetShaper v3.8.0")
    parser.add_argument(
        "--version", action="store_true",
        help="Show NetShaper version and exit.",
    )
    parser.add_argument(
        "-i", "--interface",
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
        "--limit",
        type=float,
        help="Set bandwidth throttling in Mbps without using the interactive prompt.",
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
    return args


def choose_interface(requested: Optional[str] = None) -> str:
    if requested:
        return requested

    ifaces = [
        (name, addr.address)
        for name, addrs in psutil.net_if_addrs().items()
        for addr in addrs
        if addr.family == socket.AF_INET and not addr.address.startswith("127.")
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
        print_flush(
            f"  {idx:<4} {dev.ip:<16} {hostname:<28} {dev.mac}"
        )
    print_flush("=" * 90)

    while True:
        choice = safe_input(
            "\n  Select devices (e.g. 1,2,5  1-3  all): "
        ).lower()
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
                        selected.extend(devices[first - 1:last])
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


def normalize_feature_choices(raw: str) -> tuple[set[int], list[str]]:
    """Parse feature numbers and return valid features plus invalid tokens."""
    features: set[int] = set()
    invalid: list[str] = []

    for token in raw.split():
        try:
            value = int(token)
        except ValueError:
            invalid.append(token)
            continue

        if 1 <= value <= 6:
            features.add(value)
        else:
            invalid.append(token)

    return features, invalid


def pick_limit_ui() -> float:
    presets = {"1": 1.0, "2": 2.0, "3": 3.0, "4": 5.0}
    print_flush("\n  Bandwidth presets:")
    print_flush("  [1] 1 Mbps  [2] 2 Mbps  [3] 3 Mbps  [4] 5 Mbps  [5] Custom")
    while True:
        choice = safe_input("  Select (1-5): ")
        if choice in presets:
            return presets[choice]
        if choice == "5":
            try:
                value = float(safe_input("  Enter Mbps: "))
                if 0.1 <= value <= 1000:
                    return value
                print_flush("  [!] 0.1 - 1000 Mbps only.")
            except ValueError:
                print_flush("  [!] Invalid number.")


def run_active_session(
    ns,
    targets: List[str],
    *,
    arp_on: bool,
    dns_spoof_on: bool,
    captive_portal: bool,
    http_redirect_port: Optional[int],
    throttle_on: bool,
    limit: Optional[float],
    sniff_on: bool,
    save_pcap: bool,
    rolling: bool,
) -> None:
    try:
        ns._apply_global_rules()
        for target in targets:
            ns.add_target(
                target,
                arp_on=arp_on,
                dns_spoof=dns_spoof_on,
                captive_portal=captive_portal,
                http_redirect_port=http_redirect_port,
                limit=limit if throttle_on else None,
            )

        if sniff_on:
            ns.launch_sniffer(
                target_ips=targets,
                save_pcap=save_pcap,
                rolling=rolling,
            )

        ns.save_state()
        threading.Thread(target=ns.monitor, daemon=True).start()
        print_flush("[*] Active. Press Ctrl+C to stop.")
        while not ns.stop_event.wait(1):
            pass
    finally:
        ns.cleanup()
        print_flush("[+] Teardown complete. Goodbye.")


def main() -> None:
    args = parse_args()
    if args.version:
        print(VERSION)
        return

    config.configure_logging()
    config.DRY_RUN = args.dry_run
    if config.DRY_RUN:
        print_flush("[*] DRY RUN MODE - no system changes.\n")

    print_flush(config.BANNER)
    interface = choose_interface(args.interface)

    from netshaper.core.orchestrator import NetShaper

    if not config.DRY_RUN:
        NetShaper(interface).load_state_and_cleanup()

    ns = NetShaper(interface)
    if not ns.own_ip:
        sys.exit("[NetShaper] Could not determine own IP.")
    if not ns.gw:
        ns.gw = safe_input("  Gateway IP: ")
    print_flush(f"  Your IP : {ns.own_ip}\n  Gateway : {ns.gw}")
    if ns.gw_ipv6:
        print_flush(f"  IPv6 GW : {ns.gw_ipv6}")

    if args.targets:
        raw_targets = []
        for token in args.targets:
            raw_targets.extend(part.strip() for part in token.split(",") if part.strip())
        targets = raw_targets
        print_flush(f"  Targets from --targets: {', '.join(targets)}")
    else:
        devices = ns.discover()
        targets = [dev.ip for dev in pick_targets_ui(devices)]

    print_flush("\n  -- Features (enter numbers e.g. 1 3 5) ------------------")
    print_flush("  [1] ARP spoofing (core MITM)")
    print_flush("  [2] DNS spoofing")
    print_flush("  [3] Captive portal (index.html for HTTP)")
    print_flush("  [4] Bandwidth throttle")
    print_flush("  [5] Packet sniffer")
    print_flush("  [6] mitmproxy HTTPS inspection")

    raw_choices = safe_input("  Choices: ")
    features, invalid = normalize_feature_choices(raw_choices)
    if invalid:
        print_flush("  [!] Ignoring invalid feature choices: " + ", ".join(invalid))
    if not features:
        print_flush("  [!] No valid features selected.")
        sys.exit(0)

    arp_on = 1 in features
    dns_spoof_on = 2 in features
    captive_portal = 3 in features
    throttle_on = 4 in features
    sniff_on = 5 in features
    mitm_on = 6 in features

    if dns_spoof_on and not captive_portal:
        print_flush("  [!] DNS spoofing without captive portal can break HTTP.")
        if safe_input("  Enable captive portal too? (y/n): ").lower() == "y":
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
        print_flush("      For HTTPS, install the mitmproxy CA on the target device.")

    limit = args.limit if throttle_on and args.limit is not None else pick_limit_ui() if throttle_on else None
    save_pcap = False
    rolling = False
    if sniff_on:
        save_pcap = safe_input("  Save to .pcap? (y/n): ").lower() == "y"
        if save_pcap:
            rolling = safe_input("  Use rolling 50 MB files? (y/n): ").lower() == "y"

    if dns_spoof_on and not check_local_port(ns.own_ip, 53, socket.SOCK_DGRAM):
        print_flush("  [!] Fake DNS (port 53) not reachable.")
        print_flush("      sudo python3 fake_server3.py")
        if safe_input("  Continue anyway? (y/n): ").lower() != "y":
            sys.exit(0)

    if http_redirect_port == 80 and not check_local_port(ns.own_ip, 80):
        print_flush("  [!] Fake HTTP (port 80) not reachable.")
        print_flush("      sudo python3 fake_server3.py")
        if safe_input("  Continue anyway? (y/n): ").lower() != "y":
            sys.exit(0)

    if http_redirect_port == 8088 and not check_local_port(ns.own_ip, 8088):
        print_flush("  [!] mitmproxy (port 8088) not reachable.")
        if safe_input("  Auto-launch mitmproxy? (y/n): ").lower() == "y":
            if not ns.launch_mitmproxy(port=8088, web_port=8083):
                if safe_input("  Continue without mitmproxy? (y/n): ").lower() != "y":
                    sys.exit(0)
        else:
            print_flush(
                "      mitmweb --mode transparent --listen-port 8088 "
                "--set web_port=8083"
            )
            if safe_input("  Continue anyway? (y/n): ").lower() != "y":
                sys.exit(0)

    print_flush(f"\n{'=' * 58}")
    print_flush(f"  Targets       : {', '.join(targets)}")
    print_flush(f"  ARP spoof     : {'Yes' if arp_on else 'No'}")
    print_flush(f"  DNS spoof     : {'Yes' if dns_spoof_on else 'No'}")
    print_flush(f"  Captive portal: {'Yes' if captive_portal else 'No'}")
    if captive_portal:
        print_flush(f"    HTTP -> port: {http_redirect_port}")
    print_flush(f"  Throttle      : {f'{limit} Mbps' if throttle_on else 'No'}")
    print_flush(f"  mitmproxy     : {'Yes' if mitm_on else 'No'}")
    print_flush(f"  Sniffer       : {'Yes' if sniff_on else 'No'}")
    if sniff_on and save_pcap:
        print_flush(f"    Rolling pcap: {'Yes' if rolling else 'No'}")
    print_flush(f"{'=' * 58}")

    if safe_input("\n  Proceed? (y/n): ").lower() != "y":
        sys.exit(0)

    def sig_handler(_sig, _frame):
        ns.stop_event.set()

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    try:
        run_active_session(
            ns,
            targets,
            arp_on=arp_on,
            dns_spoof_on=dns_spoof_on,
            captive_portal=captive_portal,
            http_redirect_port=http_redirect_port,
            throttle_on=throttle_on,
            limit=limit,
            sniff_on=sniff_on,
            save_pcap=save_pcap,
            rolling=rolling,
        )
    except KeyboardInterrupt:
        ns.stop_event.set()


if __name__ == "__main__":
    main()
