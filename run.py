#!/usr/bin/env python3
"""
run.py — NetShaper v3.8.0 entry point
──────────────────────────────────────
Thin launcher: argparse → feature selection → session lifecycle.
All logic lives inside the netshaper/ package; this file is intentionally
kept short so the wiring is easy to audit at a glance.

Usage:
    sudo python3 run.py [--dry-run]
"""

import os
import sys
import signal
import socket
import threading
import warnings
import logging
import argparse

from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import psutil

import netshaper.system as _sys_module          # set DRY_RUN before any other import
from netshaper.system  import SystemChecker, check_local_port, safe_input, print_flush
from netshaper.core    import NetShaper
from netshaper.ui      import (
    pick_targets_ui, pick_features_ui,
    pick_limit_ui, print_summary,
)


# ── Logging setup ─────────────────────────────────────────────────────────────
LOG_FILE = "netshaper.log"
_fh = logging.FileHandler(LOG_FILE)
_ch = logging.StreamHandler()
_fh.setFormatter(logging.Formatter(
    '%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'
))
_ch.setFormatter(logging.Formatter(
    '[NetShaper] %(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S'
))
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


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="NetShaper v3.8.0")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print system commands without executing them",
    )
    args = parser.parse_args()

    # Propagate dry-run flag into the system module before anything runs
    _sys_module.DRY_RUN = args.dry_run
    if args.dry_run:
        print_flush("[*] DRY RUN MODE — no system changes.\n")

    print_flush(BANNER)
    SystemChecker.check()

    # ── Interface selection ───────────────────────────────────────────────────
    ifaces = [
        (name, addr.address)
        for name, addrs in psutil.net_if_addrs().items()
        for addr in addrs
        if addr.family == socket.AF_INET
        and not addr.address.startswith("127.")
    ]
    if not ifaces:
        sys.exit("[NetShaper] No active interface.")
    if len(ifaces) == 1:
        interface = ifaces[0][0]
        print_flush(f"  Interface: {interface} ({ifaces[0][1]})")
    else:
        print_flush("\n  Interfaces:")
        for i, (name, ip) in enumerate(ifaces, 1):
            print_flush(f"  [{i}] {name} ({ip})")
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

    # ── Stale state recovery ──────────────────────────────────────────────────
    if not args.dry_run:
        NetShaper(interface).load_state_and_cleanup()

    ns = NetShaper(interface)
    if not ns.own_ip:
        sys.exit("[NetShaper] Could not determine own IP.")
    if not ns.gw:
        ns.gw = safe_input("  Gateway IP: ")
    print_flush(f"  Your IP : {ns.own_ip}\n  Gateway : {ns.gw}")
    if ns.gw_ipv6:
        print_flush(f"  IPv6 GW : {ns.gw_ipv6}")

    # ── Discovery & target selection ──────────────────────────────────────────
    devices = ns.discover()
    targets = pick_targets_ui(devices)

    # ── Feature selection ─────────────────────────────────────────────────────
    features = pick_features_ui()

    arp_on         = 1 in features
    dns_spoof_on   = 2 in features
    captive_portal = 3 in features
    throttle_on    = 4 in features
    sniff_on       = 5 in features
    mitm_on        = 6 in features

    if dns_spoof_on and not captive_portal:
        print_flush(
            "  [!] DNS spoofing without captive portal will break HTTP "
            "for the target."
        )
        if safe_input("  Enable captive portal too? (y/n): ").lower() == 'y':
            captive_portal = True

    # Derive HTTP redirect port from feature combination
    if captive_portal and mitm_on:
        http_redirect_port = 8088
    elif captive_portal:
        http_redirect_port = 80
    elif mitm_on:
        http_redirect_port = 8088
    else:
        http_redirect_port = None

    if http_redirect_port:
        print_flush("  [!] HTTP redirect captures plain HTTP only.")
        print_flush(
            "      For HTTPS install the mitmproxy CA on the target device."
        )

    limit     = pick_limit_ui() if throttle_on else None
    save_pcap = False
    rolling   = False
    if sniff_on:
        save_pcap = safe_input("  Save to .pcap? (y/n): ").lower() == 'y'
        if save_pcap:
            rolling = (
                safe_input("  Use rolling 50 MB files? (y/n): ").lower() == 'y'
            )

    # ── Pre-flight checks ─────────────────────────────────────────────────────
    if dns_spoof_on and not check_local_port(
            ns.own_ip, 53, socket.SOCK_DGRAM):
        print_flush("  [!] Fake DNS (port 53) not reachable.")
        print_flush("      sudo python3 fake_server3.py")
        if safe_input("  Continue anyway? (y/n): ").lower() != 'y':
            sys.exit(0)

    if http_redirect_port == 80 and not check_local_port(ns.own_ip, 80):
        print_flush("  [!] Fake HTTP (port 80) not reachable.")
        print_flush("      sudo python3 fake_server3.py")
        if safe_input("  Continue anyway? (y/n): ").lower() != 'y':
            sys.exit(0)

    if http_redirect_port == 8088 and not check_local_port(ns.own_ip, 8088):
        print_flush("  [!] mitmproxy (port 8088) not reachable.")
        if safe_input("  Auto-launch mitmproxy? (y/n): ").lower() == 'y':
            if not ns.launch_mitmproxy(port=8088, web_port=8083):
                if safe_input(
                    "  Continue without mitmproxy? (y/n): "
                ).lower() != 'y':
                    sys.exit(0)
        else:
            print_flush(
                "      mitmweb --mode transparent --listen-port 8088 "
                "--set web_port=8083"
            )
            if safe_input("  Continue anyway? (y/n): ").lower() != 'y':
                sys.exit(0)

    # ── Summary + confirmation ────────────────────────────────────────────────
    print_summary(
        targets, arp_on, dns_spoof_on, captive_portal,
        http_redirect_port, throttle_on, limit,
        mitm_on, sniff_on, save_pcap, rolling,
    )
    if safe_input("\n  Proceed? (y/n): ").lower() != 'y':
        sys.exit(0)

    # ── Signal handlers ───────────────────────────────────────────────────────
    def sig_handler(sig, frame):
        log.warning("Signal received — shutting down…")
        ns.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT,  sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    # ── Activate ──────────────────────────────────────────────────────────────
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
            target_ips=[t.ip for t in targets],
            save_pcap=save_pcap,
            rolling=rolling,
        )

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
