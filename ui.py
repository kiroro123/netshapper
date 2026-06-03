"""
netshaper.ui
────────────
Interactive terminal UI helpers: device picker, bandwidth preset picker,
and the feature selection menu.

All functions in this module are pure I/O — they read from stdin and write
to stdout. No network operations, no system calls beyond terminal helpers.
Swap this file to add a web UI or a non-interactive CLI mode without
touching any other module.
"""

import sys
from typing import List, Optional, Set

from .models import Device
from .system import safe_input, print_flush


# ── Device picker ─────────────────────────────────────────────────────────────

def pick_targets_ui(devices: List[Device]) -> List[Device]:
    """
    Display a numbered device table and return the user-selected subset.
    Accepts individual indices, ranges (1-3), and 'all'.
    """
    if not devices:
        sys.exit("[NetShaper] No devices found.")

    print_flush("\n" + "=" * 90)
    print_flush("  Devices:")
    print_flush("=" * 90)
    print_flush(f"  {'No':<4} {'IP':<16} {'Hostname':<28} {'MAC'}")
    for i, d in enumerate(devices, 1):
        print_flush(
            f"  {i:<4} {d.ip:<16} {(d.hostname or ''):<28} {d.mac}"
        )
    print_flush("=" * 90)

    while True:
        choice = safe_input(
            "\n  Select devices (e.g. 1,2,5  1-3  all): "
        ).lower()
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
                        selected.extend(devices[s - 1:e])
                    else:
                        print_flush(f"  [!] Range {a}-{b} out of bounds.")
                        selected = []
                        break
                else:
                    idx = int(part) - 1
                    if 0 <= idx < len(devices):
                        selected.append(devices[idx])
                    else:
                        print_flush(f"  [!] Index {part} out of range.")
                        selected = []
                        break
            else:
                if selected:
                    return selected
                print_flush("  [!] No valid devices selected.")
        except ValueError:
            print_flush(
                "  [!] Invalid format. Use numbers, ranges, or 'all'."
            )


# ── Bandwidth preset picker ───────────────────────────────────────────────────

def pick_limit_ui() -> float:
    """Return a bandwidth limit in Mbps from presets or a custom value."""
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


# ── Feature menu ──────────────────────────────────────────────────────────────

def pick_features_ui() -> Set[int]:
    """
    Display the feature selection menu and return the set of chosen feature IDs.

    Feature IDs:
      1 — ARP spoofing (core MITM)
      2 — DNS spoofing
      3 — Captive portal (index.html for HTTP)
      4 — Bandwidth throttle
      5 — Packet sniffer
      6 — mitmproxy HTTPS inspection
    """
    print_flush("\n  ── Features (enter numbers e.g. 1 3 5) ──────────────────")
    print_flush("  [1] ARP spoofing (core MITM)")
    print_flush("  [2] DNS spoofing")
    print_flush("  [3] Captive portal (index.html for HTTP)")
    print_flush("  [4] Bandwidth throttle")
    print_flush("  [5] Packet sniffer")
    print_flush("  [6] mitmproxy HTTPS inspection")
    choices = safe_input("  Choices: ").split()
    return {int(c) for c in choices if c.isdigit() and 1 <= int(c) <= 6}


# ── Summary banner ────────────────────────────────────────────────────────────

def print_summary(targets: List[Device], arp_on: bool, dns_spoof_on: bool,
                  captive_portal: bool, http_redirect_port: Optional[int],
                  throttle_on: bool, limit: Optional[float],
                  mitm_on: bool, sniff_on: bool,
                  save_pcap: bool, rolling: bool):
    print_flush(f"\n{'=' * 58}")
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
    print_flush(f"{'=' * 58}")
