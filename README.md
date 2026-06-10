# NetShaper

NetShaper is a modular, authorized network-testing toolkit for controlled lab and client-network analysis. It combines discovery, packet capture, DNS handling, traffic shaping, and MITM-style interception in a single Python CLI.

**Use only on networks and devices you own or have explicit written permission to test.**

## Features

- Dual-stack ARP + NDP spoofing (IPv4 and IPv6 MITM)
- Per-target DNS redirect and captive portal (HTTP)
- Bandwidth throttling via Linux `tc` HTB
- Packet capture with optional rolling `.pcap` files
- Transparent HTTPS inspection via mitmproxy
- Atomic state persistence and automatic stale-session recovery
- Full `--dry-run` mode — prints commands without touching the system

## Requirements

- Linux, Python ≥ 3.10
- Root (`sudo`)
- `iptables` / `ip6tables`, `tc`, `sysctl` on PATH
- `scapy`, `psutil` (installed automatically)

## Installation

```bash
python -m pip install -e .
```

Dev extras (pytest etc.):

```bash
python -m pip install -e ".[dev]"
```

## Quick Start

```bash
sudo env PYTHONPATH="$PWD/src" python -m netshaper -i <interface> \
  --allow-cidr <authorized-cidr>
```

Dry-run preview (no system changes):

```bash
sudo env PYTHONPATH="$PWD/src" python -m netshaper -i <interface> \
  --allow-cidr <authorized-cidr> --targets <ip> --dry-run
```

Optional DNS/HTTP captive-portal helper (separate terminal):

```bash
sudo env PYTHONPATH="$PWD/src" python -m netshaper.fake_server3 --smart-spoof-all --host-ip <your-ip>
```

## User Guide

See [USER_GUIDE.md](USER_GUIDE.md) for the full workflow, shell aliases, fake-server modes, discovery behaviour, dry-run usage, and troubleshooting.

## Testing

```bash
python -m unittest discover -s tests -v
```

Root-only end-to-end namespace checks:

```bash
sudo env PYTHONPATH="$PWD/src:$PWD" python -m unittest tests.test_netns_integration -v
```

## Release Hygiene

Do not distribute a working tree ZIP. Build releases from a clean checkout with
`python -m build` or `git archive` so `.git`, virtual environments, packet
captures, logs, caches, reference artifacts, and state files are excluded.
Treat Git history and packet captures as sensitive material.

## Logs

When running normally (not `--dry-run`), NetShaper writes to `/var/log/netshaper.log`.
After startup, the CLI prints a verified evidence block with the session ID,
timestamp, interface, targets, state file, log file, monitor status, sniffer
status, and any packet-capture files known at that point. Auto-launched
mitmproxy output is written to `/run/netshaper/<session-id>/mitmproxy.log`.

During the active session NetShaper keeps checking the monitor thread, requested
packet sniffer, mitmproxy process, and configured local redirect ports. A failed
health check is reported as an error and triggers normal cleanup instead of
continuing to display a successful status.

## Notes

- Session state is stored under `/run/netshaper/` and cleaned up on exit.
- Only one NetShaper instance may run at a time (enforced via lock file).
- `fake_server3` is an optional helper for captive-portal and DNS lab scenarios; it is not required for ARP spoofing or traffic shaping.
