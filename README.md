# NetShaper

NetShaper is a modular, authorized network-testing toolkit for controlled lab and client-network analysis. It combines discovery, packet capture, DNS handling, traffic shaping, and MITM-style interception in a single Python CLI.

**Use only on networks and devices you own or have explicit written permission to test.**

## Architecture

NetShaper is organized into independently auditable components:

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI Entry Point                          │
│              (src/netshaper/ui/cli.py)                          │
└─────────────────────┬───────────────────────────────────────────┘
                      │
      ┌───────────────┼───────────────┐
      │               │               │
      ▼               ▼               ▼
  ┌────────┐   ┌────────────┐  ┌──────────┐
  │Discovery│  │Authorization│  │Firewall  │
  │         │  │ Policy      │  │Manager   │
  │ ARP/NDP │  │             │  │          │
  │ sweep   │  │ CIDR checks │  │ iptables │
  │ hostname│  │             │  │ nat/mgle │
  └────────┘  └────────────┘  └──────────┘
      │               │               │
      └───────────────┼───────────────┘
                      │
      ┌───────────────┼───────────────┬──────────────┐
      │               │               │              │
      ▼               ▼               ▼              ▼
  ┌────────┐   ┌──────────┐   ┌──────────┐    ┌──────────┐
  │ Traffic│   │ Packet   │   │ mitmproxy│    │ Stale    │
  │ Shaper│   │ Sniffer  │   │ Manager  │    │ Recovery │
  │(tc HTB)│   │          │   │          │    │ Manager  │
  │        │   │ .pcap    │   │ HTTPS    │    │          │
  │        │   │ capture  │   │ intercept│    │ Cleanup  │
  └────────┘   └──────────┘   └──────────┘    └──────────┘
      │               │               │              │
      └───────────────┼───────────────┴──────────────┘
                      │
                      ▼
         ┌─────────────────────────────┐
         │  State Persistence Layer    │
         │  /run/netshaper/state.json  │
         └─────────────────────────────┘
```

## Component Responsibilities

| Module | Purpose | Audit Surface |
|--------|---------|---|
| **AuthorizationPolicy** | Validates target IPs against authorized CIDR allowlist | IP validation, bounds checking |
| **FirewallManager** | Manages iptables/ip6tables rules for forwarding and per-target interception | Firewall rule construction, cleanup |
| **MitmProxyManager** | Launches, monitors, and terminates mitmproxy in transparent mode | Process lifecycle, port binding |
| **RecoveryManager** | Detects and cleans up orphaned rules from crashed sessions | Stale session detection, atomic cleanup |
| **TargetSession** | Per-target interception (ARP spoofing, DNS redirect, firewall rules) | Per-target rule scope, isolation |
| **TrafficShaper** | Linux `tc`-based bandwidth throttling via HTB qdisc | Qdisc lifecycle, rate limiting |
| **PacketSniffer** | Captures packets to .pcap using libpcap | Packet capture, rolling files |
| **NetworkDiscovery** | ARP sweep and hostname resolution | Network scanning, host enumeration |
| **PluginLoader** | Discovers and loads third-party extension modules | Plugin registry, entry point discovery |

## Workflow: DNS Redirect + Captive Portal + HTTPS Inspection

A typical flow for testing a target device:

```
1. DISCOVERY PHASE
   ├─ NetShaper discovers targets on subnet via ARP sweep
   ├─ Resolves hostnames (reverse DNS)
   └─ Validates targets are in authorized CIDR

2. SETUP PHASE (per-target)
   ├─ AuthorizationPolicy checks target IP
   ├─ FirewallManager applies per-target iptables rules
   ├─ Setup ARP/NDP spoofing (TargetSession)
   │  └─ Device now sends traffic to NetShaper IP
   ├─ Setup DNS interception (iptables redirect 53 → fake_server3)
   ├─ Setup HTTP captive portal redirect
   └─ Setup HTTPS inspection (mitmproxy transparent mode)

3. ACTIVE SESSION
   ├─ fake_server3 captures DNS queries
   │  ├─ Responds with spoofed A/AAAA records
   │  └─ Serves captive portal redirect
   ├─ Device visits http://..., gets 302 to captive portal
   ├─ Captive portal serves mitmproxy root CA download
   ├─ Device installs CA and retries HTTPS
   ├─ HTTPS traffic flows through mitmproxy (transparent proxy)
   ├─ Traffic shaping applies bandwidth limits (tc HTB)
   ├─ Packet sniffer captures all traffic to .pcap
   └─ State persisted to /run/netshaper/<session-id>/state.json

4. SHUTDOWN PHASE
   ├─ Signal all subsystems to halt
   ├─ TargetSession cleanup (remove ARP spoofing, iptables rules)
   ├─ FirewallManager cleanup (remove global forwarding rules)
   ├─ MitmProxyManager cleanup (terminate mitmproxy)
   ├─ RecoveryManager verifies no stale rules remain
   ├─ Sysctl settings restored to pre-session state
   └─ State file cleaned up

5. RECOVERY (if process crashes)
   ├─ Next NetShaper startup detects stale /run/netshaper/state.json
   ├─ RecoveryManager checks process ownership (PID + start time)
   ├─ Orphaned rules detected and removed
   │  ├─ Firewall rules cleaned
   │  ├─ Traffic shaper qdisc removed
   │  ├─ Sysctl settings restored
   │  └─ State file deleted
   └─ Recovery logged to /var/log/netshaper.log
```

## Features

- Dual-stack ARP + NDP spoofing (IPv4 and IPv6 MITM)
- Bounded ARP/NDP burst controls for cache-race training
- Per-target DNS redirect and captive portal (HTTP)
- DNSSEC suppression/fail-closed modeling in the fake resolver
- Reserved-domain HSTS and IDN/Punycode training page (no credential capture)
- Bandwidth throttling and controlled impairment via Linux `tc` HTB + netem
- Packet capture with optional rolling `.pcap` files
- Transparent HTTPS inspection via mitmproxy
- Atomic state persistence and automatic stale-session recovery
- Full `--dry-run` mode — prints commands without touching the system
- Modular, independently auditable components
- **Plugin system:** Load third-party extension modules (WiFi recon, BLE scanning, etc.)

## Requirements

- Linux, Python ≥ 3.10
- Root (`sudo`)
- `iptables` / `ip6tables`, `tc`, `sysctl` on PATH
- `scapy`, `psutil` (installed automatically)

## Installation

```bash
python -m pip install -e .
```

Dev extras (pytest, mypy, bandit, ruff, coverage):

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

Lab behavior examples:

```bash
# Bounded ARP/NDP burst: at most 5 packets every 0.25 seconds.
sudo env PYTHONPATH="$PWD/src" python -m netshaper -i <interface> \
  --allow-cidr <authorized-cidr> --targets <ip> \
  --arp-burst 3 --arp-interval 0.5

# Model DNSSEC suppression and serve the static HSTS/IDN lesson.
sudo env PYTHONPATH="$PWD/src" python -m netshaper.fake_server3 \
  --host-ip <your-ip> --suppress-dnssec --web-security-demo \
  --idn-demo-domain арр.test
```

The web lesson is available at `/training/web-security`. IDN examples are
restricted to reserved `.test`, `.example`, `.invalid`, and `.localhost`
domains. Established or preloaded HSTS is not bypassed; the lesson demonstrates
the first-visit downgrade boundary and browser IDN display behavior.

## Plugin System

NetShaper supports third-party extension modules (plugins) for specialized capabilities
like wireless reconnaissance or Bluetooth scanning.

### Installing a Plugin

Plugins are installed as Python packages with an entry point:

```bash
pip install netshaper-wifi-recon  # example plugin package
```

The plugin must declare itself in its `pyproject.toml`:

```toml
[project.entry-points."netshaper.plugins"]
wifi-recon = "netshaper_wifi_recon:WifiReconPlugin"
```

### Using a Plugin

Pass `--plugin` to the CLI:

```bash
sudo env PYTHONPATH="$PWD/src" python -m netshaper -i <interface> \
  --allow-cidr <authorized-cidr> \
  --plugin wifi-recon \
  --plugin-config config.json
```

Plugins are started before target discovery and stopped on session shutdown. Plugin state
is persisted alongside the main NetShaper session state.

### Plugin Configuration

A JSON config file can be passed to all loaded plugins:

```json
{
  "wifi_scan_timeout": 10,
  "verbose": true
}
```

### Dry-Run with Plugins

Plugins see the `--dry-run` flag and should print commands instead of executing them:

```bash
sudo env PYTHONPATH="$PWD/src" python -m netshaper -i <interface> \
  --allow-cidr <authorized-cidr> \
  --plugin wifi-recon \
  --dry-run
```

## User Guide

See [USER_GUIDE.md](USER_GUIDE.md) for the full workflow, shell aliases, fake-server modes, discovery behaviour, dry-run usage, and troubleshooting.

## Security & Risk

See [SECURITY.md](SECURITY.md) for:
- Known risks (unauthenticated `/cert` endpoint, root privilege requirements)
- Mitigation strategies
- Recommended audit procedures
- Stale session recovery behavior

## Testing

Unit tests (mocked):

```bash
python -m pytest tests/ -v --cov=src/netshaper --cov-report=term
```

Root-only end-to-end namespace checks (requires network namespaces):

```bash
sudo env PYTHONPATH="$PWD/src:$PWD" python -m pytest tests/test_netns_integration.py -v
```

Code quality checks:

```bash
ruff check src/netshaper/
mypy src/netshaper/
bandit -r src/netshaper/ -ll
```

Pre-release checklist (before merging to `main`):
- [ ] All unit tests pass (`pytest tests/`)
- [ ] Coverage ≥ 80% (`coverage report`)
- [ ] Type checking passes (`mypy src/netshaper/`)
- [ ] Style and lint pass (`ruff check`)
- [ ] Security checks pass (`bandit`)
- [ ] Privileged tests pass on self-hosted runner (`sudo pytest tests/test_netns_integration.py`)

## Release Hygiene

Do not distribute a working tree ZIP. Build releases from a clean checkout with
`python -m build` or `git archive` so `.git`, virtual environments, packet
captures, logs, caches, reference artifacts, and state files are excluded.
Treat Git history and packet captures as sensitive material.

## Logs and Debugging

When running normally (not `--dry-run`), NetShaper writes to `/var/log/netshaper.log`.

After startup, the CLI prints a verified evidence block:
- Session ID, timestamp, interface
- Targets, state file path
- Monitor thread status, sniffer status, packet-capture files
- mitmproxy process ID and log path
- Any runtime errors detected

During the active session, NetShaper continuously monitors:
- Bandwidth monitor thread (updates TX/RX counters)
- Packet sniffer (running or stopped)
- mitmproxy process (running or crashed)
- Local redirect ports (reachable or unreachable)

If any health check fails, it is reported as an error and normal cleanup is triggered.

## Operational Notes

- Session state is stored under `/run/netshaper/` (root-owned, mode 0700) and cleaned up on exit
- Only one NetShaper instance may run at a time (enforced via `/run/netshaper/netshaper.lock`)
- `fake_server3` is an optional helper for captive-portal and DNS lab scenarios; it is not required for ARP spoofing or traffic shaping
- Use `--dry-run` extensively before running live sessions
- Monitor `/var/log/netshaper.log` during and after sessions
- Firewall rules are tagged with `netshaper:<session-id>:global` for easy identification

## Troubleshooting

See [USER_GUIDE.md](USER_GUIDE.md) for detailed troubleshooting steps, including:
- Device not spoofed
- DNS not redirecting
- Traffic shaping not applied
- mitmproxy not starting
- Stale session recovery
