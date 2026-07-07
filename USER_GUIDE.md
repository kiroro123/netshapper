# NetShaper User Guide

NetShaper is a modular offensive network toolkit for authorized labs and
client networks you own or have explicit permission to test.

## Run From Source

This repo uses a `src/` Python layout. Set `PYTHONPATH` so Python finds the
package without a system install:

```bash
sudo env PYTHONPATH="$PWD/src" python -m netshaper -i <interface> \
  --allow-cidr <authorized-cidr>
```

Suggested alias (add to `~/.bashrc` or `~/.zshrc`):

```bash
alias snetshaper='sudo env PYTHONPATH="$(git -C ~/Downloads/netshaper rev-parse --show-toplevel)/src" python -m netshaper'
```

Or with a fixed path:

```bash
alias snetshaper='sudo env PYTHONPATH=/path/to/netshaper/src python -m netshaper'
```

Why plain `sudo python -m netshaper` fails:

```text
No module named netshaper
```

Root's `$PYTHONPATH` is stripped by default. The `env PYTHONPATH=...` form
passes it through explicitly.

## Offensive DNS + Portal Engine

`netshaper-portal` handles DNS queries and serves the captive-portal HTTP page.
Run it in a **separate terminal** before starting NetShaper when using modules
2 or 3.

```bash
sudo env PYTHONPATH="$PWD/src" python -m netshaper.portal
```

Suggested alias:

```bash
alias sportal='sudo env PYTHONPATH=/path/to/netshaper/src python -m netshaper.portal'
```

The portal engine binds ports `53` (DNS) and `80` (HTTP), so it requires `sudo`.

## Recommended Two-Terminal Workflow

**Terminal 1** — portal engine:

```bash
sportal --smart-spoof-all --host-ip <your-ip> \
  --allow-cidr <authorized-cidr> --verbose-dns
```

**Terminal 2** — NetShaper:

```bash
snetshaper -i <interface> --allow-cidr <authorized-cidr>
```

Then select modules `1 2 3` (or `1,2,3`) for ARP + DNS + captive portal.

## Offensive Network Module Menu

```text
[1] ARP spoofing (core MITM)
[2] DNS spoofing (lab redirect)
[3] Captive portal (HTTP index.html)
[4] Bandwidth throttle / netem impairment
[5] Packet sniffer
[6] mitmproxy HTTPS inspection
[7] ARP amplification (requires [1], default 256 phantom IPs)
[8] DNSSEC suppression (requires [2], default fail-closed)
[9] HSTS/IDN first-visit offensive demo (requires [3])
```

Enter numbers separated by spaces or commas:

```text
1 2 3        ARP + DNS + captive portal
1,2,3,4      same + bandwidth throttle
1 5          ARP + packet capture
1 6          ARP + mitmproxy HTTPS inspection
1 7          ARP + ARP amplification
2 8          DNS spoofing + DNSSEC suppression
3 9          captive portal + HSTS/IDN offensive demo
```

Offensive network modules prompt to enable their required base module if it was
not selected. If you decline the base module, the dependent module is
disabled before the final session summary.

## Bandwidth Throttle Presets

When module `4` is selected you'll be shown:

```text
[1] 1 Mbps   [2] 2 Mbps   [3] 3 Mbps
[4] 5 Mbps   [5] 10 Mbps  [6] Custom
```

Custom accepts any value from 0.1 to 1000 Mbps.

You can also set throttle non-interactively:

```bash
snetshaper -i <interface> --allow-cidr 192.168.1.0/24 --targets 192.168.1.5 --limit 2.5
```

Module `4` also supports controlled `tc netem` impairment:

```bash
snetshaper -i eth0 \
  --allow-cidr 192.168.1.0/24 \
  --targets 192.168.1.5 \
  --limit 5 \
  --latency-ms 120 \
  --jitter-ms 20 \
  --loss-percent 1.5
```

Available impairment flags are `--latency-ms`, `--jitter-ms`,
`--loss-percent`, `--corruption-percent`, `--duplicate-percent`, and
`--reorder-percent`. Jitter and reordering require a non-zero latency.
All resources are journaled and removed during normal or stale-session cleanup.

## ARP/NDP Cache-Race Training

Module `1` supports bounded packet timing controls:

```bash
snetshaper -i eth0 \
  --allow-cidr 192.168.1.0/24 \
  --targets 192.168.1.5 \
  --arp-burst 3 \
  --arp-interval 0.5
```

`--arp-burst` accepts 1-5 packets per cycle. `--arp-interval` accepts
0.25-10 seconds. The same settings apply to NDP when the selected device has
IPv6 information.

## Fake Server Modes

| Flag | Behaviour |
|------|-----------|
| *(none)* | Serve captive portal; forward all DNS upstream |
| `--spoof example.com,test.local` | Spoof only listed domains |
| `--spoof-all` | Spoof every queried domain |
| `--smart-spoof-all` | Spoof broadly; auto-forward connectivity checks, CDNs, payment domains |
| `--forward google.com` | Always forward these domains even in spoof-all mode |
| `--block ads.example.com` | Return NXDOMAIN for these domains |
| `--upstream 1.1.1.1` | Use a different upstream DNS resolver |
| `--forward-category connectivity` | Forward a built-in safe category in smart mode |
| `--verbose-dns` | Log every DNS query and response |
| `--host-ip <ip>` | Override the IP returned in spoofed A records |
| `--dns-workers 16` | Set maximum concurrent DNS forwarding workers |
| `--allow-cidr 192.0.2.0/24` | Allow DNS clients from this CIDR; repeat as needed |
| `--serve-ca-cert` | Explicitly enable serving the mitmproxy CA at `/cert` |
| `--dnssec-mode <mode>` | Select `fail-closed`, `fail-open`, `nxdomain`, or `timeout` behavior |
| `--hsts-idn-demo` | Enable the static HSTS/IDN offensive demo at `/training/web-security` |
| `--idn-demo-domain арр.test` | Add a Unicode/Punycode example using a reserved demo domain |

DNS defaults to loopback-only clients unless at least one `--allow-cidr` is
provided. DNSSEC `fail-open` models a non-validating intermediary; the other
modes return SERVFAIL, NXDOMAIN, or no response for DNSSEC-aware queries.
None of these modes defeats validation on the endpoint.

The HSTS/IDN offensive demo contains no sign-in form and captures no credentials.
It explains that preloaded or previously learned HSTS upgrades the request
before an HTTP intermediary can act. IDN examples must end in `.test`,
`.example`, `.invalid`, or `.localhost`.

## Non-Interactive Mode

Skip discovery and set all options from the command line:

```bash
snetshaper -i eth0 \
  --allow-cidr 192.168.1.0/24 \
  --targets 192.168.1.5,192.168.1.6 \
  --modules 1,4,5 \
  --limit 1.5
```

`--targets` accepts space-separated or comma-separated IPs. `--modules`
accepts space-separated or comma-separated offensive network module numbers and
skips the interactive module menu. `--limit` and the netem flags configure
module 4 after it is selected. `--allow-cidr` is required and should match the
written authorization scope for the test.

## Discovery Behaviour

Discovery uses three sources in parallel:

1. Linux neighbor cache (`ip neigh` + `/proc/net/arp`) — instant
2. Live ARP sweep — two passes across the subnet in 64-host batches
3. Passive ARP sniff — 15 seconds, catches quiet devices

Expected output:

```text
Cached neighbors: 12 devices
ARP sweep: pass 1/2 batch 1/2 | 12 devices
Passive sniff: 15s | 14 devices
```

To see what Linux already knows before running NetShaper:

```bash
ip neigh show dev <interface>
cat /proc/net/arp
```

## Dry Run

Prints every command that would be run without applying any system change.
Discovery is skipped; supply targets manually:

```bash
snetshaper -i eth0 --allow-cidr 192.168.1.0/24 --targets 192.168.1.5 --dry-run
```

No `sudo` requirement in dry-run mode, but target scope is still validated.

## Logs

Normal runs write to `/var/log/netshaper.log`. Set `NETSHAPER_LOG_FILE` to
override the path and `NETSHAPER_LOG_LEVEL` to change verbosity. `--dry-run`
logs to the console
only.

## Runtime Evidence

NetShaper does not treat startup as successful just because setup commands
returned. Before it prints the active monitoring prompt, it verifies the
runtime checks and shows an evidence block like:

```text
[+] Startup verified. Evidence:
    Session ID: NS-ABC123
    Started at: 2026-06-10 12:34:56 +0800
    Interface: eth0
    Targets: 192.168.1.5
    State file: /run/netshaper/NS-ABC123/state.json
    Log file: /var/log/netshaper.log
    Monitor thread: running
    Packet sniffer: running
    PCAP files: will be written during shutdown
    Runtime errors: none
```

During the active session it keeps checking:

- The bandwidth monitor thread
- Requested packet sniffer liveness
- Auto-launched mitmproxy process state
- Local TCP/UDP redirect ports used by selected DNS, HTTP, or mitmproxy modes

If a check fails, NetShaper reports `Runtime health check failed: ...`, runs
normal cleanup, and exits with an error instead of continuing to show a healthy
status. Auto-launched mitmproxy stdout/stderr is saved under
`/run/netshaper/<session-id>/mitmproxy.log`.

## Wireless Plugins

Wireless plugins require an explicit JSON scope. Preview the complete setup
before enabling any active Wi-Fi action:

```bash
sudo env PYTHONPATH="$PWD/src" python -m netshaper \
  -i wlan0 \
  --allow-cidr 192.0.2.0/24 \
  --plugin wifi-recon \
  --plugin-config wireless-lab.json \
  --dry-run
```

`wifi-recon` changes the selected interface to monitor mode for the session and
restores managed mode during shutdown. Authorized frames are saved under
`/run/netshaper/captures/` by default with mode `0600`. Channel hopping defaults
to channels 1, 6, and 11; configure only channels permitted for the adapter and
local regulatory domain.

Active probe requests require `allow_active_scan` and an ESSID allowlist.
Unicast disconnect tests additionally require `allow_deauth_test`, exact BSSID
and client MAC allowlists, and configured `deauth_tests`. Marked lab-beacon
tests require `allow_beacon_test` and `NETSHAPER-LAB-` ESSIDs. Each action is
capped at five frames and all actions share `max_tx_frames` (maximum 100).

Install BLE support with:

```bash
python -m pip install -e ".[ble]"
```

`ble-recon` requests passive scanning. Optional service enumeration is
read-only and uses `pair=False`. `audit_unpaired_access` reports services
available without pairing; it neither bypasses pairing nor writes to GATT
characteristics. BlueZ monitor patterns are derived from service UUIDs.
Address-only scopes must configure a narrow, non-empty advertisement
`passive_patterns` signature. See the full JSON example in
[README.md](README.md). Linux passive mode requires BlueZ 5.56 or newer with
experimental advertisement monitoring enabled and kernel 5.10 or newer.

## Port Conflicts

If the portal engine cannot bind its ports:

```bash
sudo ss -ltnup | grep -E ':53|:80|:8088'
```

Common conflicts:

| Port | Usual culprit | Quick fix |
|------|---------------|-----------|
| 53   | `systemd-resolved` | `sudo systemctl stop systemd-resolved` |
| 80   | Apache / Nginx | `sudo systemctl stop apache2` |
| 8088 | Previous mitmproxy | `pkill mitmweb` |

## Cleanup

Stop NetShaper with `Ctrl+C`. It will:

- Send corrective ARP/NDP packets to restore real MAC tables
- Remove all per-target iptables/ip6tables chains
- Delete the session forwarding chain and each recorded target-scoped
  forwarding/IPv4 MASQUERADE rule
- Restore original `ip_forward` / `route_localnet` sysctl values
- Remove the session state file from `/run/netshaper/`

If a previous run left stale state (e.g. after a crash), NetShaper detects and
cleans it automatically at the next startup.

## Testing

```bash
python -m unittest discover -s tests -v
```

Run a specific module:

```bash
python -m unittest tests.test_cli -v
python -m unittest tests.test_firewall -v
```

Run the root-only end-to-end namespace checks when validating a real operating
environment:

```bash
sudo env PYTHONPATH="$PWD/src:$PWD" python -m unittest tests.test_netns_integration -v
```

## Release Hygiene

Do not share a working tree ZIP. Build from a clean checkout with
`python -m build` or `git archive`, and exclude `.git`, virtual environments,
packet captures, logs, caches, reference artifacts, and state files. Treat
packet captures, runtime logs, and Git history as sensitive material.
