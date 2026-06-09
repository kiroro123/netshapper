# NetShaper User Guide

NetShaper is for authorized lab testing and controlled diagnostics on networks
you own or have explicit permission to test.

## Run From Source

This repo uses a `src/` Python layout. When running directly from the checkout,
use `PYTHONPATH` so Python can find the package:

```bash
cd /home/kyrol/Downloads/netshaper
sudo env PYTHONPATH="$PWD/src" python -m netshaper -i wlp0s20f3
```

If you already created the `snetshaper` alias:

```bash
snetshaper -i wlp0s20f3
```

Suggested alias:

```bash
echo "alias snetshaper='sudo env PYTHONPATH=/home/kyrol/Downloads/netshaper/src python -m netshaper'" >> ~/.bashrc
source ~/.bashrc
```

Why plain `sudo python -m netshaper` may fail:

```text
No module named netshaper
```

Root's Python does not automatically include this repo's `src/` directory.
Using `PYTHONPATH` fixes that without installing into the system Python.

## Fake Server

The fake server is the DNS and HTTP helper used for captive-portal style lab
flows. Run it in a separate terminal before starting NetShaper.

From source:

```bash
cd /home/kyrol/Downloads/netshaper
sudo env PYTHONPATH="$PWD/src" python -m netshaper.fake_server3
```

Or with an alias:

```bash
echo "alias sfakeserver='sudo env PYTHONPATH=/home/kyrol/Downloads/netshaper/src python -m netshaper.fake_server3'" >> ~/.bashrc
source ~/.bashrc
sfakeserver
```

The root source-file entrypoint also works:

```bash
cd /home/kyrol/Downloads/netshaper
sudo python3 fake_server3.py
```

The fake server binds low ports such as DNS `53` and HTTP `80`, so it normally
needs `sudo`.

## Recommended Two-Terminal Workflow

Terminal 1:

```bash
sfakeserver --smart-spoof-all --host-ip 192.168.24.140 --verbose-dns
```

Terminal 2:

```bash
snetshaper -i wlp0s20f3
```

In NetShaper, choose features:

```text
1 2 3
```

For ARP spoofing, DNS handling, and captive portal.

With bandwidth throttling too:

```text
1 2 3 4
```

## NetShaper Feature Menu

```text
[1] ARP spoofing (core MITM)
[2] DNS spoofing
[3] Captive portal (index.html for HTTP)
[4] Bandwidth throttle
[5] Packet sniffer
[6] mitmproxy HTTPS inspection
```

Common choices:

```text
1 2 3      ARP + DNS + captive portal
1 2 3 4    ARP + DNS + captive portal + throttle
1 5        ARP + packet sniffer
1 6        ARP + mitmproxy HTTPS inspection
```

## Fake Server Modes

Show all fake-server options:

```bash
sfakeserver --help
```

Default mode:

```bash
sfakeserver
```

Runs the HTTP portal and DNS helper. DNS queries not selected for spoofing are
forwarded upstream.

Spoof specific domains:

```bash
sfakeserver --spoof example.com,test.local --host-ip 192.168.24.140
```

Spoof every queried domain:

```bash
sfakeserver --spoof-all --host-ip 192.168.24.140
```

Smart broad spoofing:

```bash
sfakeserver --smart-spoof-all --host-ip 192.168.24.140 --verbose-dns
```

`--smart-spoof-all` spoofs broadly but forwards safe categories such as
connectivity checks, DNS providers, Android/Google core services, and sensitive
finance/payment domains.

Always forward specific domains:

```bash
sfakeserver --smart-spoof-all --forward google.com,apple.com
```

Block specific domains with NXDOMAIN:

```bash
sfakeserver --block ads.example.com
```

Use a different upstream DNS server:

```bash
sfakeserver --upstream 1.1.1.1
```

Forward only selected safe categories in smart mode:

```bash
sfakeserver --smart-spoof-all --forward-category connectivity --forward-category android
```

## Discovery Behavior

Discovery now uses three sources:

- Linux neighbor cache (`ip neigh`)
- `/proc/net/arp`
- Live ARP refresh plus passive ARP sniffing

Expected discovery output may include:

```text
Cached neighbors: 35 devices
ARP sweep: pass 1/2 batch 1/4 | 35 devices
Passive sniff: 15s | 35 devices
```

The passive sniff phase listens for ARP traffic for about 15 seconds. This is
normal and helps catch quiet devices.

To inspect what Linux already knows:

```bash
sudo ip neigh show dev wlp0s20f3
cat /proc/net/arp
```

## Dry Run

Dry-run avoids system changes and active discovery. Provide targets manually:

```bash
snetshaper -i wlp0s20f3 --targets 192.168.24.134,192.168.24.176 --dry-run
```

## Port Conflicts

If the fake server cannot bind DNS or HTTP ports:

```bash
sudo ss -ltnup | grep -E ':53|:80|:8088'
```

Common conflicts:

- `systemd-resolved` or another DNS service on port `53`
- Apache/Nginx or another web server on port `80`
- mitmproxy on port `8088`

## Testing

Run the full regression suite:

```bash
python -m unittest discover -s tests -v
```

Run focused tests:

```bash
python -m unittest tests.test_discovery -v
python -m unittest tests.test_fake_server -v
python -m unittest tests.test_cli -v
```

## Cleanup

Stop NetShaper with `Ctrl+C`. It should restore forwarding, firewall rules,
traffic shaping state, and remove its session state file.

If startup reports stale recovery state, let NetShaper recover it before
starting a new active session.
