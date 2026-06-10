# Security & Risk Documentation

## Known Risks and Mitigation

### 1. /cert Endpoint — Unauthenticated CA Certificate Access

**Risk Level:** Medium (Intentional for captive portal flow)

**Description:**
The `fake_server3` helper serves the mitmproxy root CA certificate over plain HTTP on port 80 at the `/cert` endpoint. This endpoint has **no authentication** — anyone with network access to the server can download the root CA.

**Why This Exists:**
In captive portal scenarios, the target device must be able to retrieve and trust the mitmproxy root CA without pre-configuration. Since the initial HTTP connection is also intercepted, the captive portal flow is:
1. Device connects to captive portal HTTP
2. Device is redirected to certificate install endpoint
3. Device downloads certificate in the clear
4. Device installs root CA and accepts HTTPS interception

**Risk Scenarios:**
- An attacker on the local network could intercept the CA and impersonate the testing infrastructure
- A malicious device could download the CA before the target does

**Mitigation:**
- **Network isolation:** Run NetShaper only on isolated lab networks with controlled device access
- **Time-limited sessions:** Use NetShaper for discrete testing windows, not continuous operation
- **Restrict to authorized CIDRs:** The `--allow-cidr` flag limits target scope; ensure all test networks are listed
- **Firewall boundaries:** Run on a separate VLAN or air-gapped network segment
- **Clear audit trail:** Monitor `/var/log/netshaper.log` for unexpected access

**Documentation:**
If you are concerned about the CA exposure, consider alternative flows:
- Pre-install the mitmproxy CA on test devices before running NetShaper
- Use a captive portal flow that does not require dynamic cert serving
- Restrict `/cert` endpoint to a whitelist of known MAC addresses (requires customization)

### 2. Privileged Execution — Root Privilege Required

**Risk Level:** High

**Description:**
NetShaper requires root to:
- Modify iptables rules (firewall, NAT, mangle)
- Run ARP/NDP spoofing
- Bind to low-numbered ports (UDP 53 for DNS, TCP 80 for HTTP)
- Launch transparent proxy (mitmproxy)

**Mitigation:**
- Use `--dry-run` to preview commands before execution
- Review all firewall rules that will be added: `sudo iptables -L -n`
- Monitor system state changes during a session
- Ensure SystemChecker passes (`[root required]` + Linux only)
- Automatic cleanup and recovery system cleans up orphaned rules

### 3. System State Modifications — Firewall, Forwarding, Traffic Control

**Risk Level:** High

**Description:**
NetShaper modifies:
- `net.ipv4.ip_forward` and `net.ipv6.conf.all.forwarding`
- `net.ipv4.conf.<iface>.route_localnet`
- iptables rules (FORWARD, INPUT, PREROUTING, POSTROUTING, mangle, nat)
- Traffic control (tc) root qdisc on the interface

**Mitigation:**
- Snapshots are taken at startup and restored on shutdown
- State is persisted to `/run/netshaper/<session-id>/state.json` for recovery
- Stale session detection: if a process crashes, the next `NetShaper()` call will clean up rules
- Always run cleanup on exit (Ctrl+C or normal termination)
- Logs are written to `/var/log/netshaper.log` with timestamps

### 4. Subprocess Execution — iptables, tc, sysctl, mitmproxy

**Risk Level:** High (input validation required)

**Description:**
NetShaper runs system binaries:
- `iptables` / `ip6tables` (rule management)
- `tc` (traffic shaping)
- `sysctl` (kernel parameter changes)
- `mitmproxy` / `mitmweb` (packet interception)

All commands are constructed from validated inputs (IP addresses, CIDR blocks, interface names).

**Input Validation:**
- Target IPs are validated against `ipaddress.ip_address()` and checked against the authorized CIDR allowlist
- Interface names are checked against `psutil.net_if_addrs()`
- Ports are checked as integers in valid ranges
- All IP/CIDR objects are `ipaddress` module objects, preventing injection

**Mitigation:**
- Use `--dry-run` to inspect all commands before execution
- Review `/var/log/netshaper.log` for executed subprocess calls
- Keep the system patched (`iptables`, kernel, Python)

## Recommended Audit Procedures

Before running in a new environment:

1. **Verify authorized CIDRs:**
   ```bash
   sudo python -m netshaper -i eth0 --allow-cidr 10.0.0.0/8 --targets 10.0.1.100 --dry-run
   ```

2. **Preview firewall rules:**
   ```bash
   sudo iptables -L -n
   sudo ip6tables -L -n
   ```

3. **Check system parameters:**
   ```bash
   sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
   ```

4. **Monitor during execution:**
   ```bash
   # In another terminal
   tail -f /var/log/netshaper.log
   sudo iptables -L -n -v
   ```

5. **After shutdown, verify cleanup:**
   ```bash
   sudo iptables -L FORWARD -n | grep netshaper
   # Should be empty
   ```

## Responsible Disclosure

If you discover a security vulnerability in NetShaper:

1. Do **not** open a public GitHub issue
2. Email security details to the maintainer (see CONTRIBUTING.md)
3. Include a reproduction case and proposed fix if possible
4. Allow 30 days for response and patch before public disclosure

## Further Reading

- [USER_GUIDE.md](USER_GUIDE.md) — Workflow and operational details
- [tests/](tests/) — Automated test suite including regression tests
- `/var/log/netshaper.log` — Runtime execution log
