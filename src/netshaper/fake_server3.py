#!/usr/bin/env python3
"""
Combined Captive Portal (HTTP) + Fake DNS Server
NetShaper packaged fake server
─────────────────────────────────────────────────
• Fail-fast IP detection with psutil fallback (no silent loopback fallback)
• UDP 53 : Dual-stack DNS (AF_INET6 + IPV6_V6ONLY=0)
           Policy-based spoof / forward / block decisions
           Optional --spoof-all and --smart-spoof-all lab modes
           Pointer-compression guard, single-question validation,
           bounds-checked QTYPE extraction
• TCP 80 : Dual-stack threaded HTTP server
           DualStackHTTPServer via address_family + super().server_bind()
• Privilege drop after socket binding (Phase 1 / Phase 2 architecture)
• Optional CA cert serving over plain HTTP when --serve-ca-cert is set
"""

import argparse
import errno
import hmac
import html
import os
import pwd
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import IPv6Address, ip_address, ip_network
from socketserver import ThreadingMixIn

import psutil

try:
    from netshaper.utils import bold, cyan, green, print_flush, red, yellow
except ModuleNotFoundError:  # Allows direct execution from src/netshaper/.
    from utils import bold, cyan, green, print_flush, red, yellow


# ── Auto-detect own IP (fail-fast) ─────────────────────────────────────────
def _usable_ipv4(address: str) -> bool:
    try:
        parsed = ip_address(address)
    except ValueError:
        return False
    return parsed.version == 4 and not parsed.is_loopback and not parsed.is_unspecified


def get_own_ip() -> str:
    """Return IPv4 address of the primary interface or exit with a clear error."""
    errors = []

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if _usable_ipv4(ip):
                return ip
            errors.append(f"route probe returned unusable address {ip}")
    except OSError as e:
        errors.append(f"route probe failed: {e}")

    try:
        stats = psutil.net_if_stats()
        for iface, addrs in psutil.net_if_addrs().items():
            iface_stats = stats.get(iface)
            if iface_stats is not None and not iface_stats.isup:
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET and _usable_ipv4(addr.address):
                    return addr.address
        errors.append("psutil found no active non-loopback IPv4 address")
    except Exception as e:
        errors.append(f"psutil fallback failed: {e}")

    detail = "; ".join(errors)
    sys.exit(
        f"{red('[Engine]')} Fatal: Automatic network IP detection failed: {detail}\n"
        f"Use --host-ip with the IPv4 address that targets should resolve to."
    )


YOUR_IP = ""
INDEX_FILE_PATH = "/var/www/html/index.html"
CA_CERT_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.cer")
CA_CERT_CONTENT: bytes | None = None
DNS_UPSTREAM = os.environ.get("DNS_UPSTREAM", "8.8.8.8")
DNS_SPOOF_ALL = os.environ.get("DNS_SPOOF_ALL", "").lower() in ("1", "true", "yes")
DNS_SMART_SPOOF_ALL = os.environ.get("DNS_SMART_SPOOF_ALL", "").lower() in (
    "1",
    "true",
    "yes",
)
DNS_VERBOSE = os.environ.get("DNS_VERBOSE", "").lower() in ("1", "true", "yes")
DNS_MAX_WORKERS = int(os.environ.get("DNS_MAX_WORKERS", "16"))
SERVE_CA_CERT = os.environ.get("SERVE_CA_CERT", "").lower() in ("1", "true", "yes")
HEALTH_TOKEN = os.environ.get("NETSHAPER_HEALTH_TOKEN", "")
DNS_SUPPRESS_DNSSEC = os.environ.get("DNS_SUPPRESS_DNSSEC", "").lower() in (
    "1",
    "true",
    "yes",
)
DNSSEC_MODE = os.environ.get("DNSSEC_MODE", "off").strip().lower()
if DNSSEC_MODE not in {"off", "fail-closed", "fail-open", "nxdomain", "timeout"}:
    DNSSEC_MODE = "off"
DNS_SUPPRESS_DNSSEC = DNS_SUPPRESS_DNSSEC or DNSSEC_MODE != "off"
DNS_ALLOWED_NETWORKS = (
    ip_network("127.0.0.0/8"),
    ip_network("::1/128"),
)
WEB_SECURITY_DEMO = os.environ.get("WEB_SECURITY_DEMO", "").lower() in (
    "1",
    "true",
    "yes",
)
IDN_DEMO_DOMAINS: list[tuple[str, str]] = []

# HTTP port used when rendering redirects. Set from CLI in `main()`.
HTTP_PORT = 80

RESERVED_TRAINING_SUFFIXES = (
    ".test",
    ".example",
    ".invalid",
    ".localhost",
)

DNSSEC_QTYPES = {
    43,  # DS
    46,  # RRSIG
    47,  # NSEC
    48,  # DNSKEY
    50,  # NSEC3
    51,  # NSEC3PARAM
}


def parse_domain_csv(value: str) -> set[str]:
    return {d.strip().rstrip(".").lower() for d in value.split(",") if d.strip()}


DNS_SPOOF_DOMAINS = parse_domain_csv(os.environ.get("DNS_SPOOF_DOMAINS", ""))
DNS_FORWARD_DOMAINS = parse_domain_csv(os.environ.get("DNS_FORWARD_DOMAINS", ""))
DNS_BLOCK_DOMAINS = parse_domain_csv(os.environ.get("DNS_BLOCK_DOMAINS", ""))


def normalize_idn_demo_domain(value: str) -> tuple[str, str]:
    """Return (Unicode, ASCII/IDNA) for a reserved training-only domain."""
    unicode_domain = value.strip().rstrip(".").lower()
    if not unicode_domain or "/" in unicode_domain or "@" in unicode_domain:
        raise ValueError(f"invalid IDN demo domain: {value!r}")
    try:
        ascii_domain = unicode_domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid IDN demo domain: {value!r}") from exc
    if not ascii_domain.endswith(RESERVED_TRAINING_SUFFIXES):
        raise ValueError(
            "IDN demo domains must end in .test, .example, .invalid, "
            "or .localhost"
        )
    return unicode_domain, ascii_domain


def render_web_security_demo(domains: list[tuple[str, str]]) -> bytes:
    """Render a static, non-credential-capturing HSTS and IDN training page."""
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(unicode_domain)}</td>"
        f"<td><code>{html.escape(ascii_domain)}</code></td>"
        "</tr>"
        for unicode_domain, ascii_domain in domains
    )
    if not rows:
        rows = "<tr><td>арр.test</td><td><code>xn--80a6aa.test</code></td></tr>"
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>NetShaper Web Security Lab</title>
  <style>
    body {{ max-width: 54rem; margin: 3rem auto; font: 16px/1.5 sans-serif; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #bbb; padding: .55rem; text-align: left; }}
    code {{ background: #eee; padding: .1rem .25rem; }}
  </style>
</head>
<body>
  <h1>HSTS and IDN training lab</h1>
  <p>This page intentionally contains no sign-in form and stores no credentials.</p>
  <h2>HSTS outcomes</h2>
  <ul>
    <li><strong>Preloaded or previously learned HSTS:</strong> the browser upgrades
        to HTTPS before an HTTP intermediary can rewrite the request.</li>
    <li><strong>First visit without HSTS:</strong> a lab intermediary can demonstrate
        an HTTP downgrade before the browser learns the policy.</li>
    <li><strong>HSTS sent over HTTP:</strong> ignored by conforming browsers. This
        response includes such a header so the behavior can be observed.</li>
  </ul>
  <h2>Reserved-domain IDN examples</h2>
  <table>
    <thead><tr><th>Unicode label</th><th>ASCII/Punycode form</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <p>Browser display policy varies; security-sensitive UI should compare the
     canonical ASCII form and highlight mixed scripts.</p>
</body>
</html>
"""
    return document.encode("utf-8")


def portal_base_url() -> str:
    """Return the canonical portal base URL including port when required."""
    if HTTP_PORT == 80:
        return f"http://{YOUR_IP}"
    return f"http://{YOUR_IP}:{HTTP_PORT}"


SAFE_DOMAIN_CATEGORIES = {
    "connectivity": {
        "connectivitycheck.gstatic.com",
        "clients3.google.com",
        "www.google.com",
        "www.google.cn",
        "captive.apple.com",
        "www.apple.com",
        "www.msftconnecttest.com",
        "msftconnecttest.com",
        "www.msftncsi.com",
        "detectportal.firefox.com",
    },
    "dns": {
        "dns.google",
        "cloudflare-dns.com",
        "one.one.one.one",
        "dns.quad9.net",
        "use-application-dns.net",
    },
    "android": {
        "android.googleapis.com",
        "android.apis.google.com",
        "play.googleapis.com",
        "clients2.google.com",
        "clientservices.googleapis.com",
        "update.googleapis.com",
        "optimizationguide-pa.googleapis.com",
        "discover-pa.googleapis.com",
        "prod-lt-playstoregatewayadapter-pa.googleapis.com",
    },
    "sensitive": {
        "maybank2u.com.my",
        "cimbclicks.com.my",
        "pbebank.com",
        "mybsn.com.my",
        "paypal.com",
        "stripe.com",
        "visa.com",
        "mastercard.com",
    },
}
DEFAULT_SMART_FORWARD_CATEGORIES = {"connectivity", "dns", "android", "sensitive"}
DNS_FORWARD_CATEGORIES = {
    c.strip().lower()
    for c in os.environ.get("DNS_FORWARD_CATEGORIES", "").split(",")
    if c.strip()
}

CAPTIVE_CHECK_PATHS = [
    "/generate_204",
    "/gen_204",
    "/hotspot-detect.html",
    "/success.txt",
    "/connecttest.txt",
    "/redirect",
]


# ── Certificate cache ──────────────────────────────────────────────────────
def load_ca_cert() -> bytes | None:
    """
    Cache the mitmproxy CA certificate while the process still has privileges.

    The HTTP handler may run after drop_privileges("nobody"), when the original
    mitmproxy profile directory is no longer readable.
    """
    global CA_CERT_CONTENT
    try:
        with open(CA_CERT_PATH, "rb") as f:
            CA_CERT_CONTENT = f.read()
    except FileNotFoundError:
        CA_CERT_CONTENT = None
    except OSError as e:
        CA_CERT_CONTENT = None
        print_flush(f"{yellow('[Portal]')} Could not preload CA cert: {e}")
    return CA_CERT_CONTENT


def ca_cert_content() -> bytes | None:
    """Return cached CA bytes, loading from disk if still accessible."""
    if CA_CERT_CONTENT is not None:
        return CA_CERT_CONTENT
    return load_ca_cert()


# ── Privilege drop (Phase 2 — call after sockets are bound) ────────────────
def drop_privileges(user: str = "nobody"):
    """
    Drop from root to an unprivileged user after raw sockets are bound.
    Call order: setgroups → setgid → setuid (GID must change before UID).
    """
    if os.geteuid() != 0:
        return  # Already unprivileged — nothing to do

    try:
        pw = pwd.getpwnam(user)
        os.setgroups([])  # Drop supplementary group memberships
        os.setgid(pw.pw_gid)  # Set GID first (can't after setuid)
        os.setuid(pw.pw_uid)  # Drop to unprivileged UID
        print_flush(
            f"{green('[Engine]')} Privileges dropped to '{user}' "
            f"(uid={pw.pw_uid}, gid={pw.pw_gid})"
        )
    except KeyError:
        sys.exit(f"{red('[Engine]')} Fatal: Drop target user '{user}' does not exist.")
    except PermissionError as e:
        sys.exit(f"{red('[Engine]')} Fatal: Failed to drop privileges: {e}")


# ── DNS helpers ────────────────────────────────────────────────────────────
def parse_dns_question(data: bytes):
    """Return (domain, qtype, question_end) for the first DNS question."""
    if len(data) < 12:
        return None, None, None

    labels = []
    offset = 12
    jumps = 0
    wire_end = None  # byte position in wire format where QTYPE starts

    while offset < len(data):
        length = data[offset]
        if length == 0:
            if wire_end is None:
                wire_end = offset + 1
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                return None, None, None
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if wire_end is None:
                wire_end = offset + 2  # QTYPE follows the 2-byte pointer in wire
            offset = pointer
            jumps += 1
            if jumps > 8:
                return None, None, None
            continue
        offset += 1
        if offset + length > len(data):
            return None, None, None
        try:
            labels.append(data[offset : offset + length].decode("ascii").lower())
        except UnicodeDecodeError:
            return None, None, None
        offset += length

    if wire_end is None:
        return None, None, None
    question_end = wire_end + 4
    if question_end > len(data):
        return None, None, None
    qtype = (data[wire_end] << 8) | data[wire_end + 1]
    return ".".join(labels).rstrip("."), qtype, question_end


def dns_qdcount(data: bytes) -> int | None:
    if len(data) < 12:
        return None
    return (data[4] << 8) | data[5]


def _skip_dns_name(data: bytes, offset: int) -> int | None:
    """Return the next wire offset after a DNS name without following pointers."""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2 if offset + 1 < len(data) else None
        if length & 0xC0:
            return None
        offset += 1 + length
    return None


def _skip_dns_rr(data: bytes, offset: int) -> tuple[int, int, int] | None:
    """Return (next_offset, rr_type, ttl_offset) for one resource record."""
    name_end = _skip_dns_name(data, offset)
    if name_end is None or name_end + 10 > len(data):
        return None
    rr_type = int.from_bytes(data[name_end : name_end + 2], "big")
    ttl_offset = name_end + 4
    rdlength = int.from_bytes(data[name_end + 8 : name_end + 10], "big")
    next_offset = name_end + 10 + rdlength
    if next_offset > len(data):
        return None
    return next_offset, rr_type, ttl_offset


def _find_opt_ttl_offset(data: bytes) -> int | None:
    """Locate the EDNS OPT TTL field, whose low 16 bits contain the DO flag."""
    if len(data) < 12:
        return None
    qdcount = int.from_bytes(data[4:6], "big")
    ancount = int.from_bytes(data[6:8], "big")
    nscount = int.from_bytes(data[8:10], "big")
    arcount = int.from_bytes(data[10:12], "big")
    offset = 12

    for _ in range(qdcount):
        name_end = _skip_dns_name(data, offset)
        if name_end is None or name_end + 4 > len(data):
            return None
        offset = name_end + 4

    for _ in range(ancount + nscount):
        record = _skip_dns_rr(data, offset)
        if record is None:
            return None
        offset = record[0]

    for _ in range(arcount):
        record = _skip_dns_rr(data, offset)
        if record is None:
            return None
        next_offset, rr_type, ttl_offset = record
        if rr_type == 41:  # OPT
            return ttl_offset
        offset = next_offset
    return None


def suppress_dnssec_query(data: bytes) -> tuple[bytes, bool]:
    """
    Model a non-validating intermediary by clearing CD and EDNS DO.

    A validating endpoint should treat the resulting unsigned answer as a
    validation failure; this option does not defeat endpoint validation.
    """
    if len(data) < 12:
        return data, False
    altered = bytearray(data)
    changed = False

    flags = int.from_bytes(altered[2:4], "big")
    new_flags = flags & ~0x0010  # CD (Checking Disabled)
    if new_flags != flags:
        altered[2:4] = new_flags.to_bytes(2, "big")
        changed = True

    ttl_offset = _find_opt_ttl_offset(data)
    if ttl_offset is not None and ttl_offset + 4 <= len(altered):
        if altered[ttl_offset + 2] & 0x80:  # EDNS DO bit
            altered[ttl_offset + 2] &= 0x7F
            changed = True

    return bytes(altered), changed


def suppress_dnssec_response(data: bytes) -> bytes:
    """Clear the AD bit on an upstream answer in DNSSEC suppression mode."""
    if len(data) < 4:
        return data
    altered = bytearray(data)
    flags = int.from_bytes(altered[2:4], "big") & ~0x0020
    altered[2:4] = flags.to_bytes(2, "big")
    return bytes(altered)


def dns_client_authorized(raw_address: str) -> bool:
    """Return whether a DNS client belongs to the explicit source allowlist."""
    try:
        parsed = ip_address(raw_address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(parsed, IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return any(
        parsed.version == network.version and parsed in network
        for network in DNS_ALLOWED_NETWORKS
    )


def _effective_dnssec_mode() -> str:
    if DNSSEC_MODE != "off":
        return DNSSEC_MODE
    return "fail-open" if DNS_SUPPRESS_DNSSEC else "off"


def _query_requests_dnssec(data: bytes, qtype: int) -> bool:
    if qtype in DNSSEC_QTYPES:
        return True
    ttl_offset = _find_opt_ttl_offset(data)
    return bool(
        ttl_offset is not None
        and ttl_offset + 4 <= len(data)
        and data[ttl_offset + 2] & 0x80
    )


def domain_matches(domain: str, patterns: set[str]) -> bool:
    if not domain:
        return False
    return any(
        domain == pattern or domain.endswith(f".{pattern}") for pattern in patterns
    )


def category_for_domain(domain: str, categories: set[str]) -> str | None:
    for category in sorted(categories):
        patterns = SAFE_DOMAIN_CATEGORIES.get(category, set())
        if domain_matches(domain, patterns):
            return category
    return None


def active_smart_categories() -> set[str]:
    if DNS_FORWARD_CATEGORIES:
        return DNS_FORWARD_CATEGORIES
    return DEFAULT_SMART_FORWARD_CATEGORIES


def decide_dns_policy(domain: str, qtype: int) -> tuple[str, str]:
    """
    Return (action, reason), where action is spoof, forward, or block.

    Explicit operator rules win first. Smart spoof-all then forwards known
    connectivity/core/sensitive domains and spoofs the rest.
    """
    if domain_matches(domain, DNS_BLOCK_DOMAINS):
        return "block", "explicit_block"

    if domain_matches(domain, DNS_FORWARD_DOMAINS):
        return "forward", "explicit_forward"

    category = category_for_domain(domain, active_smart_categories())
    if category and DNS_SMART_SPOOF_ALL:
        return "forward", f"safe_category:{category}"

    if domain_matches(domain, DNS_SPOOF_DOMAINS):
        return "spoof", "explicit_spoof"

    if DNS_SPOOF_ALL:
        return "spoof", "spoof_all"

    if DNS_SMART_SPOOF_ALL:
        return "spoof", "smart_spoof_all"

    return "forward", "default_forward"


def build_dns_response(data: bytes, question_end: int, qtype: int) -> bytes:
    txid = data[0:2]
    qdcount = b"\x00\x01"
    question_section = data[12:question_end]

    if qtype == 1:  # A record
        return (
            txid
            + b"\x81\x80"
            + qdcount
            + b"\x00\x01"
            + b"\x00\x00\x00\x00"
            + question_section
            + b"\xc0\x0c"
            + b"\x00\x01"
            + b"\x00\x01"
            + b"\x00\x00\x00\x3c"
            + b"\x00\x04"
            + socket.inet_aton(YOUR_IP)
        )

    # For AAAA/HTTPS/SVCB/etc. on spoofed domains, answer NOERROR with no data.
    # That is gentler than NXDOMAIN and avoids saying the whole name does not exist.
    return (
        txid
        + b"\x81\x80"
        + qdcount
        + b"\x00\x00\x00\x00\x00\x00"
        + question_section
    )


def build_nxdomain_response(data: bytes, question_end: int) -> bytes:
    txid = data[0:2]
    qdcount = b"\x00\x01"
    question_section = data[12:question_end]
    return (
        txid
        + b"\x81\x83"
        + qdcount
        + b"\x00\x00\x00\x00\x00\x00"
        + question_section
    )


def build_servfail_response(data: bytes, question_end: int) -> bytes:
    txid = data[0:2]
    question_section = data[12:question_end]
    return (
        txid
        + b"\x81\x82"
        + b"\x00\x01"
        + b"\x00\x00\x00\x00\x00\x00"
        + question_section
    )


def _dns_question_class(data: bytes, question_end: int | None) -> int | None:
    if question_end is None or question_end < 2 or question_end > len(data):
        return None
    return int.from_bytes(data[question_end - 2 : question_end], "big")


def _dns_response_matches_query(query: bytes, response: bytes) -> bool:
    """Return whether an upstream DNS response belongs to the forwarded query."""
    if len(query) < 12 or len(response) < 12:
        return False
    if response[:2] != query[:2]:
        return False
    if not response[2] & 0x80:  # QR bit: must be a response
        return False
    if dns_qdcount(query) != 1 or dns_qdcount(response) != 1:
        return False

    query_domain, query_qtype, query_end = parse_dns_question(query)
    response_domain, response_qtype, response_end = parse_dns_question(response)
    if (
        query_domain is None
        or query_qtype is None
        or query_end is None
        or response_domain is None
        or response_qtype is None
        or response_end is None
    ):
        return False

    return (
        response_domain == query_domain
        and response_qtype == query_qtype
        and _dns_question_class(response, response_end)
        == _dns_question_class(query, query_end)
    )


def forward_dns_query(data: bytes) -> bytes | None:
    errors = []
    try:
        upstream_addresses = socket.getaddrinfo(
            DNS_UPSTREAM, 53, type=socket.SOCK_DGRAM
        )
    except socket.gaierror as e:
        print_flush(
            f"{yellow('[DNS]')} Upstream lookup failed ({DNS_UPSTREAM}): {e}"
        )
        return None

    if not upstream_addresses:
        print_flush(
            f"{yellow('[DNS]')} Upstream lookup returned no addresses ({DNS_UPSTREAM})"
        )
        return None

    for family, socktype, proto, _, sockaddr in upstream_addresses:
        try:
            with socket.socket(family, socktype, proto) as upstream:
                upstream.settimeout(2.0)
                upstream.connect(sockaddr)
                upstream.send(data)
                deadline = time.monotonic() + 2.0
                mismatches = 0
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise socket.timeout(
                            f"timed out waiting for matching response "
                            f"({mismatches} mismatched)"
                        )
                    upstream.settimeout(remaining)
                    response = upstream.recv(4096)
                    if _dns_response_matches_query(data, response):
                        return response
                    mismatches += 1
        except socket.timeout as e:
            errors.append(f"{sockaddr}: {e}")
        except OSError as e:
            errors.append(f"{sockaddr}: {e}")

    if errors:
        print_flush(
            f"{yellow('[DNS]')} Upstream forward failed ({DNS_UPSTREAM}): "
            + "; ".join(errors)
        )
    return None


def parse_args():
    parser = argparse.ArgumentParser(
        description="Combined captive portal HTTP server + selective fake DNS"
    )
    parser.add_argument(
        "--spoof",
        action="append",
        default=[],
        help="Domain to spoof to this host. May be repeated or comma-separated.",
    )
    parser.add_argument(
        "--spoof-all",
        action="store_true",
        help="Spoof every queried domain to this host for lab testing.",
    )
    parser.add_argument(
        "--smart-spoof-all",
        action="store_true",
        help="Spoof broadly, but forward safe connectivity/core/sensitive domains.",
    )
    parser.add_argument(
        "--forward",
        action="append",
        default=[],
        help="Domain to always forward upstream. May be repeated or comma-separated.",
    )
    parser.add_argument(
        "--block",
        action="append",
        default=[],
        help="Domain to block with NXDOMAIN. May be repeated or comma-separated.",
    )
    parser.add_argument(
        "--forward-category",
        action="append",
        default=[],
        choices=sorted(SAFE_DOMAIN_CATEGORIES),
        help="Safe category to forward in --smart-spoof-all mode.",
    )
    parser.add_argument(
        "--upstream",
        default=DNS_UPSTREAM,
        help="DNS server used for non-spoofed domains.",
    )
    parser.add_argument(
        "--dns-port",
        type=int,
        default=53,
        help="UDP DNS port to bind.",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=80,
        help="TCP HTTP portal port to bind.",
    )
    parser.add_argument(
        "--host-ip",
        help="IPv4 address to return for spoofed DNS. Defaults to auto-detect.",
    )
    parser.add_argument(
        "--health-token",
        default=HEALTH_TOKEN,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--verbose-dns",
        action="store_true",
        help="Print every DNS question, including forwarded domains.",
    )
    parser.add_argument(
        "--serve-ca-cert",
        action="store_true",
        help="Serve the mitmproxy CA certificate at /cert.",
    )
    parser.add_argument(
        "--dns-workers",
        type=int,
        default=DNS_MAX_WORKERS,
        help="Maximum concurrent DNS forwarding workers.",
    )
    parser.add_argument(
        "--suppress-dnssec",
        action="store_true",
        help="Compatibility alias for --dnssec-mode fail-open.",
    )
    parser.add_argument(
        "--dnssec-mode",
        choices=["off", "fail-closed", "fail-open", "nxdomain", "timeout"],
        default="off",
        help="Behavior for DNSSEC-aware queries (default: off).",
    )
    parser.add_argument(
        "--allow-cidr",
        action="append",
        default=[],
        help=(
            "Client CIDR allowed to use DNS. May be repeated or comma-separated; "
            "defaults to loopback only."
        ),
    )
    parser.add_argument(
        "--web-security-demo",
        action="store_true",
        help=(
            "Serve a non-credential-capturing HSTS/IDN lesson at "
            "/training/web-security."
        ),
    )
    parser.add_argument(
        "--idn-demo-domain",
        action="append",
        default=[],
        help=(
            "Unicode domain shown in the web lesson; restricted to reserved "
            ".test/.example/.invalid/.localhost names."
        ),
    )
    return parser.parse_args()


def configure_dns(args) -> None:
    """Merge CLI DNS policy into module-level state used by the server loop."""
    global DNS_SPOOF_ALL, DNS_SMART_SPOOF_ALL, DNS_SPOOF_DOMAINS
    global DNS_FORWARD_DOMAINS, DNS_BLOCK_DOMAINS, DNS_FORWARD_CATEGORIES
    global DNS_UPSTREAM, DNS_VERBOSE, DNS_MAX_WORKERS, SERVE_CA_CERT
    global HEALTH_TOKEN
    global DNS_SUPPRESS_DNSSEC, DNSSEC_MODE, DNS_ALLOWED_NETWORKS
    global WEB_SECURITY_DEMO, IDN_DEMO_DOMAINS
    DNS_SPOOF_ALL = DNS_SPOOF_ALL or args.spoof_all
    DNS_SMART_SPOOF_ALL = DNS_SMART_SPOOF_ALL or args.smart_spoof_all
    DNS_VERBOSE = DNS_VERBOSE or args.verbose_dns
    DNS_UPSTREAM = args.upstream
    DNS_MAX_WORKERS = max(1, min(args.dns_workers, 128))
    SERVE_CA_CERT = SERVE_CA_CERT or args.serve_ca_cert
    HEALTH_TOKEN = getattr(args, "health_token", "") or HEALTH_TOKEN
    requested_dnssec_mode = getattr(args, "dnssec_mode", "off")
    if requested_dnssec_mode != "off":
        DNSSEC_MODE = requested_dnssec_mode
    elif getattr(args, "suppress_dnssec", False):
        DNSSEC_MODE = "fail-open"
    DNS_SUPPRESS_DNSSEC = DNSSEC_MODE != "off"
    allowed_networks = []
    for token in getattr(args, "allow_cidr", []) or []:
        for raw_cidr in token.split(","):
            raw_cidr = raw_cidr.strip()
            if raw_cidr:
                allowed_networks.append(ip_network(raw_cidr, strict=False))
    DNS_ALLOWED_NETWORKS = tuple(allowed_networks) or (
        ip_network("127.0.0.0/8"),
        ip_network("::1/128"),
    )
    WEB_SECURITY_DEMO = WEB_SECURITY_DEMO or getattr(
        args, "web_security_demo", False
    )
    IDN_DEMO_DOMAINS = [
        normalize_idn_demo_domain(domain)
        for domain in getattr(args, "idn_demo_domain", [])
    ]
    cli_domains = {
        domain.strip().rstrip(".").lower()
        for item in args.spoof
        for domain in item.split(",")
        if domain.strip()
    }
    DNS_SPOOF_DOMAINS.update(cli_domains)
    cli_forward = {
        domain.strip().rstrip(".").lower()
        for item in args.forward
        for domain in item.split(",")
        if domain.strip()
    }
    DNS_FORWARD_DOMAINS.update(cli_forward)
    cli_block = {
        domain.strip().rstrip(".").lower()
        for item in args.block
        for domain in item.split(",")
        if domain.strip()
    }
    DNS_BLOCK_DOMAINS.update(cli_block)
    DNS_FORWARD_CATEGORIES.update(args.forward_category)


# ── Fake DNS Server (UDP, dual-stack, parameterised port) ──────────────────
def bind_dns_socket(port: int = 53) -> socket.socket:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    if hasattr(socket, "IPV6_V6ONLY"):
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception as e:
            print_flush(
                f"{yellow('[DNS]')} Warning: Could not configure IPV6_V6ONLY: {e}"
            )

    try:
        sock.bind(("::", port))
    except PermissionError:
        sock.close()
        sys.exit(
            f"{red('[DNS]')} Error: Root privileges required to bind to port {port}."
        )
    except OSError as e:
        sock.close()
        sys.exit(f"{red('[DNS]')} Error: Could not bind to port {port}: {e}")

    return sock


def print_dns_startup(port: int) -> None:
    if DNS_SPOOF_ALL:
        mode = "ALL DOMAINS"
    elif DNS_SMART_SPOOF_ALL:
        mode = "SMART ALL"
    else:
        mode = ", ".join(sorted(DNS_SPOOF_DOMAINS)) or "none (forward-only)"
    forwarded = ", ".join(sorted(DNS_FORWARD_DOMAINS)) or "none"
    blocked = ", ".join(sorted(DNS_BLOCK_DOMAINS)) or "none"
    categories = ", ".join(sorted(active_smart_categories())) or "none"
    print_flush(bold(cyan("NetShaper captive portal + DNS")))
    print_flush(
        f"{cyan('[DNS]')} Dual-stack DNS listening on port {port}  "
        f"(YOUR_IP={YOUR_IP})"
    )
    print_flush(f"{cyan('[DNS]')} Upstream={DNS_UPSTREAM}  Spoof={mode}")
    print_flush(
        f"{cyan('[DNS]')} Forward={forwarded}  Block={blocked}  "
        f"SmartCategories={categories}"
    )
    print_flush(
        f"{cyan('[DNS]')} Allowed clients="
        + ", ".join(str(network) for network in DNS_ALLOWED_NETWORKS)
    )
    if DNS_SUPPRESS_DNSSEC:
        print_flush(
            f"{yellow('[DNS]')} DNSSEC mode={_effective_dnssec_mode()}"
        )
    if WEB_SECURITY_DEMO:
        print_flush(
            f"{cyan('[Portal]')} Web security lesson: /training/web-security"
        )


def handle_dns_query(sock: socket.socket, data: bytes, addr) -> None:
    try:
        if not dns_client_authorized(str(addr[0])):
            print_flush(
                f"{yellow('[DNS]')} Rejecting unauthorized client {addr[0]}"
            )
            return
        if len(data) < 12:
            return

        qdcount = dns_qdcount(data)
        if qdcount != 1:
            print_flush(
                f"{yellow('[DNS]')} Rejecting query from {addr}: "
                f"QDCOUNT={qdcount}, expected 1"
            )
            return

        domain, qtype, question_end = parse_dns_question(data)
        if domain is None:
            return

        dnssec_mode = _effective_dnssec_mode()
        dnssec_requested = _query_requests_dnssec(data, qtype)
        if dnssec_requested and dnssec_mode == "timeout":
            print_flush(f"{yellow('[DNS]')} DNSSEC-TIMEOUT {domain} qtype={qtype}")
            return
        if dnssec_requested and dnssec_mode == "fail-closed":
            response = build_servfail_response(data, question_end)
            print_flush(f"{yellow('[DNS]')} DNSSEC-SERVFAIL {domain} qtype={qtype}")
            sock.sendto(response, addr)
            return
        if dnssec_requested and dnssec_mode == "nxdomain":
            response = build_nxdomain_response(data, question_end)
            print_flush(f"{yellow('[DNS]')} DNSSEC-NXDOMAIN {domain} qtype={qtype}")
            sock.sendto(response, addr)
            return

        action, reason = decide_dns_policy(domain, qtype)

        if dnssec_mode == "fail-open" and qtype in DNSSEC_QTYPES:
            response = build_dns_response(data, question_end, qtype)
            print_flush(
                f"{yellow('[DNS]')} DNSSEC-NODATA {domain} qtype={qtype}"
            )
        elif action == "spoof":
            response = build_dns_response(data, question_end, qtype)
            print_flush(
                f"{green('[DNS]')} SPOOF {domain} qtype={qtype} -> {YOUR_IP} "
                f"reason={reason}"
            )
        elif action == "block":
            response = build_nxdomain_response(data, question_end)
            print_flush(
                f"{yellow('[DNS]')} BLOCK {domain} qtype={qtype} reason={reason}"
            )
        else:
            if DNS_VERBOSE:
                print_flush(
                    f"{cyan('[DNS]')} FORWARD {domain} qtype={qtype} -> "
                    f"{DNS_UPSTREAM} reason={reason}"
                )
            forwarded_query = data
            dnssec_changed = False
            if dnssec_mode != "off":
                forwarded_query, dnssec_changed = suppress_dnssec_query(data)
            response = forward_dns_query(forwarded_query)
            if response is None:
                return
            if dnssec_mode != "off":
                response = suppress_dnssec_response(response)
                if DNS_VERBOSE and dnssec_changed:
                    print_flush(
                        f"{yellow('[DNS]')} DNSSEC flags suppressed for {domain}"
                    )

        sock.sendto(response, addr)

    except OSError as e:
        print_flush(f"{red('[DNS]')} Socket send failed for {addr}: {e}")
        if e.errno in (errno.EBADF, errno.ENOTSOCK, errno.ENOMEM):
            raise
    except Exception as e:
        print_flush(f"{yellow('[DNS]')} Failed to process query from {addr}: {e}")


def serve_dns(sock: socket.socket) -> None:
    in_flight = threading.BoundedSemaphore(DNS_MAX_WORKERS)
    executor = ThreadPoolExecutor(
        max_workers=DNS_MAX_WORKERS,
        thread_name_prefix="netshaper-dns",
    )

    def submit_query(data: bytes, addr) -> None:
        if not in_flight.acquire(blocking=False):
            print_flush(
                f"{yellow('[DNS]')} Dropping query from {addr}: workers busy"
            )
            return

        def run_query() -> None:
            try:
                handle_dns_query(sock, data, addr)
            finally:
                in_flight.release()

        executor.submit(run_query)

    try:
        while True:
            try:
                data, addr = sock.recvfrom(1024)
            except OSError as e:
                print_flush(
                    f"{red('[DNS]')} Socket receive failed; stopping DNS server: {e}"
                )
                break
            submit_query(data, addr)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def serve_dns_sync(sock: socket.socket) -> None:
    """Single-threaded DNS loop kept for deterministic tests."""
    while True:
        try:
            data, addr = sock.recvfrom(1024)
        except OSError as e:
            print_flush(
                f"{red('[DNS]')} Socket receive failed; stopping DNS server: {e}"
            )
            break
        try:
            handle_dns_query(sock, data, addr)
        except OSError:
            break


def dns_server(port: int = 53):
    """
    Dual-stack UDP DNS server.
      - selected A queries  → YOUR_IP
      - selected non-A      → NOERROR/NODATA
      - all other queries   → upstream DNS
    RFC 1035 §4.1.4 pointer-compression handled.
    Only single-question requests are accepted.

    port param allows unprivileged override (e.g. 5353) in CI/test runs.
    """
    sock = bind_dns_socket(port)
    print_dns_startup(port)
    serve_dns(sock)


# ── HTTP Server (Captive Portal, dual-stack) ───────────────────────────────
class CaptivePortalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client = self.client_address[0]
        path = self.path

        if path == "/_netshaper/health":
            supplied = self.headers.get("X-NetShaper-Session", "")
            if HEALTH_TOKEN and hmac.compare_digest(supplied, HEALTH_TOKEN):
                content = HEALTH_TOKEN.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("X-NetShaper-Session", HEALTH_TOKEN)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(content)
                return
            msg = b"Not found."
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(msg)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(msg)
            return

        # 1. Static HSTS/IDN training page (no forms or credential capture)
        if path == "/training/web-security":
            if not WEB_SECURITY_DEMO:
                msg = b"Web security training demo is disabled."
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(msg)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(msg)
                return
            content = render_web_security_demo(IDN_DEMO_DOMAINS)
            print_flush(
                f"{green('[Portal]')} Serving web security lab to {client}"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            # Deliberately sent over HTTP: conforming browsers must ignore it.
            self.send_header(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(content)
            return

        # 2. OS captive-portal probes → 204 No Content
        if any(probe in path for probe in CAPTIVE_CHECK_PATHS):
            print_flush(f"{cyan('[Portal]')} Captive check  {client}  {path}")
            self.send_response(204)
            self.send_header("Connection", "close")
            self.end_headers()
            return

        # 3. CA certificate delivery
        #    Served over plain HTTP intentionally — client must be able to
        #    fetch the cert BEFORE trusting TLS; that's the whole install flow.
        if path == "/cert":
            if not SERVE_CA_CERT:
                msg = b"CA certificate serving is disabled."
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(msg)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(msg)
                return
            content = ca_cert_content()
            if content is not None:
                print_flush(
                    f"{green('[Portal]')} Serving MITM CA cert to {client}"
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/x-x509-ca-cert")
                self.send_header("Content-Length", str(len(content)))
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="mitmproxy-ca-cert.cer"',
                )
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(content)
            else:
                msg = b"Error: mitmproxy CA cert not found on server."
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(msg)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(msg)
            return

        # 4. Root / index
        if path in ("/", "/index.html"):
            if os.path.exists(INDEX_FILE_PATH):
                print_flush(f"{green('[Portal]')} Serving index.html to {client}")
                with open(INDEX_FILE_PATH, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(content)
            else:
                msg = b"Error: index.html not found at /var/www/html/index.html"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(msg)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(msg)
            return

        # 5. Everything else → redirect to captive portal
        print_flush(
            f"{cyan('[Portal]')} Redirecting {client}  {path}  → /index.html"
        )
        self.send_response(302)
        # Use canonical portal URL (includes configured port when non-80)
        self.send_header("Location", f"{portal_base_url()}/index.html")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass  # Suppress Apache-style access log noise


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server — suppresses predictable client-drop noise."""

    daemon_threads = True

    def handle_error(self, request, client_address):
        exc_type = sys.exc_info()[0]
        if exc_type in (ConnectionResetError, BrokenPipeError):
            pass  # OS probed then dropped — normal captive-portal noise
        else:
            super().handle_error(request, client_address)


class DualStackHTTPServer(ThreadedHTTPServer):
    """
    Accepts both IPv4 and IPv6 on a single socket.
    address_family tells HTTPServer.__init__ to create an AF_INET6 socket;
    server_bind() then disables IPV6_V6ONLY before the parent binds so
    IPv4-mapped addresses (::ffff:x.x.x.x) are also accepted.
    """

    address_family = socket.AF_INET6

    def server_bind(self):
        if hasattr(socket, "IPV6_V6ONLY"):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def main() -> None:
    global YOUR_IP, HTTP_PORT

    args = parse_args()
    configure_dns(args)
    YOUR_IP = args.host_ip or get_own_ip()
    HTTP_PORT = args.http_port

    # Phase 1: bind privileged ports
    dns_sock = bind_dns_socket(args.dns_port)

    try:
        httpd = DualStackHTTPServer(("::", args.http_port), CaptivePortalHandler)
    except PermissionError:
        dns_sock.close()
        sys.exit(
            f"{red('[Portal]')} Error: Root privileges required to bind to "
            f"port {args.http_port}."
        )
    except OSError as e:
        dns_sock.close()
        sys.exit(
            f"{red('[Portal]')} Error: Could not bind to port {args.http_port}: {e}"
        )

    # Phase 2: drop root now that sockets are bound
    if SERVE_CA_CERT:
        load_ca_cert()
    drop_privileges("nobody")
    print_dns_startup(args.dns_port)
    threading.Thread(target=serve_dns, args=(dns_sock,), daemon=True).start()

    print_flush(
        f"{bold(green('[Engine]'))} Combined server running — DNS :{args.dns_port}  "
        f"HTTP :{args.http_port}  (IP: {YOUR_IP})"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print_flush(f"\n{yellow('[Engine]')} Shutting down gracefully.")


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
