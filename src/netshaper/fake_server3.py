#!/usr/bin/env python3
"""
Combined Captive Portal (HTTP) + Fake DNS Server
Production Build v3 — All patches applied
─────────────────────────────────────────────────
• Fail-fast IP detection (no silent loopback fallback)
• UDP 53 : Dual-stack DNS (AF_INET6 + IPV6_V6ONLY=0)
           Policy-based spoof / forward / block decisions
           Optional --spoof-all and --smart-spoof-all lab modes
           Pointer-compression guard, dynamic QDCOUNT echo,
           bounds-checked QTYPE extraction
• TCP 80 : Dual-stack threaded HTTP server
           DualStackHTTPServer via address_family + super().server_bind()
• Privilege drop after socket binding (Phase 1 / Phase 2 architecture)
• CA cert served over plain HTTP intentionally (install flow pre-TLS)
"""

import argparse, os, sys, socket, threading, pwd
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn


# ── Auto-detect own IP (fail-fast) ─────────────────────────────────────────
def get_own_ip() -> str:
    """Return IPv4 address of the primary interface or exit with a clear error."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception as e:
        sys.exit(
            f"[Portal] Fatal: Automatic network IP detection failed: {e}\n"
            f"Ensure an active network interface is available."
        )
    finally:
        s.close()
    return ip


YOUR_IP         = ""
INDEX_FILE_PATH = "/var/www/html/index.html"
CA_CERT_PATH    = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.cer")
DNS_UPSTREAM    = os.environ.get("DNS_UPSTREAM", "8.8.8.8")
DNS_SPOOF_ALL   = os.environ.get("DNS_SPOOF_ALL", "").lower() in ("1", "true", "yes")
DNS_SMART_SPOOF_ALL = os.environ.get("DNS_SMART_SPOOF_ALL", "").lower() in (
    "1", "true", "yes"
)
DNS_VERBOSE     = os.environ.get("DNS_VERBOSE", "").lower() in ("1", "true", "yes")


def parse_domain_csv(value: str) -> set[str]:
    return {d.strip().rstrip(".").lower() for d in value.split(",") if d.strip()}


DNS_SPOOF_DOMAINS = parse_domain_csv(os.environ.get("DNS_SPOOF_DOMAINS", ""))
DNS_FORWARD_DOMAINS = parse_domain_csv(os.environ.get("DNS_FORWARD_DOMAINS", ""))
DNS_BLOCK_DOMAINS = parse_domain_csv(os.environ.get("DNS_BLOCK_DOMAINS", ""))

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
    "/generate_204", "/gen_204", "/hotspot-detect.html",
    "/success.txt", "/connecttest.txt", "/redirect",
]


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
        os.setgroups([])            # Drop supplementary group memberships
        os.setgid(pw.pw_gid)        # Set GID first (can't after setuid)
        os.setuid(pw.pw_uid)        # Drop to unprivileged UID
        print(f"[Engine] Privileges dropped to '{user}' "
              f"(uid={pw.pw_uid}, gid={pw.pw_gid})")
    except KeyError:
        sys.exit(f"[Engine] Fatal: Drop target user '{user}' does not exist.")
    except PermissionError as e:
        sys.exit(f"[Engine] Fatal: Failed to drop privileges: {e}")


# ── DNS helpers ────────────────────────────────────────────────────────────
def parse_dns_question(data: bytes):
    """Return (domain, qtype, question_end) for the first DNS question."""
    if len(data) < 12:
        return None, None, None

    labels = []
    offset = 12
    jumped = False
    jumps = 0

    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                return None, None, None
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                offset += 2
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > 8:
                return None, None, None
            continue
        offset += 1
        if offset + length > len(data):
            return None, None, None
        try:
            labels.append(data[offset:offset + length].decode("ascii").lower())
        except UnicodeDecodeError:
            return None, None, None
        offset += length

    question_end = offset + 4
    if question_end > len(data):
        return None, None, None
    qtype = (data[offset] << 8) | data[offset + 1]
    return ".".join(labels).rstrip("."), qtype, question_end


def domain_matches(domain: str, patterns: set[str]) -> bool:
    if not domain:
        return False
    return any(domain == pattern or domain.endswith(f".{pattern}")
               for pattern in patterns)


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
    qdcount = data[4:6]
    question_section = data[12:question_end]

    if qtype == 1:  # A record
        return (
            txid
            + b'\x81\x80'
            + qdcount
            + b'\x00\x01'
            + b'\x00\x00\x00\x00'
            + question_section
            + b'\xc0\x0c'
            + b'\x00\x01'
            + b'\x00\x01'
            + b'\x00\x00\x00\x3c'
            + b'\x00\x04'
            + socket.inet_aton(YOUR_IP)
        )

    # For AAAA/HTTPS/SVCB/etc. on spoofed domains, answer NOERROR with no data.
    # That is gentler than NXDOMAIN and avoids saying the whole name does not exist.
    return (
        txid
        + b'\x81\x80'
        + qdcount
        + b'\x00\x00\x00\x00\x00\x00'
        + question_section
    )


def build_nxdomain_response(data: bytes, question_end: int) -> bytes:
    txid = data[0:2]
    qdcount = data[4:6]
    question_section = data[12:question_end]
    return (
        txid
        + b'\x81\x83'
        + qdcount
        + b'\x00\x00\x00\x00\x00\x00'
        + question_section
    )


def forward_dns_query(data: bytes) -> bytes | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
            upstream.settimeout(2.0)
            upstream.sendto(data, (DNS_UPSTREAM, 53))
            response, _ = upstream.recvfrom(4096)
            return response
    except Exception as e:
        print(f"[DNS] Upstream forward failed ({DNS_UPSTREAM}): {e}")
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
        "--verbose-dns",
        action="store_true",
        help="Print every DNS question, including forwarded domains.",
    )
    return parser.parse_args()


def configure_dns(args) -> None:
    global DNS_SPOOF_ALL, DNS_SMART_SPOOF_ALL, DNS_SPOOF_DOMAINS
    global DNS_FORWARD_DOMAINS, DNS_BLOCK_DOMAINS, DNS_FORWARD_CATEGORIES
    global DNS_UPSTREAM, DNS_VERBOSE
    DNS_SPOOF_ALL = DNS_SPOOF_ALL or args.spoof_all
    DNS_SMART_SPOOF_ALL = DNS_SMART_SPOOF_ALL or args.smart_spoof_all
    DNS_VERBOSE = DNS_VERBOSE or args.verbose_dns
    DNS_UPSTREAM = args.upstream
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
            print(f"[DNS] Warning: Could not configure IPV6_V6ONLY: {e}")

    try:
        sock.bind(("::", port))
    except PermissionError:
        sock.close()
        sys.exit(f"[DNS] Error: Root privileges required to bind to port {port}.")
    except OSError as e:
        sock.close()
        sys.exit(f"[DNS] Error: Could not bind to port {port}: {e}")

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
    print(f"[DNS] Dual-stack DNS listening on port {port}  (YOUR_IP={YOUR_IP})")
    print(f"[DNS] Upstream={DNS_UPSTREAM}  Spoof={mode}")
    print(f"[DNS] Forward={forwarded}  Block={blocked}  SmartCategories={categories}")


def serve_dns(sock: socket.socket) -> None:
    while True:
        try:
            data, addr = sock.recvfrom(1024)

            if len(data) < 12:
                continue

            domain, qtype, question_end = parse_dns_question(data)
            if domain is None:
                continue

            action, reason = decide_dns_policy(domain, qtype)

            if action == "spoof":
                response = build_dns_response(data, question_end, qtype)
                print(
                    f"[DNS] SPOOF {domain} qtype={qtype} -> {YOUR_IP} "
                    f"reason={reason}"
                )
            elif action == "block":
                response = build_nxdomain_response(data, question_end)
                print(f"[DNS] BLOCK {domain} qtype={qtype} reason={reason}")
            else:
                if DNS_VERBOSE:
                    print(
                        f"[DNS] FORWARD {domain} qtype={qtype} -> {DNS_UPSTREAM} "
                        f"reason={reason}"
                    )
                response = forward_dns_query(data)
                if response is None:
                    continue

            sock.sendto(response, addr)

        except Exception:
            continue              # Never crash on a bad packet


def dns_server(port: int = 53):
    """
    Dual-stack UDP DNS server.
      - selected A queries  → YOUR_IP
      - selected non-A      → NOERROR/NODATA
      - all other queries   → upstream DNS
    RFC 1035 §4.1.4 pointer-compression handled.
    QDCOUNT echoed verbatim for strict-resolver compatibility.

    port param allows unprivileged override (e.g. 5353) in CI/test runs.
    """
    sock = bind_dns_socket(port)
    print_dns_startup(port)
    serve_dns(sock)


# ── HTTP Server (Captive Portal, dual-stack) ───────────────────────────────
class CaptivePortalHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        client = self.client_address[0]
        path   = self.path

        # 1. OS captive-portal probes → 204 No Content
        if any(probe in path for probe in CAPTIVE_CHECK_PATHS):
            print(f"[Portal] Captive check  {client}  {path}")
            self.send_response(204)
            self.send_header("Connection", "close")
            self.end_headers()
            return

        # 2. CA certificate delivery
        #    Served over plain HTTP intentionally — client must be able to
        #    fetch the cert BEFORE trusting TLS; that's the whole install flow.
        if path == "/cert":
            if os.path.exists(CA_CERT_PATH):
                print(f"[Portal] Serving MITM CA cert to {client}")
                with open(CA_CERT_PATH, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-x509-ca-cert")
                self.send_header("Content-Length", str(len(content)))
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="mitmproxy-ca-cert.cer"'
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

        # 3. Root / index
        if path in ("/", "/index.html"):
            if os.path.exists(INDEX_FILE_PATH):
                print(f"[Portal] Serving index.html to {client}")
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

        # 4. Everything else → redirect to captive portal
        print(f"[Portal] Redirecting {client}  {path}  → /index.html")
        self.send_response(302)
        self.send_header("Location", f"http://{YOUR_IP}/index.html")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass   # Suppress Apache-style access log noise


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server — suppresses predictable client-drop noise."""
    daemon_threads = True

    def handle_error(self, request, client_address):
        exc_type = sys.exc_info()[0]
        if exc_type in (ConnectionResetError, BrokenPipeError):
            pass   # OS probed then dropped — normal captive-portal noise
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
    global YOUR_IP

    args = parse_args()
    configure_dns(args)
    YOUR_IP = args.host_ip or get_own_ip()

    # Phase 1: bind privileged ports
    dns_sock = bind_dns_socket(args.dns_port)

    try:
        httpd = DualStackHTTPServer(("::", args.http_port), CaptivePortalHandler)
    except PermissionError:
        dns_sock.close()
        sys.exit(
            f"[Portal] Error: Root privileges required to bind to port {args.http_port}."
        )
    except OSError as e:
        dns_sock.close()
        sys.exit(f"[Portal] Error: Could not bind to port {args.http_port}: {e}")

    # Phase 2: drop root now that sockets are bound
    drop_privileges("nobody")
    print_dns_startup(args.dns_port)
    threading.Thread(target=serve_dns, args=(dns_sock,), daemon=True).start()

    print(
        f"[Portal] Combined server running — DNS :{args.dns_port}  "
        f"HTTP :{args.http_port}  (IP: {YOUR_IP})"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Portal] Shutting down gracefully.")


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
