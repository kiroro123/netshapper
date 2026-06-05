#!/usr/bin/env python3
"""
Combined Captive Portal (HTTP) + Fake DNS Server
Production Build v3 — All patches applied
─────────────────────────────────────────────────
• Fail-fast IP detection (no silent loopback fallback)
• UDP 53 : Dual-stack DNS (AF_INET6 + IPV6_V6ONLY=0)
           Parameterised port for unprivileged CI testing
           Pointer-compression guard, dynamic QDCOUNT echo,
           bounds-checked QTYPE extraction
• TCP 80 : Dual-stack threaded HTTP server
           DualStackHTTPServer via address_family + super().server_bind()
• Privilege drop after socket binding (Phase 1 / Phase 2 architecture)
• CA cert served over plain HTTP intentionally (install flow pre-TLS)
"""

import os, sys, socket, threading, pwd
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


YOUR_IP         = get_own_ip()
INDEX_FILE_PATH = "/var/www/html/index.html"
CA_CERT_PATH    = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.cer")

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


# ── Fake DNS Server (UDP, dual-stack, parameterised port) ──────────────────
def dns_server(port: int = 53):
    """
    Dual-stack UDP DNS server.
      - A queries  → YOUR_IP
      - All others → NXDOMAIN
    RFC 1035 §4.1.4 pointer-compression handled.
    QDCOUNT echoed verbatim for strict-resolver compatibility.

    port param allows unprivileged override (e.g. 5353) in CI/test runs.
    """
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    if hasattr(socket, "IPV6_V6ONLY"):
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception as e:
            print(f"[DNS] Warning: Could not configure IPV6_V6ONLY: {e}")

    try:
        sock.bind(("::", port))
    except PermissionError:
        sys.exit(f"[DNS] Error: Root privileges required to bind to port {port}.")

    print(f"[DNS] Dual-stack DNS listening on port {port}  (YOUR_IP={YOUR_IP})")

    while True:
        try:
            data, addr = sock.recvfrom(1024)

            if len(data) < 12:
                continue

            txid    = data[0:2]
            qdcount = data[4:6]   # Echo verbatim — RFC compliance
            offset  = 12          # Start of Question section

            # ── Traverse QNAME labels ────────────────────────────────────
            # while/else: else runs ONLY on natural exit (null terminator).
            # break (pointer compression) skips the else block entirely,
            # keeping offset arithmetic correct in both paths.
            while offset < len(data) and data[offset] != 0:
                if (data[offset] & 0xC0) == 0xC0:
                    offset += 2   # Pointer is exactly 2 bytes; done
                    break
                label_len = data[offset]
                offset += label_len + 1
            else:
                offset += 1       # Step past the 0x00 null terminator

            # ── Bounds-check before reading QTYPE/QCLASS ─────────────────
            if offset + 4 > len(data):
                continue          # Malformed — drop silently

            qtype            = (data[offset] << 8) | data[offset + 1]
            question_section = data[12:offset + 4]  # Reused in both branches

            if qtype == 1:        # A record → answer with YOUR_IP
                response = (
                    txid
                    + b'\x81\x80'           # QR=1 AA=0 RD=1 RA=1 RCODE=0 (NOERROR)
                    + qdcount               # QDCOUNT echoed
                    + b'\x00\x01'           # ANCOUNT = 1
                    + b'\x00\x00\x00\x00'   # NSCOUNT / ARCOUNT = 0
                    + question_section
                    + b'\xc0\x0c'           # Answer NAME → pointer to offset 12
                    + b'\x00\x01'           # TYPE  = A
                    + b'\x00\x01'           # CLASS = IN
                    + b'\x00\x00\x00\x3c'  # TTL   = 60 s
                    + b'\x00\x04'           # RDLENGTH = 4
                    + socket.inet_aton(YOUR_IP)
                )
            else:                 # Anything else → NXDOMAIN
                response = (
                    txid
                    + b'\x81\x83'           # QR=1 RCODE=3 (NXDOMAIN)
                    + qdcount
                    + b'\x00\x00\x00\x00\x00\x00'
                    + question_section
                )

            sock.sendto(response, addr)

        except Exception:
            continue              # Never crash on a bad packet


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


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Phase 1: bind privileged ports
    threading.Thread(target=dns_server, daemon=True).start()

    try:
        httpd = DualStackHTTPServer(("::", 80), CaptivePortalHandler)
    except PermissionError:
        sys.exit("[Portal] Error: Root privileges required to bind to port 80.")

    # Phase 2: drop root now that sockets are bound
    drop_privileges("nobody")

    print(f"[Portal] Combined server running — DNS :53  HTTP :80  (IP: {YOUR_IP})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Portal] Shutting down gracefully.")
