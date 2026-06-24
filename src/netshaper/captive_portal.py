#!/usr/bin/env python3
"""
NetShaper — Captive Portal + Fake DNS Server

- DnsConfig dataclass for immutable DNS configuration
- HTTPPortalConfig dataclass for HTTP configuration
- CLI arguments for hardcoded paths
- Phase 1/2 privilege dropping
"""

import argparse
import logging
import os
import pwd
import socket
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import ip_address
from socketserver import ThreadingMixIn
from typing import Optional, Set

import psutil

try:
    from netshaper.utils import bold, cyan, print_flush
except ModuleNotFoundError:
    # Allows direct execution for development
    from utils import bold, cyan, print_flush

log = logging.getLogger("netshaper.captive_portal")


@dataclass(frozen=True)
class DnsConfig:
    """Immutable DNS configuration."""
    upstream: str = "8.8.8.8"
    spoof_all: bool = False
    smart_spoof_all: bool = False
    verbose: bool = False
    max_workers: int = 16
    spoof_domains: Set[str] = None
    forward_domains: Set[str] = None
    block_domains: Set[str] = None

    def __post_init__(self):
        # Use object.__setattr__ to set frozen dataclass fields
        if self.spoof_domains is None:
            object.__setattr__(self, 'spoof_domains', frozenset())
        if self.forward_domains is None:
            object.__setattr__(self, 'forward_domains', frozenset())
        if self.block_domains is None:
            object.__setattr__(self, 'block_domains', frozenset())


@dataclass(frozen=True)
class HTTPPortalConfig:
    """Immutable HTTP portal configuration."""
    host_ip: str
    http_port: int = 80
    index_file: Optional[str] = None
    ca_cert_path: Optional[str] = None
    serve_ca_cert: bool = False

    def get_index_content(self) -> bytes:
        """Load index file content, with fallback."""
        if self.index_file and os.path.exists(self.index_file):
            try:
                with open(self.index_file, "rb") as f:
                    return f.read()
            except Exception as e:
                log.warning(f"Could not load index file {self.index_file}: {e}")

        # Fallback: simple portal page
        return b"""<!DOCTYPE html>
<html>
<head><title>Captive Portal</title></head>
<body>
  <h1>Network Access Required</h1>
  <p>Please accept the security certificate to continue.</p>
  <a href="/cert">Download Certificate</a>
</body>
</html>"""

    def get_ca_cert_content(self) -> Optional[bytes]:
        """Load CA certificate, if configured."""
        if not self.ca_cert_path or not os.path.exists(self.ca_cert_path):
            return None
        try:
            with open(self.ca_cert_path, "rb") as f:
                return f.read()
        except Exception as e:
            log.error(f"Could not read CA cert {self.ca_cert_path}: {e}")
            return None


def get_own_ip(host_ip: Optional[str] = None) -> str:
    """
    Auto-detect own IPv4 or use explicit address.

    Raises:
        RuntimeError: If no usable address found
    """
    if host_ip:
        try:
            parsed = ip_address(host_ip)
            if parsed.version == 4 and not parsed.is_loopback:
                return host_ip
        except ValueError:
            pass
        raise RuntimeError(f"Invalid --host-ip {host_ip}")

    # Auto-detect
    errors = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip_address(ip).is_loopback:
                return ip
            errors.append(f"route probe returned loopback {ip}")
    except Exception as e:
        errors.append(f"route probe failed: {e}")

    try:
        stats = psutil.net_if_stats()
        for iface, addrs in psutil.net_if_addrs().items():
            if not stats.get(iface, psutil.snicstats()).isup:
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET and not ip_address(addr.address).is_loopback:
                    return addr.address
        errors.append("psutil found no active non-loopback IPv4")
    except Exception as e:
        errors.append(f"psutil fallback failed: {e}")

    detail = "; ".join(errors)
    raise RuntimeError(f"IP detection failed: {detail}. Use --host-ip explicitly.")


def drop_privileges(user: str = "nobody") -> None:
    """
    Drop from root to unprivileged user after sockets are bound.
    Call order: setgroups → setgid → setuid.
    """
    if os.geteuid() != 0:
        return  # Already unprivileged

    try:
        pw = pwd.getpwnam(user)
        os.setgroups([])
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)
        log.info(f"Privileges dropped to '{user}' (uid={pw.pw_uid}, gid={pw.pw_gid})")
    except KeyError as e:
        raise RuntimeError(f"Drop target user '{user}' does not exist.") from e
    except PermissionError as e:
        raise RuntimeError(f"Failed to drop privileges: {e}") from e


# ── DNS Server ─────────────────────────────────────────────────────────────

class DNSServer(ThreadingMixIn, socket.socket):
    """UDP DNS server with configurable spoof/forward/block policies."""

    def __init__(self, host: str, port: int, dns_config: DnsConfig):
        super().__init__(socket.AF_INET6, socket.SOCK_DGRAM)
        self.host = host
        self.port = port
        self.dns_config = dns_config
        self.running = True

        # Dual-stack IPv6
        self.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self.bind(("::", port))
        log.info(f"DNS server listening on [::]:{ port}")

    def handle_dns_request(self, data: bytes, addr) -> bytes:
        """Process DNS query and return response."""
        if len(data) < 12:
            return b""

        # Simple query? (QR=0, OPCODE=0)
        if (data[2] & 0xF8) != 0:
            return b""

        # Single question?
        question_count = (data[4] << 8) | data[5]
        if question_count != 1:
            return b""

        try:
            domain, qtype = self._parse_question(data)
            if not domain or qtype not in (1, 28):  # A or AAAA
                return b""

            decision = self._spoof_decision(domain)
            if decision == "spoof":
                return self._build_response(data, domain, qtype, self.dns_config.upstream if not self.dns_config.spoof_all else self.host)
            elif decision == "forward":
                return self._forward_query(data, self.dns_config.upstream)
            else:  # "block"
                return self._build_nxdomain(data)
        except Exception as e:
            log.debug(f"DNS error: {e}")
            return b""

    def _parse_question(self, data: bytes):
        """Parse first DNS question."""
        offset = 12
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                offset = ((length & 0x3F) << 8) | data[offset + 1]
                continue
            offset += 1
            if offset + length > len(data):
                return None, None
            labels.append(data[offset:offset + length].decode("ascii", errors="ignore").lower())
            offset += length

        if offset + 4 > len(data):
            return None, None
        domain = ".".join(labels)
        qtype = (data[offset] << 8) | data[offset + 1]
        return domain, qtype

    def _spoof_decision(self, domain: str) -> str:
        """Return 'spoof', 'forward', or 'block' decision."""
        if self.dns_config.block_domains and domain in self.dns_config.block_domains:
            return "block"
        if self.dns_config.spoof_all:
            return "spoof"
        if self.dns_config.smart_spoof_all and not domain.endswith(".local"):
            return "spoof"
        if domain in self.dns_config.spoof_domains:
            return "spoof"
        if domain in self.dns_config.forward_domains:
            return "forward"
        return "forward" if self.dns_config.spoof_all or self.dns_config.smart_spoof_all else "forward"

    def _build_response(self, req: bytes, domain: str, qtype: int, answer_ip: str) -> bytes:
        """Build DNS response with spoofed answer."""
        # Simplified: just echo with RR answer
        resp = bytearray(req[:2])  # Transaction ID
        resp.extend([0x84, 0x00])  # Flags: response, no error
        resp.extend(req[4:6])  # Questions
        resp.extend([0x00, 0x01])  # Answer RRs
        resp.extend([0x00, 0x00, 0x00, 0x00])  # Auth + Additional
        resp.extend(req[12:])  # Original question

        # Answer RR (simplified)
        ttl = 60
        resp.extend([0xC0, 0x0C])  # Pointer to question name
        resp.extend([0x00, qtype])  # Type (A=1 or AAAA=28)
        resp.extend([0x00, 0x01])  # Class (IN)
        resp.extend(ttl.to_bytes(4, "big"))  # TTL
        if qtype == 1:  # A record
            resp.extend([0x00, 0x04])  # Data length (4 bytes for IPv4)
            resp.extend(ip_address(answer_ip).packed)
        else:  # AAAA record
            resp.extend([0x00, 0x10])  # Data length (16 bytes for IPv6)
            resp.extend(ip_address(answer_ip).packed)
        return bytes(resp)

    def _build_nxdomain(self, req: bytes) -> bytes:
        """Build NXDOMAIN response."""
        resp = bytearray(req[:2])
        resp.extend([0x84, 0x03])  # Response, NXDOMAIN
        resp.extend(req[4:12])
        return bytes(resp)

    def _forward_query(self, data: bytes, upstream: str) -> bytes:
        """Forward query to upstream DNS."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.sendto(data, (upstream, 53))
                return s.recv(512)
        except Exception:
            return self._build_nxdomain(data)

    def serve_forever(self):
        """Serve DNS requests."""
        while self.running:
            try:
                data, addr = self.recvfrom(512)
                response = self.handle_dns_request(data, addr)
                if response:
                    self.sendto(response, addr)
            except Exception as e:
                if self.running:
                    log.debug(f"DNS serve error: {e}")


# ── HTTP Server ────────────────────────────────────────────────────────────

class PortalHandler(BaseHTTPRequestHandler):
    """HTTP handler for captive portal."""

    portal_config: HTTPPortalConfig = None

    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/cert" and self.portal_config.serve_ca_cert:
            cert_content = self.portal_config.get_ca_cert_content()
            if cert_content:
                self.send_response(200)
                self.send_header("Content-Type", "application/x-x509-ca-cert")
                self.send_header("Content-Length", str(len(cert_content)))
                self.end_headers()
                self.wfile.write(cert_content)
                return

        if self.path in ["/generate_204", "/gen_204", "/hotspot-detect.html", "/success.txt"]:
            self.send_response(204)
            self.end_headers()
            return

        # Redirect to captive portal
        self.send_response(302)
        self.send_header("Location", f"http://{self.portal_config.host_ip}/")
        self.end_headers()

    def do_POST(self):
        """Handle POST (same as GET for this portal)."""
        self.do_GET()

    def log_message(self, format, *args):
        """Suppress default logging."""
        log.debug(format % args)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="NetShaper Captive Portal + DNS Server")
    parser.add_argument("--host-ip", help="Explicit IP to use (auto-detected if omitted)")
    parser.add_argument("--dns-port", type=int, default=53, help="DNS port (default 53)")
    parser.add_argument("--http-port", type=int, default=80, help="HTTP port (default 80)")
    parser.add_argument("--index-file", help="Custom index.html path")
    parser.add_argument("--ca-cert", help="mitmproxy CA cert path")
    parser.add_argument("--serve-ca-cert", action="store_true", help="Serve CA over HTTP")
    parser.add_argument("--spoof-all", action="store_true", help="Spoof all DNS queries")
    parser.add_argument("--smart-spoof-all", action="store_true", help="Spoof non-.local queries")
    parser.add_argument("--dns-upstream", default="8.8.8.8", help="Upstream DNS (default 8.8.8.8)")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[Portal] %(asctime)s - %(levelname)s - %(message)s",
    )

    try:
        # Get own IP
        own_ip = get_own_ip(args.host_ip)
        log.info(f"Using IP: {own_ip}")

        # Create configs
        dns_config = DnsConfig(
            upstream=args.dns_upstream,
            spoof_all=args.spoof_all,
            smart_spoof_all=args.smart_spoof_all,
            verbose=args.verbose,
        )
        http_config = HTTPPortalConfig(
            host_ip=own_ip,
            http_port=args.http_port,
            index_file=args.index_file,
            ca_cert_path=args.ca_cert,
            serve_ca_cert=args.serve_ca_cert,
        )

        # Bind sockets (Phase 1)
        try:
            dns_sock = DNSServer("::", args.dns_port, dns_config)
        except OSError as e:
            raise RuntimeError(f"Cannot bind DNS port {args.dns_port}: {e}") from e

        try:
            PortalHandler.portal_config = http_config
            # Captive portal intentionally listens on all interfaces for clients.
            http_server = HTTPServer(("0.0.0.0", args.http_port), PortalHandler)  # nosec B104
        except OSError as e:
            raise RuntimeError(f"Cannot bind HTTP port {args.http_port}: {e}") from e

        # Drop privileges (Phase 2)
        drop_privileges("nobody")

        # Start servers
        print_flush(bold(cyan("NetShaper Captive Portal + DNS")))
        print_flush(f"  DNS     [::]:{ args.dns_port} (spoof_all={args.spoof_all})")
        print_flush(f"  HTTP    {own_ip}:{args.http_port}")
        print_flush()

        dns_thread = threading.Thread(target=dns_sock.serve_forever, daemon=True)
        dns_thread.start()

        http_server.serve_forever()

    except KeyboardInterrupt:
        log.info("Interrupted")
        sys.exit(0)
    except Exception as e:
        log.error(f"Fatal: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
