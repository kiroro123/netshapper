"""Lifecycle manager for the NetShaper DNS + HTTP portal engine."""

from __future__ import annotations

import http.client
import logging
import secrets
import socket
import subprocess  # nosec B404
import sys
import time
from dataclasses import dataclass
from typing import Any, Optional, Sequence

from netshaper import config
from netshaper.system import check_local_port
from netshaper.utils import print_flush

log = logging.getLogger("netshaper")


@dataclass(frozen=True)
class PortalConfig:
    dnssec_mode: str = "off"
    web_security_demo: bool = False
    dns_upstream: str = "8.8.8.8"
    smart_spoof_all: bool = False
    suppress_dnssec: bool = False


class PortalManager:
    """Owns portal process launch, health verification, and shutdown."""

    VALID_DNSSEC_MODES = {"off", "fail-closed", "fail-open", "nxdomain", "timeout"}

    def __init__(self, host_ip: str, authorized_cidrs: Sequence[object]):
        self.host_ip = host_ip
        self.authorized_cidrs = tuple(str(network) for network in authorized_cidrs)
        self.process: Optional[subprocess.Popen[Any]] = None
        self._health_token: Optional[str] = None

    def start(self, portal_config: PortalConfig) -> bool:
        dnssec_mode = portal_config.dnssec_mode
        if dnssec_mode not in self.VALID_DNSSEC_MODES:
            raise ValueError(f"invalid DNSSEC mode: {dnssec_mode}")
        if portal_config.suppress_dnssec and dnssec_mode == "off":
            dnssec_mode = "fail-open"
        if config.DRY_RUN:
            print_flush(
                "[DRY-RUN] Would launch netshaper-portal "
                f"(dnssec={dnssec_mode}, hsts={portal_config.web_security_demo}, "
                f"smart-spoof-all={portal_config.smart_spoof_all})"
            )
            return True

        health_token = self.health_token()
        if self.ready():
            log.info("netshaper-portal already ready for this session")
            return True

        if self.process and self.process.poll() is None:
            log.debug("Waiting for existing netshaper-portal child")
        else:
            dns_claimed = check_local_port(self.host_ip, 53, socket.SOCK_DGRAM)
            http_claimed = check_local_port(self.host_ip, 80)
            if dns_claimed or http_claimed:
                log.error(
                    "Refusing to adopt unverified portal listener "
                    "(dns=%s, http=%s). Stop the existing listener or relaunch "
                    "it with the session health token printed by NetShaper.",
                    dns_claimed,
                    http_claimed,
                )
                return False

            cmd = [
                sys.executable,
                "-m",
                "netshaper.fake_server3",
                "--host-ip",
                self.host_ip,
                "--upstream",
                portal_config.dns_upstream,
                "--health-token",
                health_token,
            ]
            if portal_config.smart_spoof_all:
                cmd.append("--smart-spoof-all")
            if dnssec_mode != "off":
                cmd.extend(["--dnssec-mode", dnssec_mode])
            allowed_cidrs = set(self.authorized_cidrs)
            allowed_cidrs.add(f"{self.host_ip}/32")
            for allowed_cidr in sorted(allowed_cidrs):
                cmd.extend(["--allow-cidr", allowed_cidr])
            if portal_config.web_security_demo:
                cmd.append("--hsts-idn-demo")

            try:
                self.process = subprocess.Popen(  # nosec B603
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError as exc:
                log.error(f"portal launch failed: {exc}")
                return False

        for _ in range(20):
            if self.ready():
                log.info("netshaper-portal ready")
                return True
            if self.process and self.process.poll() is not None:
                log.error(
                    "netshaper-portal exited during startup "
                    f"with code {self.process.returncode}"
                )
                self.stop()
                return False
            time.sleep(0.25)

        log.error("netshaper-portal did not become reachable within 5s")
        self.stop()
        return False

    def health_token(self) -> str:
        if not self._health_token:
            self._health_token = secrets.token_urlsafe(32)
        return self._health_token

    def ready(self) -> bool:
        return self.health_ready(self.health_token())

    def health_ready(self, token: str) -> bool:
        conn: Optional[http.client.HTTPConnection] = None
        try:
            conn = http.client.HTTPConnection(self.host_ip, 80, timeout=1.0)
            conn.request(
                "GET",
                "/_netshaper/health",
                headers={"X-NetShaper-Session": token},
            )
            response = conn.getresponse()
            body = response.read(256).decode("utf-8", errors="replace")
            return (
                response.status == 200
                and response.getheader("X-NetShaper-Session") == token
                and body == token
            )
        except Exception:
            return False
        finally:
            if conn is not None:
                conn.close()

    def stop(self) -> bool:
        if not self.process:
            return True

        ok = True
        try:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            if self.process.poll() is None:
                ok = False
            else:
                log.info("netshaper-portal terminated")
        except Exception as exc:
            ok = False
            log.error(f"portal cleanup failed: {exc}")

        if ok:
            self.process = None
        return ok
