"""
NetShaper — per-target iptables/ip6tables chain management.

Each target gets dedicated NS-MNG-{suffix} / NS-NAT-{suffix} chains
so that teardown of one target never touches another's rules.
"""
import hashlib
import logging
import subprocess
from typing import List, Optional

from netshaper import config
from netshaper.system import SubprocessRunner

log = logging.getLogger("netshaper")

# Maps table → the parent hook chain for both _setup and cleanup.
# Centralised here so _setup() and cleanup() can't drift out of sync.
_TABLE_HOOK: dict = {
    "mangle": "POSTROUTING",
    "nat":    "PREROUTING",
}


class FirewallManager:
    def __init__(
            self, target_ip: str, interface: str,
            session_id: Optional[str] = None):
        self.target_ip = target_ip
        self.interface = interface
        self._v6       = ':' in target_ip
        suffix         = self._chain_suffix(target_ip, session_id)
        self.MANGLE    = f"NS-MNG-{suffix}"
        self.NAT       = f"NS-NAT-{suffix}"
        # Track which optional rule groups were actually added so cleanup
        # only removes what exists (avoids iptables errors + log noise).
        self._dns_added  = False
        self._http_added = False
        self._http_redirect_port: Optional[int] = None
        if not self._setup():
            self.cleanup()
            raise RuntimeError(
                f"Failed to create firewall chains for {target_ip}"
            )

    @staticmethod
    def _chain_suffix(target_ip: str, session_id: Optional[str]) -> str:
        if session_id:
            digest = hashlib.sha256(
                f"{session_id}:{target_ip}".encode("utf-8")
            ).hexdigest()[:10].upper()
            return digest
        return target_ip.replace(".", "_").replace(":", "_")

    @property
    def _binaries(self) -> List[str]:
        return ["ip6tables"] if self._v6 else ["iptables"]

    def _chain_ok(self, b: str, t: str, c: str) -> bool:
        if config.DRY_RUN:
            return False
        try:
            return subprocess.run(
                [b, "-t", t, "-L", c],
                capture_output=True,
                check=False,
            ).returncode == 0
        except FileNotFoundError:
            return False

    def _setup(self) -> bool:
        ok = True
        for b in self._binaries:
            for t, c in [("mangle", self.MANGLE), ("nat", self.NAT)]:
                if not self._chain_ok(b, t, c):
                    hook = _TABLE_HOOK[t]
                    created = SubprocessRunner.run(
                        [b, "-t", t, "-N", c],
                        silent=True,
                    )
                    linked = False
                    if created:
                        linked = SubprocessRunner.run(
                            [b, "-t", t, "-I", hook, "1", "-j", c],
                            silent=True,
                        )
                    ok = created and linked and ok
        return ok

    def add_shaping(self, target_ip: str, mark_base: int = 10) -> bool:
        binaries = ["ip6tables"] if ':' in target_ip else ["iptables"]
        ok = True
        for b in binaries:
            ok = SubprocessRunner.run(
                [b, "-t", "mangle", "-A", self.MANGLE,
                 "-d", target_ip, "-j", "MARK", "--set-mark", str(mark_base)],
                silent=True) and ok
            ok = SubprocessRunner.run(
                [b, "-t", "mangle", "-A", self.MANGLE,
                 "-s", target_ip, "-j", "MARK",
                 "--set-mark", str(mark_base + 10)],
                silent=True) and ok
        return ok

    def add_redirect_rules(self, dns_spoof: bool = False,
                           http_redirect_port: Optional[int] = None) -> bool:
        ok = True
        for b in self._binaries:
            if dns_spoof:
                self._dns_added = True
                for proto in ["udp", "tcp"]:
                    ok = SubprocessRunner.run(
                        [b, "-I", "INPUT", "1",
                         "-i", self.interface, "-s", self.target_ip,
                         "-p", proto, "--dport", "53",
                         "-j", "ACCEPT"],
                        silent=True) and ok
                    ok = SubprocessRunner.run(
                        [b, "-t", "nat", "-A", self.NAT,
                         "-s", self.target_ip, "-p", proto, "--dport", "53",
                         "-j", "REDIRECT", "--to-port", "53"],
                        silent=True) and ok

            if http_redirect_port:
                self._http_added = True
                self._http_redirect_port = http_redirect_port
                ok = SubprocessRunner.run(
                    [b, "-I", "INPUT", "1",
                     "-i", self.interface, "-s", self.target_ip,
                     "-p", "tcp", "--dport", str(http_redirect_port),
                     "-j", "ACCEPT"],
                    silent=True) and ok
                ok = SubprocessRunner.run(
                    [b, "-t", "nat", "-A", self.NAT,
                     "-s", self.target_ip, "-p", "tcp", "--dport", "80",
                     "-j", "REDIRECT", "--to-port", str(http_redirect_port)],
                    silent=True) and ok

        log.info(
            f"Redirect rules applied: DNS={dns_spoof} "
            f"HTTP→{http_redirect_port}")
        return ok

    def cleanup(self) -> bool:
        ok = True
        for b in self._binaries:
            # Flush + delete per-target chains
            for t, c in [("mangle", self.MANGLE), ("nat", self.NAT)]:
                if self._chain_ok(b, t, c):
                    ok = SubprocessRunner.run(
                        [b, "-t", t, "-F", c],
                        check=False, silent=True) and ok
                    hook = _TABLE_HOOK[t]
                    ok = SubprocessRunner.run(
                        [b, "-t", t, "-D", hook, "-j", c],
                        check=False, silent=True) and ok
                    ok = SubprocessRunner.run(
                        [b, "-t", t, "-X", c],
                        check=False, silent=True) and ok

            if self._dns_added:
                for proto in ["udp", "tcp"]:
                    ok = SubprocessRunner.run(
                        [b, "-D", "INPUT",
                         "-i", self.interface, "-s", self.target_ip,
                         "-p", proto, "--dport", "53",
                         "-j", "ACCEPT"],
                        check=False, silent=True) and ok

            if self._http_added and self._http_redirect_port:
                ok = SubprocessRunner.run(
                    [b, "-D", "INPUT",
                     "-i", self.interface, "-s", self.target_ip,
                     "-p", "tcp", "--dport", str(self._http_redirect_port),
                     "-j", "ACCEPT"],
                    check=False, silent=True) and ok
            self._dns_added = False
            self._http_added = False
            self._http_redirect_port = None
        return ok
