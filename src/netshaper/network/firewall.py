"""
NetShaper — per-target iptables/ip6tables chain management.

Each target gets dedicated NS-MNG-{suffix} / NS-NAT-{suffix} chains
so that teardown of one target never touches another's rules.
"""
import logging
import subprocess
from typing import List, Optional

from netshaper.system import SubprocessRunner

log = logging.getLogger("netshaper")

# Maps table → the parent hook chain for both _setup and cleanup.
# Centralised here so _setup() and cleanup() can't drift out of sync.
_TABLE_HOOK: dict = {
    "mangle": "POSTROUTING",
    "nat":    "PREROUTING",
}


class FirewallManager:
    def __init__(self, target_ip: str, interface: str):
        self.target_ip = target_ip
        self.interface = interface
        self._v6       = ':' in target_ip
        suffix         = target_ip.replace(".", "_").replace(":", "_")
        self.MANGLE    = f"NS-MNG-{suffix}"
        self.NAT       = f"NS-NAT-{suffix}"
        # Track which optional rule groups were actually added so cleanup
        # only removes what exists (avoids iptables errors + log noise).
        self._dns_added  = False
        self._http_added = False
        self._http_redirect_port: Optional[int] = None
        self._setup()

    @property
    def _binaries(self) -> List[str]:
        return ["ip6tables"] if self._v6 else ["iptables"]

    def _chain_ok(self, b: str, t: str, c: str) -> bool:
        return subprocess.run(
            [b, "-t", t, "-L", c], capture_output=True).returncode == 0

    def _setup(self) -> None:
        for b in self._binaries:
            for t, c in [("mangle", self.MANGLE), ("nat", self.NAT)]:
                if not self._chain_ok(b, t, c):
                    SubprocessRunner.run([b, "-t", t, "-N", c])
                    hook = _TABLE_HOOK[t]
                    SubprocessRunner.run([b, "-t", t, "-I", hook, "1", "-j", c])

    def add_shaping(self, target_ip: str, mark_base: int = 10) -> None:
        binaries = ["ip6tables"] if ':' in target_ip else ["iptables"]
        for b in binaries:
            SubprocessRunner.run(
                [b, "-t", "mangle", "-A", self.MANGLE,
                 "-d", target_ip, "-j", "MARK", "--set-mark", str(mark_base)],
                silent=True)
            SubprocessRunner.run(
                [b, "-t", "mangle", "-A", self.MANGLE,
                 "-s", target_ip, "-j", "MARK",
                 "--set-mark", str(mark_base + 10)],
                silent=True)

    def add_redirect_rules(self, dns_spoof: bool = False,
                           captive_portal: bool = False,
                           http_redirect_port: Optional[int] = None) -> None:
        for b in self._binaries:
            if dns_spoof:
                for proto in ["udp", "tcp"]:
                    SubprocessRunner.run(
                        [b, "-I", "INPUT", "1",
                         "-i", self.interface, "-s", self.target_ip,
                         "-p", proto, "--dport", "53",
                         "-j", "ACCEPT"],
                        silent=True)
                    SubprocessRunner.run(
                        [b, "-t", "nat", "-A", self.NAT,
                         "-s", self.target_ip, "-p", proto, "--dport", "53",
                         "-j", "REDIRECT", "--to-port", "53"])
                self._dns_added = True

            if http_redirect_port:
                SubprocessRunner.run(
                    [b, "-I", "INPUT", "1",
                     "-i", self.interface, "-s", self.target_ip,
                     "-p", "tcp", "--dport", str(http_redirect_port),
                     "-j", "ACCEPT"],
                    silent=True)
                SubprocessRunner.run(
                    [b, "-t", "nat", "-A", self.NAT,
                     "-s", self.target_ip, "-p", "tcp", "--dport", "80",
                     "-j", "REDIRECT", "--to-port", str(http_redirect_port)])
                self._http_added = True
                self._http_redirect_port = http_redirect_port

        log.info(
            f"Redirect rules applied: DNS={dns_spoof} "
            f"HTTP→{http_redirect_port}")

    def cleanup(self) -> None:
        for b in self._binaries:
            # Flush + delete per-target chains
            for t, c in [("mangle", self.MANGLE), ("nat", self.NAT)]:
                if self._chain_ok(b, t, c):
                    SubprocessRunner.run(
                        [b, "-t", t, "-F", c], check=False, silent=True)
                    hook = _TABLE_HOOK[t]
                    SubprocessRunner.run(
                        [b, "-t", t, "-D", hook, "-j", c],
                        check=False, silent=True)
                    SubprocessRunner.run(
                        [b, "-t", t, "-X", c], check=False, silent=True)

            if self._dns_added:
                for proto in ["udp", "tcp"]:
                    SubprocessRunner.run(
                        [b, "-D", "INPUT",
                         "-i", self.interface, "-s", self.target_ip,
                         "-p", proto, "--dport", "53",
                         "-j", "ACCEPT"],
                        check=False, silent=True)

            if self._http_added and self._http_redirect_port:
                SubprocessRunner.run(
                    [b, "-D", "INPUT",
                     "-i", self.interface, "-s", self.target_ip,
                     "-p", "tcp", "--dport", str(self._http_redirect_port),
                     "-j", "ACCEPT"],
                    check=False, silent=True)
            self._dns_added = False
            self._http_added = False
            self._http_redirect_port = None
