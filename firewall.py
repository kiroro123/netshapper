"""
netshaper.firewall
──────────────────
Per-target iptables / ip6tables chain management.

Each target gets two isolated chains:
  NS-MNG-{suffix}  (mangle table — traffic shaping marks)
  NS-NAT-{suffix}  (nat table   — DNS / HTTP redirects)

Isolation prevents cross-target teardown corruption: removing one target
flushes only its own chains, never touching another target's rules.

Future migration path: replace _binaries / SubprocessRunner calls with
nft expressions when the kernel drops iptables support entirely.
"""

import subprocess
import logging
from typing import List, Optional

from .system import SubprocessRunner

log = logging.getLogger("netshaper")


class FirewallManager:
    def __init__(self, target_ip: str, interface: str):
        self.target_ip = target_ip
        self.interface = interface
        self._v6       = ':' in target_ip
        suffix         = target_ip.replace(".", "_").replace(":", "_")
        self.MANGLE    = f"NS-MNG-{suffix}"
        self.NAT       = f"NS-NAT-{suffix}"
        self._setup()

    # ── Internal helpers ──────────────────────────────────────────────────────

    @property
    def _binaries(self) -> List[str]:
        return ["ip6tables"] if self._v6 else ["iptables"]

    def _chain_ok(self, binary: str, table: str, chain: str) -> bool:
        return (
            subprocess.run(
                [binary, "-t", table, "-L", chain],
                capture_output=True,
            ).returncode == 0
        )

    # ── Chain initialisation ──────────────────────────────────────────────────

    def _setup(self):
        """
        Create per-target mangle and nat chains if they don't already exist,
        then hook them into POSTROUTING / PREROUTING respectively.

        TOCTOU note: _chain_ok + -N is not atomic. A rapid remove/re-add
        cycle could cause both threads to pass _chain_ok before either
        creates the chain. The -N failure is silent (check=False) so the
        subsequent -I will still succeed if the chain was created by the
        other thread. Acceptable in practice; fix with an RLock if needed.
        """
        for b in self._binaries:
            for table, chain in [("mangle", self.MANGLE), ("nat", self.NAT)]:
                if not self._chain_ok(b, table, chain):
                    SubprocessRunner.run([b, "-t", table, "-N", chain],
                                         check=False)
                    hook = "POSTROUTING" if table == "mangle" else "PREROUTING"
                    SubprocessRunner.run(
                        [b, "-t", table, "-I", hook, "1", "-j", chain]
                    )

    # ── Rule addition ─────────────────────────────────────────────────────────

    def add_shaping(self, target_ip: str, mark_base: int = 10):
        """Add MARK rules for downstream and upstream traffic shaping."""
        binaries = ["ip6tables"] if ':' in target_ip else ["iptables"]
        for b in binaries:
            SubprocessRunner.run(
                [b, "-t", "mangle", "-A", self.MANGLE,
                 "-d", target_ip, "-j", "MARK",
                 "--set-mark", str(mark_base)],
                silent=True,
            )
            SubprocessRunner.run(
                [b, "-t", "mangle", "-A", self.MANGLE,
                 "-s", target_ip, "-j", "MARK",
                 "--set-mark", str(mark_base + 10)],
                silent=True,
            )

    def add_redirect_rules(self, dns_spoof: bool = False,
                           captive_portal: bool = False,
                           http_redirect_port: Optional[int] = None):
        """
        Add NAT REDIRECT rules for DNS spoofing and HTTP interception.
        Also inserts FORWARD DROP rules to block real DNS replies reaching
        the target when DNS spoofing is active.
        """
        for b in self._binaries:
            if dns_spoof:
                for proto in ["udp", "tcp"]:
                    SubprocessRunner.run(
                        [b, "-t", "nat", "-A", self.NAT,
                         "-i", self.interface, "-s", self.target_ip,
                         "-p", proto, "--dport", "53",
                         "-j", "REDIRECT", "--to-port", "53"]
                    )
                # Block real DNS replies reaching the target
                for proto in ["udp", "tcp"]:
                    SubprocessRunner.run(
                        [b, "-A", "FORWARD",
                         "-p", proto, "--sport", "53",
                         "-d", self.target_ip, "-j", "DROP"]
                    )

            if http_redirect_port:
                SubprocessRunner.run(
                    [b, "-t", "nat", "-A", self.NAT,
                     "-i", self.interface, "-s", self.target_ip,
                     "-p", "tcp", "--dport", "80",
                     "-j", "REDIRECT",
                     "--to-port", str(http_redirect_port)]
                )

        log.info(
            f"Redirect rules applied: "
            f"DNS={dns_spoof}  HTTP→{http_redirect_port}"
        )

    # ── Teardown ──────────────────────────────────────────────────────────────

    def cleanup(self):
        """
        Flush, detach, and delete both per-target chains.
        Also removes the FORWARD DROP rules added for DNS spoofing.
        All commands run with check=False — partial teardown is acceptable.
        """
        for b in self._binaries:
            for table, chain in [("mangle", self.MANGLE), ("nat", self.NAT)]:
                if self._chain_ok(b, table, chain):
                    SubprocessRunner.run(
                        [b, "-t", table, "-F", chain],
                        check=False, silent=True,
                    )
                    hook = "POSTROUTING" if table == "mangle" else "PREROUTING"
                    SubprocessRunner.run(
                        [b, "-t", table, "-D", hook, "-j", chain],
                        check=False, silent=True,
                    )
                    SubprocessRunner.run(
                        [b, "-t", table, "-X", chain],
                        check=False, silent=True,
                    )
            # Remove DNS FORWARD DROP rules
            for proto in ["udp", "tcp"]:
                SubprocessRunner.run(
                    [b, "-D", "FORWARD",
                     "-p", proto, "--sport", "53",
                     "-d", self.target_ip, "-j", "DROP"],
                    check=False, silent=True,
                )
