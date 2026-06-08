"""
NetShaper — per-target iptables/ip6tables chain management.

Each target gets dedicated NS-MNG-{suffix} / NS-NAT-{suffix} chains
so that teardown of one target never touches another's rules.
"""
import hashlib
import logging
import shutil
import subprocess
from typing import List, Optional, Set, Tuple

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
            session_id: Optional[str] = None,
            auto_setup: bool = True):
        self.target_ip = target_ip
        self.interface = interface
        self.session_id = session_id
        self._v6       = ':' in target_ip
        suffix         = self._chain_suffix(target_ip, session_id)
        self.MANGLE    = f"NS-MNG-{suffix}"
        self.NAT       = f"NS-NAT-{suffix}"
        self._rule_comment = (
            f"netshaper:{session_id}:{target_ip}" if session_id else None
        )
        self._managed_chains: Set[Tuple[str, str, str]] = set()
        self._linked_chains: Set[Tuple[str, str, str]] = set()
        self._created_chains: Set[Tuple[str, str, str]] = set()
        self._dns_input_rules: Set[Tuple[str, str]] = set()
        self._http_input_rules: Set[Tuple[str, int]] = set()
        # Track which optional rule groups were actually added so cleanup
        # only removes what exists (avoids iptables errors + log noise).
        self._dns_added  = False
        self._http_added = False
        self._http_redirect_port: Optional[int] = None
        self._shaping_added = False
        self._shaping_mark_base: Optional[int] = None
        if auto_setup:
            self.setup()

    def setup(self) -> None:
        if not self._setup():
            rollback_ok = self.cleanup()
            message = f"Failed to create firewall chains for {self.target_ip}"
            if not rollback_ok:
                message += "; rollback incomplete"
            raise RuntimeError(message)

    def _comment_args(self) -> List[str]:
        if not self._rule_comment:
            return []
        return ["-m", "comment", "--comment", self._rule_comment]

    def _rule_ok(self, command: List[str]) -> bool:
        if config.DRY_RUN:
            return False
        try:
            return subprocess.run(
                command,
                capture_output=True,
                check=False,
            ).returncode == 0
        except FileNotFoundError:
            return False

    def _input_accept_rule(
            self,
            b: str,
            action: str,
            proto: str,
            port: int) -> List[str]:
        base = [
            "INPUT",
            "-i", self.interface,
            "-s", self.target_ip,
            "-p", proto,
            "--dport", str(port),
            *self._comment_args(),
            "-j", "ACCEPT",
        ]
        if action == "-I":
            return [b, action, "INPUT", "1", *base[1:]]
        return [b, action, *base]

    def _drop_chain_tracking(self, key: Tuple[str, str, str]) -> None:
        self._managed_chains.discard(key)
        self._linked_chains.discard(key)
        self._created_chains.discard(key)

    def _cleanup_chain(self, b: str, t: str, c: str) -> bool:
        key = (b, t, c)
        tracked = (
            key in self._managed_chains
            or key in self._linked_chains
            or key in self._created_chains
        )
        if not tracked:
            return True
        exists = self._chain_ok(b, t, c)
        if not exists:
            self._drop_chain_tracking(key)
            return True
        ok = True
        if key in self._managed_chains:
            ok = SubprocessRunner.run(
                [b, "-t", t, "-F", c],
                check=False, silent=True) and ok
        hook = _TABLE_HOOK[t]
        jump_check = [b, "-t", t, "-C", hook, "-j", c]
        if key in self._linked_chains:
            if self._rule_ok(jump_check):
                if SubprocessRunner.run(
                        [b, "-t", t, "-D", hook, "-j", c],
                        check=False, silent=True):
                    self._linked_chains.discard(key)
                else:
                    ok = False
            else:
                self._linked_chains.discard(key)
        if key not in self._linked_chains:
            if self._chain_ok(b, t, c):
                if SubprocessRunner.run(
                        [b, "-t", t, "-X", c],
                        check=False, silent=True):
                    self._created_chains.discard(key)
                    self._managed_chains.discard(key)
                else:
                    ok = False
            else:
                self._created_chains.discard(key)
                self._managed_chains.discard(key)
        return ok

    def _cleanup_input_rule(
            self,
            b: str,
            proto: str,
            port: int) -> bool:
        check_cmd = self._input_accept_rule(b, "-C", proto, port)
        delete_cmd = self._input_accept_rule(b, "-D", proto, port)
        if not self._rule_ok(check_cmd):
            return True
        return SubprocessRunner.run(
            delete_cmd,
            check=False,
            silent=True,
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

    def _binary_available(self, b: str) -> bool:
        return config.DRY_RUN or shutil.which(b) is not None

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
                self._managed_chains.add((b, t, c))
                if not self._chain_ok(b, t, c):
                    hook = _TABLE_HOOK[t]
                    created = SubprocessRunner.run(
                        [b, "-t", t, "-N", c],
                        silent=True,
                    )
                    linked = False
                    if created:
                        self._created_chains.add((b, t, c))
                        linked = SubprocessRunner.run(
                            [b, "-t", t, "-I", hook, "1", "-j", c],
                            silent=True,
                        )
                        if linked:
                            self._linked_chains.add((b, t, c))
                    ok = created and linked and ok
        return ok

    def add_shaping(self, target_ip: str, mark_base: int = 10) -> bool:
        binaries = ["ip6tables"] if ':' in target_ip else ["iptables"]
        ok = True
        for b in binaries:
            self._shaping_added = True
            self._shaping_mark_base = mark_base
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
                    if SubprocessRunner.run(
                            self._input_accept_rule(b, "-I", proto, 53),
                            silent=True):
                        self._dns_input_rules.add((b, proto))
                    else:
                        ok = False
                    ok = SubprocessRunner.run(
                        [b, "-t", "nat", "-A", self.NAT,
                         "-s", self.target_ip, "-p", proto, "--dport", "53",
                         "-j", "REDIRECT", "--to-port", "53"],
                        silent=True) and ok

            if http_redirect_port:
                self._http_added = True
                self._http_redirect_port = http_redirect_port
                if SubprocessRunner.run(
                        self._input_accept_rule(
                            b, "-I", "tcp", http_redirect_port),
                        silent=True):
                    self._http_input_rules.add((b, http_redirect_port))
                else:
                    ok = False
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
        if not hasattr(self, "_dns_input_rules"):
            self._dns_input_rules = set()
        if not hasattr(self, "_http_input_rules"):
            self._http_input_rules = set()
        for b in self._binaries:
            if not self._binary_available(b):
                has_resources = (
                    any(item[0] == b for item in self._managed_chains)
                    or any(item[0] == b for item in self._linked_chains)
                    or any(item[0] == b for item in self._created_chains)
                    or any(item[0] == b for item in self._dns_input_rules)
                    or any(item[0] == b for item in self._http_input_rules)
                    or self._dns_added
                    or self._http_added
                )
                if has_resources:
                    log.error(
                        f"Cannot clean firewall resources for {self.target_ip}: "
                        f"{b} unavailable"
                    )
                    ok = False
                continue
            for t, c in [("mangle", self.MANGLE), ("nat", self.NAT)]:
                ok = self._cleanup_chain(b, t, c) and ok

            if self._dns_added:
                if not any(item[0] == b for item in self._dns_input_rules):
                    for proto in ["udp", "tcp"]:
                        self._dns_input_rules.add((b, proto))
                for item in list(self._dns_input_rules):
                    rule_binary, proto = item
                    if rule_binary != b:
                        continue
                    if self._cleanup_input_rule(b, proto, 53):
                        self._dns_input_rules.discard(item)
                    else:
                        ok = False

            if self._http_added and self._http_redirect_port:
                if not any(item[0] == b for item in self._http_input_rules):
                    self._http_input_rules.add(
                        (b, self._http_redirect_port))
                for item in list(self._http_input_rules):
                    rule_binary, port = item
                    if rule_binary != b:
                        continue
                    if self._cleanup_input_rule(b, "tcp", port):
                        self._http_input_rules.discard(item)
                    else:
                        ok = False

        if not self._dns_input_rules:
            self._dns_added = False
        if not self._http_input_rules:
            self._http_added = False
            self._http_redirect_port = None
        if ok:
            self._shaping_added = False
            self._shaping_mark_base = None
        return ok
