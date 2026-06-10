import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
import uuid
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYTHONPATH = os.pathsep.join([str(PROJECT_ROOT / "src"), str(PROJECT_ROOT)])
SKIP_RC = 77


def tool_missing(tools: list[str]) -> str | None:
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        return "missing tools: " + ", ".join(missing)
    return None


class NetnsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != "linux":
            raise unittest.SkipTest("Linux network namespaces are required")
        if os.geteuid() != 0:
            raise unittest.SkipTest("network namespace integration tests require root")
        missing = tool_missing([
            "ip",
            "iptables",
            "ip6tables",
            "iptables-save",
            "ip6tables-save",
            "iptables-restore",
            "ip6tables-restore",
            "tc",
        ])
        if missing:
            raise unittest.SkipTest(missing)

    def setUp(self):
        suffix = uuid.uuid4().hex[:8]
        self.ns = f"ns-{suffix}"
        self.host_if = f"vh{suffix[:8]}"
        self.ns_if = f"vp{suffix[:8]}"

        self._run(["ip", "netns", "add", self.ns])
        self._run(["ip", "link", "add", self.host_if, "type", "veth",
                   "peer", "name", self.ns_if])
        self._run(["ip", "link", "set", self.ns_if, "netns", self.ns])
        self._run(["ip", "addr", "add", "198.51.100.1/24", "dev", self.host_if])
        self._run(["ip", "link", "set", self.host_if, "up"])
        self._run(["ip", "-n", self.ns, "link", "set", "lo", "up"])
        self._run(["ip", "-n", self.ns, "link", "set", self.ns_if, "up"])
        self._run(["ip", "-n", self.ns, "addr", "add",
                   "198.51.100.2/24", "dev", self.ns_if])
        self._run(["ip", "-n", self.ns, "addr", "add",
                   "2001:db8:100::2/64", "dev", self.ns_if])

    def tearDown(self):
        self._run(["ip", "link", "del", self.host_if], check=False)
        self._run(["ip", "netns", "del", self.ns], check=False)

    def _run(self, args: list[str], *, check: bool = True, env=None):
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        if check and result.returncode != 0:
            self.fail(
                "command failed: "
                + " ".join(args)
                + f"\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    def _run_python_in_ns(self, code: str, *, env: dict[str, str] | None = None):
        merged_env = os.environ.copy()
        merged_env["PYTHONPATH"] = PYTHONPATH
        if env:
            merged_env.update(env)
        result = self._run(
            ["ip", "netns", "exec", self.ns, sys.executable, "-c", code],
            check=False,
            env=merged_env,
        )
        if result.returncode == SKIP_RC:
            reason = result.stdout.strip() or result.stderr.strip() or "namespace test skipped"
            self.skipTest(reason)
        if result.returncode != 0:
            self.fail(
                f"namespace Python failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    def test_real_iptables_and_ip6tables_target_cleanup(self):
        code = f"""
import subprocess
import sys
from netshaper.network.firewall import FirewallManager

SKIP_RC = {SKIP_RC}
iface = {self.ns_if!r}

def run(args):
    return subprocess.run(args, capture_output=True, text=True, check=False)

for args, reason in [
    (["iptables", "-t", "nat", "-S"], "iptables nat table unavailable"),
    (["ip6tables", "-t", "nat", "-S"], "ip6tables nat table unavailable"),
]:
    result = run(args)
    if result.returncode != 0:
        print(reason + ": " + (result.stderr.strip() or result.stdout.strip()))
        raise SystemExit(SKIP_RC)

cases = [
    ("198.51.100.10", "iptables"),
    ("2001:db8:100::10", "ip6tables"),
]

for target, binary in cases:
    fw = FirewallManager(target, iface, session_id="NS-IT-FW")
    assert run([binary, "-t", "mangle", "-S", fw.MANGLE]).returncode == 0
    assert run([binary, "-t", "nat", "-S", fw.NAT]).returncode == 0
    assert fw.add_redirect_rules(dns_spoof=True, http_redirect_port=8080)
    assert fw.add_shaping(target, mark_base=10)
    assert fw.cleanup()
    assert run([binary, "-t", "mangle", "-L", fw.MANGLE]).returncode != 0
    assert run([binary, "-t", "nat", "-L", fw.NAT]).returncode != 0
"""
        self._run_python_in_ns(textwrap.dedent(code))

    def test_real_tc_target_cleanup(self):
        code = f"""
import subprocess
from netshaper.network.shaper import TrafficShaper

iface = {self.ns_if!r}

def run(args):
    return subprocess.run(args, capture_output=True, text=True, check=False)

shaper = TrafficShaper(iface)
shaper.apply_target("198.51.100.10", 1.25, mark_base=10)
qdisc = run(["tc", "qdisc", "show", "dev", iface, "root"]).stdout
classes = run(["tc", "class", "show", "dev", iface]).stdout
filters_v4 = run(["tc", "filter", "show", "dev", iface, "parent", "1:", "protocol", "ip"]).stdout
filters_v6 = run(["tc", "filter", "show", "dev", iface, "parent", "1:", "protocol", "ipv6"]).stdout
assert "qdisc htb 1:" in qdisc
assert "1:10" in classes and "1:20" in classes
assert "1:10" in filters_v4 and "1:20" in filters_v4
assert "1:10" in filters_v6 and "1:20" in filters_v6
assert shaper.cleanup_target(10)
assert shaper.cleanup()
qdisc_after = run(["tc", "qdisc", "show", "dev", iface, "root"]).stdout
assert "qdisc htb 1:" not in qdisc_after
"""
        self._run_python_in_ns(textwrap.dedent(code))

    def test_interrupted_session_recovery_removes_real_resources(self):
        with tempfile.TemporaryDirectory() as state_dir:
            code = f"""
import json
import os
import shutil
import subprocess
import sys

from netshaper import config
from netshaper.core.orchestrator import NetShaper
from netshaper.core.state_manager import StateSnapshotManager
from netshaper.network.firewall import FirewallManager
from netshaper.network.shaper import TrafficShaper

SKIP_RC = {SKIP_RC}
iface = {self.ns_if!r}
state_dir = os.environ["NETSHAPER_STATE_DIR"]
config.STATE_DIR = state_dir
config.DRY_RUN = False

def run(args):
    return subprocess.run(args, capture_output=True, text=True, check=False)

def require_ok(args, reason):
    result = run(args)
    if result.returncode != 0:
        print(reason + ": " + (result.stderr.strip() or result.stdout.strip()))
        raise SystemExit(SKIP_RC)
    return result

for args, reason in [
    (["iptables", "-t", "nat", "-S"], "iptables nat table unavailable"),
    (["ip6tables", "-t", "nat", "-S"], "ip6tables nat table unavailable"),
]:
    require_ok(args, reason)

old_session = "NS-OLDIT"
snapshot = StateSnapshotManager.capture(iface, old_session)
comment = f"netshaper:{{old_session}}:global"
global_records = []
global_binaries = []

for binary in ["iptables", "ip6tables"]:
    if not shutil.which(binary):
        continue
    global_binaries.append(binary)
    for spec in NetShaper._global_firewall_rule_specs(binary, iface, comment):
        result = run(spec["apply"])
        if result.returncode != 0:
            print("global rule unsupported: " + (result.stderr.strip() or result.stdout.strip()))
            raise SystemExit(SKIP_RC)
        global_records.append({{
            "binary": binary,
            "description": spec["description"],
            "delete": spec["delete"],
            "check": spec["check"],
        }})

fw4 = FirewallManager("198.51.100.10", iface, session_id=old_session)
if not fw4.add_redirect_rules(dns_spoof=True, http_redirect_port=8080):
    print("IPv4 redirect rules unavailable")
    raise SystemExit(SKIP_RC)
if not fw4.add_shaping("198.51.100.10", mark_base=10):
    print("IPv4 shaping marks unavailable")
    raise SystemExit(SKIP_RC)

fw6 = FirewallManager("2001:db8:100::10", iface, session_id=old_session)
if not fw6.add_redirect_rules(dns_spoof=True, http_redirect_port=8080):
    print("IPv6 redirect rules unavailable")
    raise SystemExit(SKIP_RC)
if not fw6.add_shaping("2001:db8:100::10", mark_base=30):
    print("IPv6 shaping marks unavailable")
    raise SystemExit(SKIP_RC)

shaper = TrafficShaper(iface)
shaper.apply_target("198.51.100.10", 1.0, mark_base=10)

session_dir = os.path.join(state_dir, old_session)
os.makedirs(session_dir, mode=0o700, exist_ok=True)
state_path = os.path.join(session_dir, "state.json")
with open(state_path, "w", encoding="utf-8") as f:
    json.dump({{
        "session_id": old_session,
        "interface": iface,
        "targets": [
            {{
                "ip": "198.51.100.10",
                "dns": True,
                "limit": 1.0,
                "http_redirect_port": 8080,
                "firewall_rule_comment": fw4._rule_comment,
                "mangle_chain": fw4.MANGLE,
                "nat_chain": fw4.NAT,
            }},
            {{
                "ip": "2001:db8:100::10",
                "dns": True,
                "limit": None,
                "http_redirect_port": 8080,
                "firewall_rule_comment": fw6._rule_comment,
                "mangle_chain": fw6.MANGLE,
                "nat_chain": fw6.NAT,
            }},
        ],
        "gw": "198.51.100.1",
        "own_ip": "198.51.100.2",
        "global_rules_applied": True,
        "global_rule_comment": comment,
        "global_firewall_binaries": global_binaries,
        "global_rules_created": global_records,
        "shaper_base_initialized": True,
        "owner": {{"pid": 999999, "process_start_time": "0"}},
        "snapshot": NetShaper._snapshot_to_dict(snapshot),
    }}, f)

ns = NetShaper.__new__(NetShaper)
ns.interface = iface
ns.session_id = "NS-NEWIT"
ns.state_snapshot = snapshot
assert ns.load_state_and_cleanup()
assert not os.path.exists(state_path)
assert "NS-OLDIT" not in run(["iptables-save"]).stdout
assert "NS-OLDIT" not in run(["ip6tables-save"]).stdout
assert "qdisc htb 1:" not in run(["tc", "qdisc", "show", "dev", iface, "root"]).stdout
"""
            self._run_python_in_ns(
                textwrap.dedent(code),
                env={"NETSHAPER_STATE_DIR": state_dir},
            )


class NetnsLayer2IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != "linux":
            raise unittest.SkipTest("Linux network namespaces are required")
        if os.geteuid() != 0:
            raise unittest.SkipTest("network namespace integration tests require root")
        missing = tool_missing(["ip"])
        if missing:
            raise unittest.SkipTest(missing)
        if importlib.util.find_spec("scapy") is None:
            raise unittest.SkipTest("scapy is required for ARP/NDP integration tests")

    def setUp(self):
        suffix = uuid.uuid4().hex[:6]
        self.bridge = f"br{suffix}"
        self.attacker_ns = f"nsa-{suffix}"
        self.target_ns = f"nst-{suffix}"
        self.router_ns = f"nsr-{suffix}"
        self.attacker_if = f"a{suffix}"
        self.target_if = f"t{suffix}"
        self.router_if = f"r{suffix}"
        self.host_links = [f"ab{suffix}", f"tb{suffix}", f"rb{suffix}"]

        for ns in [self.attacker_ns, self.target_ns, self.router_ns]:
            self._run(["ip", "netns", "add", ns])
        self._run(["ip", "link", "add", self.bridge, "type", "bridge"])
        self._run(["ip", "link", "set", self.bridge, "up"])
        self._add_bridge_peer(self.attacker_ns, self.attacker_if, self.host_links[0])
        self._add_bridge_peer(self.target_ns, self.target_if, self.host_links[1])
        self._add_bridge_peer(self.router_ns, self.router_if, self.host_links[2])
        self._run(["ip", "-n", self.target_ns, "addr", "add",
                   "10.42.0.2/24", "dev", self.target_if])
        self._run(["ip", "-n", self.router_ns, "addr", "add",
                   "10.42.0.1/24", "dev", self.router_if])
        self._run(["ip", "-n", self.target_ns, "addr", "add",
                   "2001:db8:42::2/64", "dev", self.target_if])
        self._run(["ip", "-n", self.router_ns, "addr", "add",
                   "2001:db8:42::1/64", "dev", self.router_if])

    def tearDown(self):
        for ns in [self.attacker_ns, self.target_ns, self.router_ns]:
            self._run(["ip", "netns", "del", ns], check=False)
        self._run(["ip", "link", "del", self.bridge], check=False)

    def _run(self, args: list[str], *, check: bool = True, env=None):
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        if check and result.returncode != 0:
            self.fail(
                "command failed: "
                + " ".join(args)
                + f"\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    def _add_bridge_peer(self, ns: str, ns_if: str, host_if: str):
        self._run(["ip", "link", "add", host_if, "type", "veth",
                   "peer", "name", ns_if])
        self._run(["ip", "link", "set", ns_if, "netns", ns])
        self._run(["ip", "link", "set", host_if, "master", self.bridge])
        self._run(["ip", "link", "set", host_if, "up"])
        self._run(["ip", "-n", ns, "link", "set", "lo", "up"])
        self._run(["ip", "-n", ns, "link", "set", ns_if, "up"])

    def _mac(self, ns: str, iface: str) -> str:
        result = self._run(["ip", "-n", ns, "-o", "link", "show", iface])
        for part in result.stdout.split():
            if part.count(":") == 5 and len(part) == 17:
                return part.lower()
        self.fail(f"could not parse MAC for {ns}/{iface}: {result.stdout}")

    def _run_python_in_attacker_ns(self, code: str):
        env = os.environ.copy()
        env["PYTHONPATH"] = PYTHONPATH
        result = self._run(
            ["ip", "netns", "exec", self.attacker_ns, sys.executable, "-c", code],
            check=False,
            env=env,
        )
        if result.returncode == SKIP_RC:
            self.skipTest(result.stdout.strip() or result.stderr.strip())
        if result.returncode != 0:
            self.fail(
                f"attacker namespace Python failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )

    def _neigh(self, ns: str, *args: str) -> str:
        return self._run(["ip", "-n", ns, *args]).stdout.lower()

    def test_real_arp_and_ndp_shutdown_restore_neighbor_entries(self):
        attacker_mac = self._mac(self.attacker_ns, self.attacker_if)
        target_mac = self._mac(self.target_ns, self.target_if)
        router_mac = self._mac(self.router_ns, self.router_if)

        self._run(["ip", "-n", self.target_ns, "neigh", "replace",
                   "10.42.0.1", "lladdr", attacker_mac,
                   "dev", self.target_if, "nud", "reachable"])
        self._run(["ip", "-n", self.router_ns, "neigh", "replace",
                   "10.42.0.2", "lladdr", attacker_mac,
                   "dev", self.router_if, "nud", "reachable"])
        self._run(["ip", "-n", self.target_ns, "-6", "neigh", "replace",
                   "2001:db8:42::1", "lladdr", attacker_mac,
                   "dev", self.target_if, "nud", "reachable"])
        self._run(["ip", "-n", self.router_ns, "-6", "neigh", "replace",
                   "2001:db8:42::2", "lladdr", attacker_mac,
                   "dev", self.router_if, "nud", "reachable"])

        code = f"""
from types import SimpleNamespace
from netshaper.network.spoofers import ARPSpoofer, NDPSpoofer

session = SimpleNamespace(active=False, is_shutting_down=True)
arp = ARPSpoofer(
    {self.attacker_if!r},
    "10.42.0.2",
    {target_mac!r},
    "10.42.0.1",
    {router_mac!r},
    {attacker_mac!r},
    session,
)
arp.shutdown()
ndp = NDPSpoofer(
    {self.attacker_if!r},
    "2001:db8:42::2",
    {target_mac!r},
    "2001:db8:42::1",
    {router_mac!r},
    {attacker_mac!r},
    session,
)
ndp.shutdown()
"""
        self._run_python_in_attacker_ns(textwrap.dedent(code))

        target_arp = self._neigh(self.target_ns, "neigh", "show",
                                 "10.42.0.1", "dev", self.target_if)
        router_arp = self._neigh(self.router_ns, "neigh", "show",
                                 "10.42.0.2", "dev", self.router_if)
        target_ndp = self._neigh(self.target_ns, "-6", "neigh", "show",
                                 "2001:db8:42::1", "dev", self.target_if)
        router_ndp = self._neigh(self.router_ns, "-6", "neigh", "show",
                                 "2001:db8:42::2", "dev", self.router_if)

        self.assertIn(router_mac, target_arp)
        self.assertIn(target_mac, router_arp)
        self.assertIn(router_mac, target_ndp)
        self.assertIn(target_mac, router_ndp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
