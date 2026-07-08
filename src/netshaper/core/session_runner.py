"""Execute resolved NetShaper session plans."""

from __future__ import annotations

from typing import Protocol

from netshaper.core.session_plan import SessionPlan, TargetRef
from netshaper.utils import bold, green, print_flush


class StopEvent(Protocol):
    def wait(self, timeout: float) -> bool: ...

    def set(self) -> None: ...


class NetShaperSessionBackend(Protocol):
    stop_event: StopEvent

    def save_state(self) -> bool: ...

    def _apply_global_rules(self) -> None: ...

    def launch_fake_server(
        self,
        *,
        suppress_dnssec: bool = False,
        dnssec_mode: str = "off",
        web_security_demo: bool = False,
        dns_upstream: str = "8.8.8.8",
        smart_spoof_all: bool = False,
    ) -> bool: ...

    def fake_server_ready(self) -> bool: ...

    def launch_mitmproxy(self, port: int = 8088, web_port: int = 8083) -> bool: ...

    def start_plugin(self, instance_id: str) -> bool: ...

    def add_target(self, target: TargetRef, **target_options: object) -> None: ...

    def launch_sniffer(
        self,
        *,
        target_ips: list[str],
        save_pcap: bool,
        rolling: bool,
        packet_verbose: bool,
    ) -> None: ...

    def start_arp_amplification(
        self,
        *,
        phantom_count: int,
        burst: int,
        interval: float,
        cam_exhaust: int,
    ) -> None: ...

    def start_monitor_thread(self) -> object: ...

    def runtime_health_issues(
        self,
        *,
        expect_sniffer: bool = False,
        expect_monitor: bool = False,
        expected_tcp_ports: list[int] | None = None,
        expected_udp_ports: list[int] | None = None,
    ) -> list[str]: ...

    def runtime_evidence_lines(
        self,
        target_ips: list[str],
        *,
        expect_sniffer: bool = False,
        save_pcap: bool = False,
        rolling: bool = False,
    ) -> list[str]: ...

    def cleanup(self) -> None: ...


class SessionRunner:
    """Runs the plan lifecycle while NetShaper owns low-level operations."""

    def __init__(
        self,
        netshaper: NetShaperSessionBackend,
        *,
        registered_plugins: tuple[tuple[str, str], ...] = (),
    ):
        self.netshaper = netshaper
        self.registered_plugins = registered_plugins

    def execute(self, plan: SessionPlan) -> None:
        try:
            target_ips = list(plan.target_ips)
            self.validate(plan)
            self.prepare(plan)
            self.start_services(plan)
            self.start_targets(plan)
            self.start_observers(plan, target_ips)
            self.verify(plan, target_ips)
            self.monitor(plan)
        finally:
            self.netshaper.cleanup()
            if getattr(self.netshaper, "_cleanup_complete", True):
                print_flush("[+] Teardown complete. Goodbye.")
            else:
                print_flush("[!] Teardown finished with cleanup errors. Check logs.")

    def validate(self, plan: SessionPlan) -> None:
        if not plan.interface:
            raise RuntimeError("Session plan is missing an interface.")
        if not plan.targets:
            raise RuntimeError("Session plan has no targets.")
        if plan.mitm.enabled and plan.mitm.listen_port <= 0:
            raise RuntimeError("mitmproxy listen port must be positive.")
        if plan.mitm.enabled and plan.mitm.web_port <= 0:
            raise RuntimeError("mitmproxy web port must be positive.")
        if (
            self._portal_required(plan)
            and not plan.portal.auto_launch
            and not self.netshaper.fake_server_ready()
        ):
            raise RuntimeError("Required netshaper-portal service is not verified.")
        if plan.mitm.enabled and not plan.mitm.auto_launch:
            raise RuntimeError("mitmproxy is required but was not approved.")

    def prepare(self, plan: SessionPlan) -> None:
        ns = self.netshaper
        if not ns.save_state():
            raise RuntimeError("Could not write recovery state before setup.")
        ns._apply_global_rules()
        if not ns.save_state():
            raise RuntimeError("Could not update recovery state after global rules.")

    def start_services(self, plan: SessionPlan) -> None:
        ns = self.netshaper
        portal_required = self._portal_required(plan)
        if portal_required and not ns.fake_server_ready():
            if not plan.portal.auto_launch:
                raise RuntimeError(
                    "Required netshaper-portal service is not verified."
                )
            if not ns.launch_fake_server(
                suppress_dnssec=plan.dns.dnssec_enabled,
                dnssec_mode=plan.dns.dnssec_mode,
                web_security_demo=plan.portal.hsts_idn_demo,
                dns_upstream=plan.dns.upstream,
                smart_spoof_all=plan.portal.smart_spoof_all,
            ):
                raise RuntimeError("netshaper-portal did not become verified.")

        if plan.mitm.enabled:
            if not plan.mitm.auto_launch:
                raise RuntimeError("mitmproxy is required but was not approved.")
            if not ns.launch_mitmproxy(
                port=plan.mitm.listen_port,
                web_port=plan.mitm.web_port,
            ):
                raise RuntimeError("mitmproxy did not become reachable.")

        for plugin_id, instance_id in self.registered_plugins:
            if ns.start_plugin(instance_id):
                print_flush(f"  [+] Plugin {plugin_id} started ({instance_id})")
            else:
                raise RuntimeError(f"Plugin {plugin_id} failed to start")

        if (portal_required or plan.mitm.enabled or self.registered_plugins) and (
            not ns.save_state()
        ):
            raise RuntimeError("Could not update recovery state after service start.")

    @staticmethod
    def _portal_required(plan: SessionPlan) -> bool:
        return (
            plan.dns.enabled
            or plan.portal.http_redirect_port == 80
            or plan.portal.hsts_idn_demo
        )

    def start_targets(self, plan: SessionPlan) -> None:
        ns = self.netshaper
        for target in plan.targets:
            target_options: dict[str, object] = {
                "arp_on": plan.arp.enabled,
                "dns_spoof": plan.dns.enabled,
                "captive_portal": plan.portal.enabled,
                "http_redirect_port": plan.portal.http_redirect_port,
                "limit": (
                    plan.shaping.bandwidth_mbps if plan.shaping is not None else None
                ),
                "arp_interval": plan.arp.interval,
                "arp_burst": plan.arp.burst,
            }
            if plan.shaping is not None:
                target_options["shaping_profile"] = plan.shaping
            ns.add_target(target, **target_options)
            if not ns.save_state():
                raise RuntimeError(
                    "Could not update recovery state after target setup."
                )

    def start_observers(self, plan: SessionPlan, target_ips: list[str]) -> None:
        ns = self.netshaper
        if plan.capture.enabled:
            ns.launch_sniffer(
                target_ips=target_ips,
                save_pcap=plan.capture.save_pcap,
                rolling=plan.capture.rolling,
                packet_verbose=plan.capture.packet_verbose,
            )

        if plan.arp.amplification_enabled:
            ns.start_arp_amplification(
                phantom_count=plan.arp.amplify,
                burst=plan.arp.amplify_burst,
                interval=plan.arp.amplify_interval,
                cam_exhaust=plan.arp.cam_exhaust,
            )

        if not ns.save_state():
            raise RuntimeError("Could not update recovery state after startup.")

    def verify(self, plan: SessionPlan, target_ips: list[str]) -> None:
        ns = self.netshaper
        expected_tcp_ports = (
            [plan.portal.http_redirect_port] if plan.portal.http_redirect_port else []
        )
        expected_udp_ports = [53] if plan.dns.enabled else []
        ns.start_monitor_thread()
        issues = ns.runtime_health_issues(
            expect_sniffer=plan.capture.enabled,
            expect_monitor=True,
            expected_tcp_ports=expected_tcp_ports,
            expected_udp_ports=expected_udp_ports,
        )
        if issues:
            raise RuntimeError("Startup verification failed: " + "; ".join(issues))

        print_flush(green("[+] Startup verified. Evidence:"))
        for line in ns.runtime_evidence_lines(
            target_ips,
            expect_sniffer=plan.capture.enabled,
            save_pcap=plan.capture.save_pcap,
            rolling=plan.capture.rolling,
        ):
            print_flush(f"    {line}")

    def monitor(self, plan: SessionPlan) -> None:
        ns = self.netshaper
        expected_tcp_ports = (
            [plan.portal.http_redirect_port] if plan.portal.http_redirect_port else []
        )
        expected_udp_ports = [53] if plan.dns.enabled else []
        print_flush(green("[*] Monitoring.") + " Press " + bold("Ctrl+C") + " to stop.")
        while not ns.stop_event.wait(1):
            issues = ns.runtime_health_issues(
                expect_sniffer=plan.capture.enabled,
                expect_monitor=True,
                expected_tcp_ports=expected_tcp_ports,
                expected_udp_ports=expected_udp_ports,
            )
            if issues:
                raise RuntimeError("Runtime health check failed: " + "; ".join(issues))
