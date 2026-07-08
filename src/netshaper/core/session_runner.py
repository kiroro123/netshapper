"""Execute resolved NetShaper session plans."""

from __future__ import annotations

from typing import Any

from netshaper.core.session_plan import SessionPlan
from netshaper.utils import bold, green, print_flush


class SessionRunner:
    """Runs the plan lifecycle while NetShaper owns low-level operations."""

    def __init__(self, netshaper: Any):
        self.netshaper = netshaper

    def execute(self, plan: SessionPlan) -> None:
        try:
            target_ips = list(plan.target_ips)
            self.prepare(plan)
            self.start(plan, target_ips)
            self.verify(plan, target_ips)
            self.monitor(plan)
        finally:
            self.netshaper.cleanup()
            if getattr(self.netshaper, "_cleanup_complete", True):
                print_flush("[+] Teardown complete. Goodbye.")
            else:
                print_flush("[!] Teardown finished with cleanup errors. Check logs.")

    def prepare(self, plan: SessionPlan) -> None:
        ns = self.netshaper
        if not ns.save_state():
            raise RuntimeError("Could not write recovery state before setup.")
        ns._apply_global_rules()
        if not ns.save_state():
            raise RuntimeError("Could not update recovery state after global rules.")
        for target in plan.targets:
            target_options: dict[str, Any] = {
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

    def start(self, plan: SessionPlan, target_ips: list[str]) -> None:
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
