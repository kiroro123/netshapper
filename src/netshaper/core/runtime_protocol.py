"""Typed runtime contract consumed by the session runner."""

from __future__ import annotations

from typing import Protocol

from netshaper.core.authorization import Network
from netshaper.core.session_plan import TargetRef
from netshaper.network.shaper import ShapingProfile


class StopEvent(Protocol):
    def wait(self, timeout: float | None = None) -> bool: ...

    def set(self) -> None: ...


class SessionRuntime(Protocol):
    """Backend operations required to execute a resolved session plan."""

    @property
    def stop_event(self) -> StopEvent: ...

    @property
    def authorized_cidrs(self) -> tuple[Network, ...]: ...

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

    def add_target(
        self,
        target: TargetRef,
        arp_on: bool = True,
        dns_spoof: bool = False,
        captive_portal: bool = False,
        http_redirect_port: int | None = None,
        limit: float | None = None,
        shaping_profile: ShapingProfile | None = None,
        arp_interval: float = 2.0,
        arp_burst: int = 1,
    ) -> None: ...

    def launch_sniffer(
        self,
        target_ips: list[str] | None = None,
        save_pcap: bool = False,
        rolling: bool = False,
        packet_verbose: bool = False,
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
        target_ips: list[str] | None = None,
        *,
        expect_sniffer: bool = False,
        save_pcap: bool = False,
        rolling: bool = False,
    ) -> list[str]: ...

    def cleanup(self) -> None: ...
