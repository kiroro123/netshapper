"""Backend abstractions for real and dry-run operations."""

from __future__ import annotations

import logging
import subprocess

log = logging.getLogger("netshaper")


def sendp(packet, iface: str, verbose: bool = False) -> None:
    """Lazy Scapy wrapper so importing this module does not touch raw sockets."""
    from scapy.all import sendp as scapy_sendp

    scapy_sendp(packet, iface=iface, verbose=verbose)


class CommandBackend:
    def run(self, command: list[str]) -> None:
        raise NotImplementedError


class RealCommandBackend(CommandBackend):
    def run(self, command: list[str]) -> None:
        subprocess.run(command, check=False)


class DryRunCommandBackend(CommandBackend):
    def run(self, command: list[str]) -> None:
        log.info("[DRY-RUN] Would run: %s", " ".join(command))


class PacketBackend:
    def send(self, packet, interface: str) -> None:
        raise NotImplementedError


class RealPacketBackend(PacketBackend):
    def send(self, packet, interface: str) -> None:
        sendp(packet, iface=interface, verbose=False)


class DryRunPacketBackend(PacketBackend):
    def send(self, packet, interface: str) -> None:
        log.info("[DRY-RUN] Would send packet on %s", interface)
