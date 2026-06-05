"""Backend abstractions for real and dry-run operations."""

from __future__ import annotations

import logging
import subprocess

from scapy.all import sendp

log = logging.getLogger("netshaper")


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
