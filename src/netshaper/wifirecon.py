"""Safety-gated wireless reconnaissance planning.

This module deliberately supports passive or read-only wireless inventory flows.
It does not implement frame injection, deauthentication, beacon flooding,
handshake capture, BLE pairing bypass, or BLE packet injection.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class WirelessOperation(str, Enum):
    """Wireless actions that can be evaluated by the safety policy."""

    PASSIVE_WIFI_SCAN = "passive_wifi_scan"
    ACTIVE_BEACON_PROBE = "active_beacon_probe"
    HANDSHAKE_CAPTURE = "handshake_capture"
    WIFI_DEAUTH = "wifi_deauth"
    DEAUTH_FRAME_INJECTION = "deauth_frame_injection"
    BEACON_FLOODING = "beacon_flooding"
    PASSIVE_BLE_DISCOVERY = "passive_ble_discovery"
    BLE_SERVICE_ENUM = "ble_service_enum"
    BLE_PAIR_BYPASS = "ble_pair_bypass"
    BLE_INJECT = "ble_inject"


@dataclass(frozen=True)
class SafetyDecision:
    operation: WirelessOperation
    allowed: bool
    reason: str


@dataclass(frozen=True)
class ReconPlan:
    operation: WirelessOperation
    command: list[str]
    timeout_seconds: int
    requires_root: bool = False
    dry_run_only: bool = False


@dataclass(frozen=True)
class BurstPolicy:
    """Caps for any future authorized lab transmitter integration."""

    max_frames: int = 20
    max_seconds: int = 5

    def cap_frames(self, requested: int) -> int:
        return max(0, min(requested, self.max_frames))

    def cap_seconds(self, requested: int) -> int:
        return max(0, min(requested, self.max_seconds))


class WirelessSafetyPolicy:
    """Allow only low-impact recon plans and reject offensive primitives."""

    _NEVER_SUPPORTED = frozenset(
        {
            WirelessOperation.HANDSHAKE_CAPTURE,
            WirelessOperation.WIFI_DEAUTH,
            WirelessOperation.DEAUTH_FRAME_INJECTION,
            WirelessOperation.BEACON_FLOODING,
            WirelessOperation.BLE_PAIR_BYPASS,
            WirelessOperation.BLE_INJECT,
        }
    )

    _PASSIVE_ALLOWED = frozenset(
        {
            WirelessOperation.PASSIVE_WIFI_SCAN,
            WirelessOperation.PASSIVE_BLE_DISCOVERY,
            WirelessOperation.BLE_SERVICE_ENUM,
        }
    )

    def __init__(self, *, authorized: bool, dry_run: bool = True) -> None:
        self.authorized = authorized
        self.dry_run = dry_run

    def evaluate(self, operation: WirelessOperation) -> SafetyDecision:
        if operation in self._NEVER_SUPPORTED:
            return SafetyDecision(
                operation=operation,
                allowed=False,
                reason=f"{operation.value} is not supported by NetShaper",
            )

        if operation in self._PASSIVE_ALLOWED:
            if not self.authorized:
                return SafetyDecision(
                    operation=operation,
                    allowed=False,
                    reason="authorized lab/client scope is required",
                )
            return SafetyDecision(
                operation=operation,
                allowed=True,
                reason="passive or read-only authorized reconnaissance",
            )

        if operation == WirelessOperation.ACTIVE_BEACON_PROBE:
            if not self.authorized:
                return SafetyDecision(
                    operation=operation,
                    allowed=False,
                    reason="authorized lab/client scope is required",
                )
            if not self.dry_run:
                return SafetyDecision(
                    operation=operation,
                    allowed=False,
                    reason="active beacon probing is dry-run only",
                )
            return SafetyDecision(
                operation=operation,
                allowed=True,
                reason="authorized dry-run planning only",
            )

        return SafetyDecision(operation=operation, allowed=False, reason="unknown operation")


def _positive_timeout(seconds: int) -> int:
    if seconds <= 0:
        raise ValueError("timeout must be positive")
    return seconds


def build_passive_wifi_scan_plan(interface: str, *, seconds: int = 15) -> ReconPlan:
    if not interface:
        raise ValueError("interface is required")
    return ReconPlan(
        operation=WirelessOperation.PASSIVE_WIFI_SCAN,
        command=["iw", "dev", interface, "scan", "passive"],
        timeout_seconds=_positive_timeout(seconds),
    )


def build_passive_ble_discovery_plan(*, seconds: int = 15) -> ReconPlan:
    return ReconPlan(
        operation=WirelessOperation.PASSIVE_BLE_DISCOVERY,
        command=["bluetoothctl", "scan", "on"],
        timeout_seconds=_positive_timeout(seconds),
    )


def build_ble_service_enum_plan(address: str, *, seconds: int = 15) -> ReconPlan:
    if not address:
        raise ValueError("BLE device address is required")
    return ReconPlan(
        operation=WirelessOperation.BLE_SERVICE_ENUM,
        command=["bluetoothctl", "info", address],
        timeout_seconds=_positive_timeout(seconds),
    )
