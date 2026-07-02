"""
NetShaper — Authorization policy enforcement.

Validates that target IPs fall within the authorized CIDR allowlist.
Raises typed exceptions on authorization violations.
"""

from __future__ import annotations

from collections.abc import Sequence
import logging
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from netshaper.exceptions import NetShaperError
from typing import Optional, cast

log = logging.getLogger("netshaper")
Network = IPv4Network | IPv6Network


class AuthorizationError(NetShaperError):
    """Raised when a target IP violates authorization policy."""

    pass


class AuthorizationPolicy:
    """
    Immutable authorization policy based on CIDR allowlist.
    Provides read-only interface to prevent accidental mutation.
    """

    def __init__(self, authorized_cidrs: Sequence[object]):
        """
        Initialize from raw CIDR values (strings or network objects).
        Converts to immutable tuple for thread-safety.

        Args:
            authorized_cidrs: List of strings like "10.0.0.0/8" or network objects

        Raises:
            ValueError: If no CIDRs provided or invalid format
        """
        networks: list[Network] = []
        for token in authorized_cidrs or []:
            raw_items: Sequence[object]
            if isinstance(token, str):
                raw_items = token.split(",")
            else:
                raw_items = [token]

            for item in raw_items:
                if isinstance(item, str):
                    item = item.strip()
                    if not item:
                        continue
                    networks.append(ip_network(item, strict=False))
                else:
                    # Accept ipaddress network objects
                    if not (
                        hasattr(item, "version")
                        and hasattr(item, "network_address")
                        and hasattr(item, "prefixlen")
                    ):
                        raise ValueError(f"invalid authorized CIDR object: {item!r}")
                    networks.append(cast(Network, item))

        if not networks:
            raise ValueError("authorized_cidrs is required before creating NetShaper")

        # Store as immutable tuple
        self._authorized_cidrs: tuple[Network, ...] = tuple(networks)

    @property
    def cidrs(self) -> tuple[Network, ...]:
        """Read-only access to authorized CIDRs."""
        return self._authorized_cidrs

    def assert_target_authorized(
        self,
        raw_ip: str,
        own_ip: Optional[str] = None,
        own_ipv6: Optional[str] = None,
        gateway: Optional[str] = None,
        gateway_ipv6: Optional[str] = None,
    ) -> None:
        """
        Validate that target IP is authorized and not reserved.

        Args:
            raw_ip: IP address to validate
            own_ip, own_ipv6, gateway, gateway_ipv6: Local addresses to reject

        Raises:
            AuthorizationError: If IP is not authorized or is reserved
        """
        try:
            parsed = ip_address(raw_ip)
        except ValueError as exc:
            raise AuthorizationError(f"invalid target IP {raw_ip!r}") from exc

        # Reject reserved addresses
        if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast:
            raise AuthorizationError(f"refusing reserved target address: {parsed}")

        # Reject own/gateway addresses
        local_addresses = {
            ip_address(value)
            for value in (own_ip, own_ipv6, gateway, gateway_ipv6)
            if value
        }
        if parsed in local_addresses:
            raise AuthorizationError(f"refusing own/gateway target address: {parsed}")

        # Check CIDR allowlist
        if not self._authorized_cidrs:
            raise AuthorizationError("authorized_cidrs is empty; refusing target")

        if not any(
            parsed.version == network.version and parsed in network
            for network in self._authorized_cidrs
        ):
            raise AuthorizationError(
                f"target {parsed} is outside authorized CIDR allowlist"
            )

        # Reject network/broadcast addresses
        for network in self._authorized_cidrs:
            if parsed.version != network.version or parsed not in network:
                continue
            if parsed == network.network_address and network.prefixlen < (
                31 if parsed.version == 4 else 127
            ):
                raise AuthorizationError(
                    f"refusing network/broadcast target address: {parsed}"
                )
            if (
                parsed.version == 4
                and parsed == network.broadcast_address
                and network.prefixlen < 31
            ):
                raise AuthorizationError(
                    f"refusing network/broadcast target address: {parsed}"
                )

    def assert_cidr_authorized(self, raw_cidr: str) -> None:
        """Validate that a CIDR scope is within the authorized allowlist."""
        try:
            requested = ip_network(raw_cidr, strict=False)
        except ValueError as exc:
            raise AuthorizationError(f"invalid CIDR scope {raw_cidr!r}") from exc

        # Reject unsupported versions if no matching authorized CIDR exists.
        if not any(
            self._network_is_subnet_of(requested, network)
            for network in self._authorized_cidrs
        ):
            raise AuthorizationError(
                f"CIDR scope {requested} is outside authorized allowlist"
            )

    @staticmethod
    def _network_is_subnet_of(requested: Network, allowed: Network) -> bool:
        if isinstance(requested, IPv4Network):
            return isinstance(allowed, IPv4Network) and requested.subnet_of(allowed)
        return isinstance(allowed, IPv6Network) and requested.subnet_of(allowed)

    @staticmethod
    def _validate_bssid_format(raw_bssid: str) -> None:
        """Validate BSSID (MAC address) format: aa:bb:cc:dd:ee:ff"""
        if not isinstance(raw_bssid, str):
            raise AuthorizationError(
                f"BSSID must be a string, got {type(raw_bssid).__name__}"
            )
        import re

        if not re.match(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$", raw_bssid):
            raise AuthorizationError(
                f"invalid BSSID format {raw_bssid!r}; expected aa:bb:cc:dd:ee:ff"
            )

    @staticmethod
    def _validate_essid_format(raw_essid: str) -> None:
        """Validate ESSID format: UTF-8 string, 0-32 bytes"""
        if not isinstance(raw_essid, str):
            raise AuthorizationError(
                f"ESSID must be a string, got {type(raw_essid).__name__}"
            )
        essid_bytes = raw_essid.encode("utf-8")
        if len(essid_bytes) > 32:
            raise AuthorizationError(
                f"ESSID exceeds 32 bytes: {len(essid_bytes)} bytes"
            )

    def assert_bssid_authorized(
        self,
        raw_bssid: str,
        authorized_bssids: tuple[str, ...],
    ) -> None:
        """Validate that a BSSID is in the authorized allowlist."""
        self._validate_bssid_format(raw_bssid)
        bssid_upper = raw_bssid.upper()
        if not any(b.upper() == bssid_upper for b in authorized_bssids):
            raise AuthorizationError(
                f"BSSID {raw_bssid} is outside authorized allowlist"
            )

    def assert_essid_authorized(
        self,
        raw_essid: str,
        authorized_essids: tuple[str, ...],
    ) -> None:
        """Validate that an ESSID is in the authorized allowlist."""
        self._validate_essid_format(raw_essid)
        if raw_essid not in authorized_essids:
            raise AuthorizationError(
                f"ESSID {raw_essid!r} is outside authorized allowlist"
            )
