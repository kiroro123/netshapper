"""
NetShaper — Authorization policy enforcement.

Validates that target IPs fall within the authorized CIDR allowlist.
Raises typed exceptions on authorization violations.
"""
from __future__ import annotations

import logging
from ipaddress import ip_address, ip_network
from netshaper.exceptions import NetShaperError
from typing import Optional, Sequence

log = logging.getLogger("netshaper")


class AuthorizationError(NetShaperError):
    """Raised when a target IP violates authorization policy."""
    pass


class AuthorizationPolicy:
    """
    Immutable authorization policy based on CIDR allowlist.
    Provides read-only interface to prevent accidental mutation.
    """

    def __init__(self, authorized_cidrs: Sequence):
        """
        Initialize from raw CIDR values (strings or network objects).
        Converts to immutable tuple for thread-safety.

        Args:
            authorized_cidrs: List of strings like "10.0.0.0/8" or network objects

        Raises:
            ValueError: If no CIDRs provided or invalid format
        """
        networks = []
        for token in authorized_cidrs or []:
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
                    networks.append(item)

        if not networks:
            raise ValueError("authorized_cidrs is required before creating NetShaper")

        # Store as immutable tuple
        self._authorized_cidrs: tuple = tuple(networks)

    @property
    def cidrs(self) -> tuple:
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
