"""NetShaper — plugin registry and lifecycle contract.

Provides a minimal, safety-first host for future extensibility.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
import logging
import uuid
from typing import Any, ClassVar, Dict, Type

from netshaper.core.authorization import AuthorizationPolicy
from netshaper.exceptions import NetShaperError

log = logging.getLogger("netshaper")


class PluginError(NetShaperError):
    """Base exception for plugin lifecycle and validation failures."""


class PluginInterface(ABC):
    """Minimal plugin interface for external capability modules."""

    PLUGIN_ID: ClassVar[str]
    PLUGIN_NAME: ClassVar[str]
    SUPPORTED_SCOPE_TYPES: ClassVar[Sequence[str]] = ("cidr", "ip")

    def __init__(
        self,
        instance_id: str,
        scope: dict[str, Any],
        config: dict[str, Any],
        auth_policy: AuthorizationPolicy,
    ) -> None:
        self.instance_id = instance_id
        self.scope = scope
        self.config = config
        self.auth_policy = auth_policy
        self.active = False

    @classmethod
    def validate_scope(
        cls,
        scope: dict[str, Any],
        auth_policy: AuthorizationPolicy,
    ) -> None:
        if not isinstance(scope, dict):
            raise PluginError("plugin scope must be a dictionary")

        scope_type = scope.get("type")
        if scope_type not in cls.SUPPORTED_SCOPE_TYPES:
            raise PluginError(
                f"plugin {cls.PLUGIN_ID} does not support scope type "
                f"{scope_type!r}"
            )

        if scope_type == "cidr":
            cidrs = scope.get("cidrs") or scope.get("cidr")
            if cidrs is None:
                raise PluginError("missing CIDR scope")
            if isinstance(cidrs, str):
                cidrs = [cidrs]
            elif not isinstance(cidrs, (list, tuple)):
                raise PluginError("CIDR scope must be a string or list")
            if not cidrs:
                raise PluginError("CIDR scope must contain at least one CIDR")
            for cidr in cidrs:
                auth_policy.assert_cidr_authorized(str(cidr))
            return

        if scope_type == "ip":
            ip_address = scope.get("ip")
            if not isinstance(ip_address, str):
                raise PluginError("IP scope requires an IP address string")
            auth_policy.assert_target_authorized(ip_address)
            return

        raise PluginError(
            f"plugin {cls.PLUGIN_ID} scope type {scope_type!r} is not supported"
        )

    @classmethod
    def new_instance(
        cls,
        scope: dict[str, Any],
        config: dict[str, Any],
        auth_policy: AuthorizationPolicy,
    ) -> "PluginInterface":
        instance_id = f"{cls.PLUGIN_ID}-{uuid.uuid4().hex[:8]}"
        return cls(instance_id, scope, config, auth_policy)

    @abstractmethod
    def start(self) -> bool:
        """Start the plugin and prepare any runtime resources."""

    @abstractmethod
    def stop(self) -> bool:
        """Stop the plugin and release any runtime resources."""

    def get_state_for_persistence(self) -> dict[str, Any]:
        """Return a JSON-serializable state object for recovery/audit."""
        return {}


class PluginManager:
    """Registry for NetShaper plugin classes."""

    _registry: Dict[str, Type[PluginInterface]] = {}

    @classmethod
    def register(cls, plugin_cls: Type[PluginInterface]) -> Type[PluginInterface]:
        if not issubclass(plugin_cls, PluginInterface):
            raise TypeError("plugin_cls must inherit from PluginInterface")
        plugin_id = getattr(plugin_cls, "PLUGIN_ID", None)
        if not plugin_id or not isinstance(plugin_id, str):
            raise ValueError("plugin_cls must define a string PLUGIN_ID")
        if plugin_id in cls._registry:
            raise ValueError(f"plugin {plugin_id!r} is already registered")
        cls._registry[plugin_id] = plugin_cls
        log.debug("Registered plugin %s", plugin_id)
        return plugin_cls

    @classmethod
    def get(cls, plugin_id: str) -> Type[PluginInterface]:
        if plugin_id not in cls._registry:
            raise PluginError(f"unknown plugin id {plugin_id!r}")
        return cls._registry[plugin_id]

    @classmethod
    def available(cls) -> list[str]:
        return list(cls._registry)


def plugin(cls: Type[PluginInterface]) -> Type[PluginInterface]:
    """Decorator to register a plugin class with the global registry."""
    return PluginManager.register(cls)
