"""
NetShaper — Plugin loading and discovery.

Handles discovery of plugins via setuptools entry points and filesystem,
validation, and registration with the PluginManager.
"""

from __future__ import annotations

import importlib.util
import importlib
import json
import logging
import os
import stat
import sys
from typing import Any, Dict, List, Optional

try:
    from importlib.metadata import entry_points
except ImportError:
    from importlib_metadata import entry_points  # type: ignore

from netshaper.core.plugin import PluginInterface, PluginManager
from netshaper.exceptions import NetShaperError

log = logging.getLogger("netshaper")


class PluginLoadError(NetShaperError):
    """Raised when plugin discovery or loading fails."""

    pass


class PluginLoader:
    """
    Discovers and loads plugins from entry points and filesystem.
    Validates plugin contract before registration.
    """

    PLUGIN_ENTRY_POINT = "netshaper.plugins"
    DEFAULT_PLUGIN_DIR = "/opt/netshaper-plugins"
    BUILTIN_PLUGINS = {
        "wifi-recon": "netshaper.plugins.wifi_recon:WifiReconPlugin",
        "ble-recon": "netshaper.plugins.ble_recon:BleReconPlugin",
    }

    @staticmethod
    def discover_builtins() -> List[tuple[str, type[PluginInterface]]]:
        """Load the plugins shipped in the NetShaper distribution."""
        discovered: List[tuple[str, type[PluginInterface]]] = []
        for expected_id, target in PluginLoader.BUILTIN_PLUGINS.items():
            module_name, class_name = target.split(":", 1)
            try:
                module = importlib.import_module(module_name)
                plugin_cls = getattr(module, class_name)
                if not isinstance(plugin_cls, type) or not issubclass(
                    plugin_cls, PluginInterface
                ):
                    raise TypeError(f"{target} is not a PluginInterface class")
                plugin_id = getattr(plugin_cls, "PLUGIN_ID", None)
                if plugin_id != expected_id:
                    raise ValueError(
                        f"{target} declares plugin id {plugin_id!r}, "
                        f"expected {expected_id!r}"
                    )
                discovered.append((plugin_id, plugin_cls))
            except Exception as exc:
                log.warning("Failed to load built-in plugin %s: %s", expected_id, exc)
        return discovered

    @staticmethod
    def discover_entry_point(
        plugin_id: str,
    ) -> Optional[tuple[str, type[PluginInterface]]]:
        """Discover a single setuptools entry point by name.

        Returns:
            A (plugin_id, plugin_class) tuple, or None if not found.
        """
        try:
            eps = entry_points()

            # Handle both dict and SelectableGroups API
            group: Any
            if isinstance(eps, dict):
                group = eps.get(PluginLoader.PLUGIN_ENTRY_POINT, [])
                selected = [ep for ep in group if ep.name == plugin_id]
            else:
                group = eps.select(group=PluginLoader.PLUGIN_ENTRY_POINT)
                try:
                    selected = group.select(name=plugin_id)
                except Exception:
                    selected = [ep for ep in group if ep.name == plugin_id]

            for ep in selected:
                try:
                    plugin_cls = ep.load()
                    actual_id = getattr(plugin_cls, "PLUGIN_ID", None)
                    if actual_id != plugin_id:
                        raise PluginLoadError(
                            f"entry point {ep.name!r} declares PLUGIN_ID={actual_id!r}"
                        )
                    if not isinstance(actual_id, str):
                        log.warning(
                            "Skipping entry point %s: missing PLUGIN_ID",
                            ep.name,
                        )
                        continue
                    if not issubclass(plugin_cls, PluginInterface):
                        log.warning(
                            "Skipping entry point %s: does not inherit from PluginInterface",
                            ep.name,
                        )
                        return None
                    log.debug(
                        "Discovered plugin %s from entry point %s",
                        actual_id,
                        ep.name,
                    )
                    return actual_id, plugin_cls
                except Exception as exc:
                    log.warning(
                        "Failed to load requested entry point %s: %s",
                        plugin_id,
                        exc,
                    )
                    return None
        except Exception as exc:
            log.warning("Entry point discovery failed: %s", exc)
        return None

    @staticmethod
    def discover_entry_points(
        blocked_plugin_ids: Optional[set[str]] = None,
    ) -> List[tuple[str, type[PluginInterface]]]:
        """
        Discover plugins registered via setuptools entry points.

        Returns:
            List of (plugin_id, plugin_class) tuples

        Raises:
            PluginLoadError: If entry point discovery fails
        """
        discovered: List[tuple[str, type[PluginInterface]]] = []
        blocked_plugin_ids = blocked_plugin_ids or set()

        try:
            eps = entry_points()

            # Handle both dict and SelectableGroups API
            group: Any
            if isinstance(eps, dict):
                group = eps.get(PluginLoader.PLUGIN_ENTRY_POINT, [])
            else:
                # SelectableGroups API (Python 3.10+)
                group = eps.select(group=PluginLoader.PLUGIN_ENTRY_POINT)

            for ep in group:
                if ep.name in blocked_plugin_ids:
                    log.debug(
                        "Skipping entry point %s: plugin id already resolved",
                        ep.name,
                    )
                    continue
                try:
                    plugin_cls = ep.load()
                    plugin_id = getattr(plugin_cls, "PLUGIN_ID", None)
                    if not plugin_id or not isinstance(plugin_id, str):
                        log.warning(
                            "Skipping entry point %s: missing PLUGIN_ID", ep.name
                        )
                        continue
                    if not issubclass(plugin_cls, PluginInterface):
                        log.warning(
                            "Skipping entry point %s: does not inherit from "
                            "PluginInterface",
                            ep.name,
                        )
                        continue
                    discovered.append((plugin_id, plugin_cls))
                    log.debug(
                        "Discovered plugin %s from entry point %s", plugin_id, ep.name
                    )
                except Exception as exc:
                    log.warning("Failed to load entry point %s: %s", ep.name, exc)
                    continue

        except Exception as exc:
            log.warning("Entry point discovery failed: %s", exc)

        return discovered

    @staticmethod
    def discover_filesystem(
        plugin_dir: str = DEFAULT_PLUGIN_DIR,
    ) -> List[tuple[str, type[PluginInterface]]]:
        """
        Discover plugins from filesystem directory.
        Only loads .py files with secure permissions (owner-writable only).

        Args:
            plugin_dir: Directory to scan for plugin modules

        Returns:
            List of (plugin_id, plugin_class) tuples

        Raises:
            PluginLoadError: If permission checks fail
        """
        discovered: List[tuple[str, type[PluginInterface]]] = []

        if not os.path.isdir(plugin_dir):
            log.debug("Plugin directory does not exist: %s", plugin_dir)
            return discovered

        # Check directory permissions: must not be world-writable
        dir_stat = os.stat(plugin_dir)
        if dir_stat.st_mode & stat.S_IWOTH:
            raise PluginLoadError(
                f"plugin directory {plugin_dir} is world-writable (security risk)"
            )

        for filename in os.listdir(plugin_dir):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue

            module_path = os.path.join(plugin_dir, filename)
            module_name = filename[:-3]  # strip .py

            # Check file permissions: must not be world-writable
            file_stat = os.stat(module_path)
            if file_stat.st_mode & stat.S_IWOTH:
                log.warning(
                    "Skipping plugin %s: file is world-writable (security risk)",
                    filename,
                )
                continue

            try:
                spec = importlib.util.spec_from_file_location(module_name, module_path)
                if spec is None or spec.loader is None:
                    log.warning("Cannot load plugin %s: invalid spec", filename)
                    continue

                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                # Look for PluginInterface subclass in module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if not isinstance(attr, type):
                        continue
                    if not issubclass(attr, PluginInterface):
                        continue
                    if attr is PluginInterface:
                        continue

                    plugin_id = getattr(attr, "PLUGIN_ID", None)
                    if not plugin_id or not isinstance(plugin_id, str):
                        log.warning(
                            "Skipping plugin class %s from %s: missing PLUGIN_ID",
                            attr_name,
                            filename,
                        )
                        continue

                    discovered.append((plugin_id, attr))
                    log.debug(
                        "Discovered plugin %s from filesystem %s", plugin_id, filename
                    )

            except Exception as exc:
                log.warning("Failed to load plugin %s: %s", filename, exc)
                continue

        return discovered

    @staticmethod
    def load_and_register(
        discover_builtins: bool = False,
        discover_entry_points: bool = True,
        discover_filesystem: bool = False,
        plugin_dir: str = DEFAULT_PLUGIN_DIR,
        requested_plugin_ids: Optional[List[str]] = None,
    ) -> Dict[str, type[PluginInterface]]:
        """
        Discover and register all available plugins.

        Args:
            discover_entry_points: If True, discover from setuptools entry points
            discover_filesystem: If True, discover from filesystem directory
            plugin_dir: Directory to scan for filesystem plugins

        Returns:
            Dict of plugin_id -> plugin_class for all registered plugins

        Raises:
            PluginLoadError: If discovery fails critically
        """
        registered: Dict[str, type[PluginInterface]] = {}
        requested = (
            list(dict.fromkeys(requested_plugin_ids))
            if requested_plugin_ids is not None
            else None
        )

        if discover_builtins:
            for plugin_id, plugin_cls in PluginLoader.discover_builtins():
                try:
                    PluginManager.register(plugin_cls)
                    registered[plugin_id] = plugin_cls
                except ValueError as exc:
                    log.debug("Failed to register plugin %s: %s", plugin_id, exc)

        if discover_entry_points:
            try:
                resolved_plugin_ids = set(PluginManager.available())
                if requested is None:
                    entries = PluginLoader.discover_entry_points(
                        blocked_plugin_ids=resolved_plugin_ids,
                    )
                else:
                    entries = []
                    for plugin_id in requested:
                        if plugin_id in resolved_plugin_ids:
                            log.debug(
                                "Skipping entry point %s: plugin id already resolved",
                                plugin_id,
                            )
                            continue
                        entry = PluginLoader.discover_entry_point(plugin_id)
                        if entry is not None:
                            entries.append(entry)
                for plugin_id, plugin_cls in entries:
                    try:
                        PluginManager.register(plugin_cls)
                        registered[plugin_id] = plugin_cls
                    except ValueError as exc:
                        log.debug("Failed to register plugin %s: %s", plugin_id, exc)
                        continue
            except Exception as exc:
                log.error("Entry point discovery failed: %s", exc)

        if discover_filesystem:
            try:
                for plugin_id, plugin_cls in PluginLoader.discover_filesystem(
                    plugin_dir
                ):
                    try:
                        PluginManager.register(plugin_cls)
                        registered[plugin_id] = plugin_cls
                    except ValueError as exc:
                        log.debug("Failed to register plugin %s: %s", plugin_id, exc)
                        continue
            except PluginLoadError as exc:
                log.error("Filesystem discovery failed: %s", exc)
                raise

        log.info("Loaded %d plugin(s)", len(registered))
        return registered

    @staticmethod
    def settings_for_plugin(
        plugin_id: str,
        raw_config: Dict[str, Any],
        default_scope: Dict[str, Any],
    ) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """Return ``(scope, config)`` for one plugin.

        The preferred file shape is::

            {"plugins": {"wifi-recon": {"scope": {...}, "config": {...}}}}

        A flat object remains supported as shared plugin configuration.
        """
        plugins = raw_config.get("plugins")
        if plugins is None:
            return dict(default_scope), dict(raw_config)
        if not isinstance(plugins, dict):
            raise PluginLoadError("'plugins' must be a JSON object")

        settings = plugins.get(plugin_id)
        if settings is None:
            return dict(default_scope), {}
        if not isinstance(settings, dict):
            raise PluginLoadError(f"configuration for {plugin_id!r} must be an object")

        scope = settings.get("scope", default_scope)
        plugin_config = settings.get("config", {})
        if not isinstance(scope, dict):
            raise PluginLoadError(f"scope for {plugin_id!r} must be an object")
        if not isinstance(plugin_config, dict):
            raise PluginLoadError(f"config for {plugin_id!r} must be an object")
        return dict(scope), dict(plugin_config)

    @staticmethod
    def parse_plugin_config(
        config_file: Optional[str],
    ) -> Dict[str, Any]:
        """
        Load plugin configuration from JSON file.

        Args:
            config_file: Path to JSON config file or None for empty config

        Returns:
            Parsed config dict

        Raises:
            PluginLoadError: If config file is invalid
        """
        if not config_file:
            return {}

        if not os.path.isfile(config_file):
            raise PluginLoadError(f"plugin config file not found: {config_file}")

        try:
            with open(config_file, encoding="utf-8") as f:
                config_dict = json.load(f)
            if not isinstance(config_dict, dict):
                raise PluginLoadError(
                    f"plugin config must be a JSON object, got {type(config_dict).__name__}"
                )
            return config_dict
        except json.JSONDecodeError as exc:
            raise PluginLoadError(f"plugin config file is invalid JSON: {exc}") from exc
