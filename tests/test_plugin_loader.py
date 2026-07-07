"""Tests for plugin discovery and loading."""

import json
import os
import tempfile
import unittest
from unittest import mock

from netshaper.core.authorization import AuthorizationPolicy
from netshaper.core.plugin import PluginInterface, PluginManager
from netshaper.core.plugin_loader import PluginLoadError, PluginLoader


class DummyPlugin(PluginInterface):
    """Test plugin implementation."""

    PLUGIN_ID = "test-dummy"
    PLUGIN_NAME = "Test Dummy Plugin"

    def start(self) -> bool:
        self.active = True
        return True

    def stop(self) -> bool:
        self.active = False
        return True

    def get_state_for_persistence(self) -> dict[str, object]:
        return {"dummy": True, "active": self.active}


class BuiltinWifiPlugin(DummyPlugin):
    PLUGIN_ID = "wifi-recon"
    PLUGIN_NAME = "Built-in Wi-Fi"


class PluginLoaderDiscoveryTests(unittest.TestCase):
    """Tests for plugin discovery from entry points and filesystem."""

    def test_discover_builtins_loads_shipped_plugins_without_optional_deps(self):
        result = dict(PluginLoader.discover_builtins())

        self.assertIn("wifi-recon", result)
        self.assertIn("ble-recon", result)

    def test_discover_entry_points_empty(self):
        """Empty entry points list returns empty discovery."""
        with mock.patch(
            "netshaper.core.plugin_loader.entry_points",
            return_value={},
        ):
            result = PluginLoader.discover_entry_points()
            self.assertEqual(result, [])

    def test_discover_entry_points_loads_valid_plugin(self):
        """Valid plugin from entry point is discovered."""
        mock_ep = mock.Mock()
        mock_ep.name = "test-ep"
        mock_ep.load.return_value = DummyPlugin

        with mock.patch(
            "netshaper.core.plugin_loader.entry_points",
            return_value={PluginLoader.PLUGIN_ENTRY_POINT: [mock_ep]},
        ):
            result = PluginLoader.discover_entry_points()

        self.assertEqual(len(result), 1)
        plugin_id, plugin_cls = result[0]
        self.assertEqual(plugin_id, "test-dummy")
        self.assertIs(plugin_cls, DummyPlugin)

    def test_discover_entry_points_skips_missing_plugin_id(self):
        """Entry point without PLUGIN_ID is skipped."""

        class BadPlugin(PluginInterface):
            PLUGIN_NAME = "Bad"

            def start(self) -> bool:
                return True

            def stop(self) -> bool:
                return True

        mock_ep = mock.Mock()
        mock_ep.name = "bad-ep"
        mock_ep.load.return_value = BadPlugin

        with mock.patch(
            "netshaper.core.plugin_loader.entry_points",
            return_value={PluginLoader.PLUGIN_ENTRY_POINT: [mock_ep]},
        ):
            result = PluginLoader.discover_entry_points()

        self.assertEqual(result, [])

    def test_discover_entry_points_skips_non_plugin_interface(self):
        """Entry point not inheriting from PluginInterface is skipped."""

        class NotAPlugin:
            PLUGIN_ID = "not-plugin"

        mock_ep = mock.Mock()
        mock_ep.name = "bad-ep"
        mock_ep.load.return_value = NotAPlugin

        with mock.patch(
            "netshaper.core.plugin_loader.entry_points",
            return_value={PluginLoader.PLUGIN_ENTRY_POINT: [mock_ep]},
        ):
            result = PluginLoader.discover_entry_points()

        self.assertEqual(result, [])

    def test_discover_entry_points_handles_load_failure(self):
        """Entry point that fails to load is skipped."""
        mock_ep = mock.Mock()
        mock_ep.name = "broken-ep"
        mock_ep.load.side_effect = ImportError("broken")

        with mock.patch(
            "netshaper.core.plugin_loader.entry_points",
            return_value={PluginLoader.PLUGIN_ENTRY_POINT: [mock_ep]},
        ):
            result = PluginLoader.discover_entry_points()

        self.assertEqual(result, [])

    def test_discover_entry_points_handles_missing_group(self):
        """Missing entry point group returns empty list."""
        with mock.patch(
            "netshaper.core.plugin_loader.entry_points",
            return_value={},
        ):
            result = PluginLoader.discover_entry_points()
            self.assertEqual(result, [])

    def test_discover_filesystem_missing_directory(self):
        """Missing plugin directory returns empty discovery."""
        result = PluginLoader.discover_filesystem("/nonexistent/path")
        self.assertEqual(result, [])

    def test_discover_filesystem_world_writable_dir_raises(self):
        """World-writable plugin directory raises PluginLoadError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Make directory world-writable
            os.chmod(tmpdir, 0o777)

            with self.assertRaises(PluginLoadError) as ctx:
                PluginLoader.discover_filesystem(tmpdir)

            self.assertIn("world-writable", str(ctx.exception))

    def test_discover_filesystem_group_writable_dir_raises(self):
        """Group-writable plugin directory raises PluginLoadError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chmod(tmpdir, 0o775)

            with self.assertRaises(PluginLoadError) as ctx:
                PluginLoader.discover_filesystem(tmpdir)

            self.assertIn("group-writable", str(ctx.exception))

    def test_discover_filesystem_loads_valid_plugin(self):
        """Valid plugin file is discovered."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a valid plugin file
            plugin_code = """
from netshaper.core.plugin import PluginInterface

class TestPlugin(PluginInterface):
    PLUGIN_ID = "fs-test"
    PLUGIN_NAME = "Filesystem Test"

    def start(self):
        return True

    def stop(self):
        return True
"""
            plugin_file = os.path.join(tmpdir, "test_plugin.py")
            with open(plugin_file, "w") as f:
                f.write(plugin_code)

            os.chmod(tmpdir, 0o755)  # Safe: owner rw, group r, other r
            os.chmod(plugin_file, 0o644)
            result = PluginLoader.discover_filesystem(tmpdir)

        self.assertEqual(len(result), 1)
        plugin_id, plugin_cls = result[0]
        self.assertEqual(plugin_id, "fs-test")

    def test_discover_filesystem_skips_world_writable_file(self):
        """World-writable plugin file is skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_code = """
from netshaper.core.plugin import PluginInterface

class TestPlugin(PluginInterface):
    PLUGIN_ID = "fs-bad"
    PLUGIN_NAME = "Filesystem Bad"

    def start(self):
        return True

    def stop(self):
        return True
"""
            plugin_file = os.path.join(tmpdir, "test_plugin.py")
            with open(plugin_file, "w") as f:
                f.write(plugin_code)

            os.chmod(tmpdir, 0o755)
            os.chmod(plugin_file, 0o666)  # World-writable

            result = PluginLoader.discover_filesystem(tmpdir)
            self.assertEqual(result, [])

    def test_discover_filesystem_skips_group_writable_file(self):
        """Group-writable plugin file is skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_code = """
from netshaper.core.plugin import PluginInterface

class TestPlugin(PluginInterface):
    PLUGIN_ID = "fs-bad-group"
    PLUGIN_NAME = "Filesystem Bad Group"

    def start(self):
        return True

    def stop(self):
        return True
"""
            plugin_file = os.path.join(tmpdir, "test_plugin.py")
            with open(plugin_file, "w") as f:
                f.write(plugin_code)

            os.chmod(tmpdir, 0o755)
            os.chmod(plugin_file, 0o664)

            result = PluginLoader.discover_filesystem(tmpdir)
            self.assertEqual(result, [])

    def test_discover_filesystem_skips_missing_plugin_id(self):
        """File without PLUGIN_ID is skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_code = """
from netshaper.core.plugin import PluginInterface

class TestPlugin(PluginInterface):
    PLUGIN_NAME = "No ID"

    def start(self):
        return True

    def stop(self):
        return True
"""
            plugin_file = os.path.join(tmpdir, "test_plugin.py")
            with open(plugin_file, "w") as f:
                f.write(plugin_code)

            os.chmod(tmpdir, 0o755)
            os.chmod(plugin_file, 0o644)

            result = PluginLoader.discover_filesystem(tmpdir)
            self.assertEqual(result, [])

    def test_discover_filesystem_skips_underscore_files(self):
        """Files starting with underscore are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = os.path.join(tmpdir, "_test_plugin.py")
            with open(plugin_file, "w") as f:
                f.write("# test")

            os.chmod(tmpdir, 0o755)
            os.chmod(plugin_file, 0o644)

            result = PluginLoader.discover_filesystem(tmpdir)
            self.assertEqual(result, [])

    def test_discover_filesystem_handles_invalid_module(self):
        """Invalid Python file is skipped gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = os.path.join(tmpdir, "test_plugin.py")
            with open(plugin_file, "w") as f:
                f.write("this is not valid python {{{{")

            os.chmod(tmpdir, 0o755)
            os.chmod(plugin_file, 0o644)

            result = PluginLoader.discover_filesystem(tmpdir)
            self.assertEqual(result, [])


class PluginLoaderRegistrationTests(unittest.TestCase):
    """Tests for plugin registration."""

    def setUp(self) -> None:
        # Clear the plugin registry before each test
        PluginManager._registry.clear()

    def tearDown(self) -> None:
        # Clean up after each test
        PluginManager._registry.clear()

    def test_load_and_register_entry_points(self):
        """load_and_register discovers and registers entry point plugins."""
        mock_ep = mock.Mock()
        mock_ep.name = "test-ep"
        mock_ep.load.return_value = DummyPlugin

        with mock.patch(
            "netshaper.core.plugin_loader.entry_points",
            return_value={PluginLoader.PLUGIN_ENTRY_POINT: [mock_ep]},
        ):
            result = PluginLoader.load_and_register(
                discover_entry_points=True, discover_filesystem=False
            )

        self.assertIn("test-dummy", result)
        self.assertIs(result["test-dummy"], DummyPlugin)
        self.assertIn("test-dummy", PluginManager.available())

    def test_load_and_register_requests_specific_entry_points(self):
        """Only requested entry points are loaded when plugin IDs are supplied."""
        unrelated_ep = mock.Mock()
        unrelated_ep.name = "unrelated-ep"
        unrelated_ep.load.return_value = DummyPlugin

        requested_ep = mock.Mock()
        requested_ep.name = "test-dummy"
        requested_ep.load.return_value = DummyPlugin

        with mock.patch(
            "netshaper.core.plugin_loader.entry_points",
            return_value={
                PluginLoader.PLUGIN_ENTRY_POINT: [unrelated_ep, requested_ep],
            },
        ):
            result = PluginLoader.load_and_register(
                discover_entry_points=True,
                discover_filesystem=False,
                requested_plugin_ids=["test-dummy"],
            )

        self.assertIn("test-dummy", result)
        self.assertIs(result["test-dummy"], DummyPlugin)
        self.assertIn("test-dummy", PluginManager.available())
        unrelated_ep.load.assert_not_called()
        requested_ep.load.assert_called_once()

    def test_builtin_plugin_id_never_loads_colliding_entry_point(self):
        malicious_ep = mock.Mock()
        malicious_ep.name = "wifi-recon"

        with mock.patch(
            "netshaper.core.plugin_loader.PluginLoader.discover_builtins",
            return_value=[("wifi-recon", BuiltinWifiPlugin)],
        ), mock.patch(
            "netshaper.core.plugin_loader.entry_points",
            return_value={PluginLoader.PLUGIN_ENTRY_POINT: [malicious_ep]},
        ):
            result = PluginLoader.load_and_register(
                discover_builtins=True,
                discover_entry_points=True,
                discover_filesystem=False,
                requested_plugin_ids=["wifi-recon"],
            )

        self.assertIs(result["wifi-recon"], BuiltinWifiPlugin)
        malicious_ep.load.assert_not_called()

    def test_load_and_register_requested_entry_points_missing_is_ignored(self):
        """Missing requested entry points do not stop loading other plugins."""
        mock_ep = mock.Mock()
        mock_ep.name = "test-ep"
        mock_ep.load.return_value = DummyPlugin

        with mock.patch(
            "netshaper.core.plugin_loader.entry_points",
            return_value={PluginLoader.PLUGIN_ENTRY_POINT: [mock_ep]},
        ):
            result = PluginLoader.load_and_register(
                discover_entry_points=True,
                discover_filesystem=False,
                requested_plugin_ids=["unknown-plugin"],
            )

        self.assertEqual(result, {})

    def test_load_and_register_builtins(self):
        result = PluginLoader.load_and_register(
            discover_builtins=True,
            discover_entry_points=False,
            discover_filesystem=False,
        )

        self.assertIn("wifi-recon", result)
        self.assertIn("ble-recon", result)
        self.assertIn("wifi-recon", PluginManager.available())

    def test_load_and_register_skips_disabled_discovery(self):
        """Disabled discovery methods are not called."""
        result = PluginLoader.load_and_register(
            discover_entry_points=False, discover_filesystem=False
        )

        self.assertEqual(result, {})

    def test_load_and_register_filesystem_raises_permission_error(self):
        """Filesystem discovery with world-writable dir raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chmod(tmpdir, 0o777)

            with self.assertRaises(PluginLoadError):
                PluginLoader.load_and_register(
                    discover_entry_points=False,
                    discover_filesystem=True,
                    plugin_dir=tmpdir,
                )

    def test_load_and_register_continues_on_duplicate(self):
        """Duplicate plugin IDs log warning but continue."""
        # Register DummyPlugin manually
        PluginManager.register(DummyPlugin)

        mock_ep = mock.Mock()
        mock_ep.name = "test-ep"
        mock_ep.load.return_value = DummyPlugin

        with mock.patch(
            "netshaper.core.plugin_loader.entry_points",
            return_value={PluginLoader.PLUGIN_ENTRY_POINT: [mock_ep]},
        ):
            result = PluginLoader.load_and_register(
                discover_entry_points=True, discover_filesystem=False
            )

        # Should not raise; duplicate is skipped
        self.assertEqual(len(result), 0)


class PluginLoaderConfigTests(unittest.TestCase):
    """Tests for plugin configuration parsing."""

    def test_parse_plugin_config_none_returns_empty(self):
        """No config file returns empty dict."""
        result = PluginLoader.parse_plugin_config(None)
        self.assertEqual(result, {})

    def test_parse_plugin_config_valid_json(self):
        """Valid JSON config is parsed."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            config = {"scan_timeout": 10, "verbose": True}
            json.dump(config, f)
            config_file = f.name

        try:
            result = PluginLoader.parse_plugin_config(config_file)
            self.assertEqual(result, config)
        finally:
            os.unlink(config_file)

    def test_parse_plugin_config_missing_file_raises(self):
        """Missing config file raises PluginLoadError."""
        with self.assertRaises(PluginLoadError) as ctx:
            PluginLoader.parse_plugin_config("/nonexistent/config.json")

        self.assertIn("not found", str(ctx.exception))

    def test_parse_plugin_config_invalid_json_raises(self):
        """Invalid JSON raises PluginLoadError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{")
            config_file = f.name

        try:
            with self.assertRaises(PluginLoadError) as ctx:
                PluginLoader.parse_plugin_config(config_file)

            self.assertIn("invalid JSON", str(ctx.exception))
        finally:
            os.unlink(config_file)

    def test_parse_plugin_config_non_dict_raises(self):
        """Non-dict JSON raises PluginLoadError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([1, 2, 3], f)  # array instead of object
            config_file = f.name

        try:
            with self.assertRaises(PluginLoadError) as ctx:
                PluginLoader.parse_plugin_config(config_file)

            self.assertIn("must be a JSON object", str(ctx.exception))
        finally:
            os.unlink(config_file)

    def test_plugin_specific_settings_split_scope_and_config(self):
        raw = {
            "plugins": {
                "wifi-recon": {
                    "scope": {
                        "type": "bssid",
                        "bssids": ["aa:bb:cc:dd:ee:ff"],
                    },
                    "config": {"interface": "wlan0"},
                }
            }
        }

        scope, config = PluginLoader.settings_for_plugin(
            "wifi-recon",
            raw,
            {"type": "cidr", "cidrs": ["192.0.2.0/24"]},
        )

        self.assertEqual(scope["type"], "bssid")
        self.assertEqual(config, {"interface": "wlan0"})

    def test_flat_config_remains_backward_compatible(self):
        scope, config = PluginLoader.settings_for_plugin(
            "test-dummy",
            {"timeout": 5},
            {"type": "cidr", "cidrs": ["192.0.2.0/24"]},
        )

        self.assertEqual(scope["type"], "cidr")
        self.assertEqual(config, {"timeout": 5})


class PluginLoaderIntegrationTests(unittest.TestCase):
    """Integration tests for plugin loading workflow."""

    def setUp(self) -> None:
        PluginManager._registry.clear()

    def tearDown(self) -> None:
        PluginManager._registry.clear()

    def test_end_to_end_discover_register_instantiate(self):
        """End-to-end: discover, register, validate, instantiate plugin."""
        mock_ep = mock.Mock()
        mock_ep.name = "test-ep"
        mock_ep.load.return_value = DummyPlugin

        with mock.patch(
            "netshaper.core.plugin_loader.entry_points",
            return_value={PluginLoader.PLUGIN_ENTRY_POINT: [mock_ep]},
        ):
            discovered = PluginLoader.load_and_register(
                discover_entry_points=True, discover_filesystem=False
            )

        self.assertIn("test-dummy", discovered)

        # Now validate and instantiate
        auth_policy = AuthorizationPolicy(["192.0.2.0/24"])
        scope = {"type": "cidr", "cidrs": ["192.0.2.0/24"]}
        config = {"timeout": 5}

        plugin_cls = PluginManager.get("test-dummy")
        plugin_cls.validate_scope(scope, auth_policy)

        plugin = plugin_cls.new_instance(scope, config, auth_policy)
        self.assertTrue(plugin.start())
        self.assertTrue(plugin.active)

        state = plugin.get_state_for_persistence()
        self.assertEqual(state, {"dummy": True, "active": True})

        self.assertTrue(plugin.stop())
        self.assertFalse(plugin.active)


if __name__ == "__main__":
    unittest.main()
