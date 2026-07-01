"""Tests for WifiRecon plugin."""
import os
import tempfile
import unittest
from unittest import mock
from datetime import datetime

from netshaper.core.authorization import AuthorizationPolicy, AuthorizationError
from netshaper.plugins.wifi_recon import (
    WifiReconPlugin,
    WifiError,
    DiscoveredNetwork,
)


class WifiScopeValidationTests(unittest.TestCase):
    """Tests for BSSID and ESSID validation."""

    def test_valid_bssid_format(self):
        """Valid BSSID format is accepted."""
        auth = AuthorizationPolicy(["192.0.2.0/24"])
        # Should not raise
        auth._validate_bssid_format("aa:bb:cc:dd:ee:ff")
        auth._validate_bssid_format("AA:BB:CC:DD:EE:FF")
        auth._validate_bssid_format("00:11:22:33:44:55")

    def test_invalid_bssid_format(self):
        """Invalid BSSID formats are rejected."""
        auth = AuthorizationPolicy(["192.0.2.0/24"])
        
        with self.assertRaises(AuthorizationError):
            auth._validate_bssid_format("aa:bb:cc:dd:ee")  # Too short
        
        with self.assertRaises(AuthorizationError):
            auth._validate_bssid_format("gg:gg:gg:gg:gg:gg")  # Invalid hex
        
        with self.assertRaises(AuthorizationError):
            auth._validate_bssid_format("aabbccddeeff")  # No colons

    def test_valid_essid_format(self):
        """Valid ESSID format is accepted."""
        auth = AuthorizationPolicy(["192.0.2.0/24"])
        # Should not raise
        auth._validate_essid_format("LabWiFi")
        auth._validate_essid_format("Test Network")
        auth._validate_essid_format("")  # Empty is valid (hidden)

    def test_essid_exceeds_max_length(self):
        """ESSID > 32 bytes is rejected."""
        auth = AuthorizationPolicy(["192.0.2.0/24"])
        long_essid = "a" * 33
        
        with self.assertRaises(AuthorizationError) as ctx:
            auth._validate_essid_format(long_essid)
        
        self.assertIn("exceeds 32 bytes", str(ctx.exception))

    def test_assert_bssid_authorized(self):
        """BSSID authorization check works."""
        auth = AuthorizationPolicy(["192.0.2.0/24"])
        authorized = ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
        
        # Should not raise
        auth.assert_bssid_authorized("aa:bb:cc:dd:ee:ff", authorized)
        auth.assert_bssid_authorized("AA:BB:CC:DD:EE:FF", authorized)  # Case-insensitive
        
        # Should raise
        with self.assertRaises(AuthorizationError):
            auth.assert_bssid_authorized("99:99:99:99:99:99", authorized)

    def test_assert_essid_authorized(self):
        """ESSID authorization check works."""
        auth = AuthorizationPolicy(["192.0.2.0/24"])
        authorized = ("LabWiFi", "TestNet")
        
        # Should not raise
        auth.assert_essid_authorized("LabWiFi", authorized)
        
        # Should raise
        with self.assertRaises(AuthorizationError):
            auth.assert_essid_authorized("UnauthorizedSSID", authorized)


class WifiReconPluginInitTests(unittest.TestCase):
    """Tests for WifiRecon plugin initialization."""

    def setUp(self) -> None:
        self.auth = AuthorizationPolicy(["192.0.2.0/24"])

    def test_init_with_bssid_scope(self):
        """Plugin initializes with BSSID scope."""
        scope = {
            "type": "bssid",
            "bssids": ["aa:bb:cc:dd:ee:ff"],
            "allow_active_scan": True,
        }
        config = {"interface": "wlan0"}
        
        plugin = WifiReconPlugin(
            "wifi-test-1",
            scope,
            config,
            self.auth
        )
        
        self.assertEqual(plugin.authorized_bssids, ("aa:bb:cc:dd:ee:ff",))
        self.assertTrue(plugin.allow_active_scan)
        self.assertEqual(plugin.interface, "wlan0")

    def test_init_with_essid_scope(self):
        """Plugin initializes with ESSID scope."""
        scope = {
            "type": "essid",
            "essids": ["LabWiFi", "TestNet"],
            "allow_hidden": False,
        }
        config = {}
        
        plugin = WifiReconPlugin(
            "wifi-test-2",
            scope,
            config,
            self.auth
        )
        
        self.assertEqual(plugin.authorized_essids, ("LabWiFi", "TestNet"))
        self.assertFalse(plugin.allow_hidden)

    def test_init_with_invalid_bssid(self):
        """Plugin rejects invalid BSSID format."""
        scope = {
            "type": "bssid",
            "bssids": ["invalid-bssid"],
        }
        config = {}
        
        with self.assertRaises(AuthorizationError):
            WifiReconPlugin("wifi-test-3", scope, config, self.auth)

    def test_default_channels(self):
        """Default channels include 2.4GHz and 5GHz."""
        scope = {"type": "bssid", "bssids": ["aa:bb:cc:dd:ee:ff"]}
        config = {}
        
        plugin = WifiReconPlugin("wifi-test-4", scope, config, self.auth)
        
        # Should include 2.4GHz channels (1-13)
        self.assertIn(1, plugin.channels)
        self.assertIn(13, plugin.channels)
        
        # Should include 5GHz channels (36, 40, ...)
        self.assertIn(36, plugin.channels)
        self.assertIn(165, plugin.channels)


class WifiReconLifecycleTests(unittest.TestCase):
    """Tests for plugin lifecycle (start/stop)."""

    def setUp(self) -> None:
        self.auth = AuthorizationPolicy(["192.0.2.0/24"])
        self.scope = {"type": "bssid", "bssids": ["aa:bb:cc:dd:ee:ff"]}
        self.config = {"interface": "wlan0"}

    @mock.patch("netshaper.config.DRY_RUN", True)
    def test_start_dry_run_no_execution(self, ):
        """Dry-run mode prints commands without executing."""
        plugin = WifiReconPlugin("wifi-dry-1", self.scope, self.config, self.auth)
        
        result = plugin.start()
        
        self.assertTrue(result)
        self.assertTrue(plugin.active)
        # No actual monitor mode activation

    @mock.patch("netshaper.config.DRY_RUN", True)
    def test_stop_dry_run_no_execution(self):
        """Dry-run stop prints commands without executing."""
        plugin = WifiReconPlugin("wifi-dry-2", self.scope, self.config, self.auth)
        plugin.start()
        
        result = plugin.stop()
        
        self.assertTrue(result)
        self.assertFalse(plugin.active)

    @mock.patch("netshaper.plugins.wifi_recon.threading.Thread")
    @mock.patch("netshaper.plugins.wifi_recon.subprocess.run")
    @mock.patch("netshaper.config.DRY_RUN", False)
    def test_start_activates_monitor_mode(self, mock_run, mock_thread):
        """Start activates monitor mode."""
        mock_run.return_value = mock.MagicMock(returncode=0)
        
        plugin = WifiReconPlugin("wifi-live-1", self.scope, self.config, self.auth)
        result = plugin.start()
        
        self.assertTrue(result)
        # Verify subprocess calls for monitor mode
        self.assertTrue(mock_run.called)
        calls = [call[0][0] for call in mock_run.call_args_list]
        self.assertTrue(any("monitor" in str(call) for call in calls))

    def test_state_persistence(self):
        """Plugin state is persisted correctly."""
        plugin = WifiReconPlugin("wifi-persist-1", self.scope, self.config, self.auth)
        
        # Simulate discovered network
        net = DiscoveredNetwork(
            bssid="aa:bb:cc:dd:ee:ff",
            essid="LabWiFi",
            band="2.4GHz",
            channel=6,
            signal_dbm=-45,
            handshake_status="eapol"
        )
        plugin._discovered_networks["aa:bb:cc:dd:ee:ff"] = net
        
        state = plugin.get_state_for_persistence()
        
        self.assertIn("discovered_networks", state)
        self.assertEqual(len(state["discovered_networks"]), 1)
        self.assertEqual(state["discovered_networks"][0]["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(state["discovered_networks"][0]["essid"], "LabWiFi")


class DiscoveredNetworkTests(unittest.TestCase):
    """Tests for DiscoveredNetwork data class."""

    def test_to_dict(self):
        """DiscoveredNetwork serializes to dict."""
        net = DiscoveredNetwork(
            bssid="aa:bb:cc:dd:ee:ff",
            essid="LabWiFi",
            band="2.4GHz",
            channel=6,
            signal_dbm=-45,
            handshake_status="eapol"
        )
        
        d = net.to_dict()
        
        self.assertEqual(d["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(d["essid"], "LabWiFi")
        self.assertEqual(d["channel"], 6)
        self.assertEqual(d["handshake_status"], "eapol")
        self.assertIn("timestamp", d)


class WifiScopeValidationIntegrationTests(unittest.TestCase):
    """Integration tests for scope validation."""

    def setUp(self) -> None:
        self.auth = AuthorizationPolicy(["192.0.2.0/24"])

    def test_mixed_scope(self):
        """Mixed BSSID + ESSID scope works."""
        scope = {
            "type": "mixed",
            "bssids": ["aa:bb:cc:dd:ee:ff"],
            "essids": ["LabWiFi"],
            "allow_active_scan": True,
            "allow_hidden": False,
        }
        config = {}
        
        plugin = WifiReconPlugin("wifi-mixed-1", scope, config, self.auth)
        
        self.assertEqual(plugin.authorized_bssids, ("aa:bb:cc:dd:ee:ff",))
        self.assertEqual(plugin.authorized_essids, ("LabWiFi",))
        self.assertTrue(plugin.allow_active_scan)
        self.assertFalse(plugin.allow_hidden)

    def test_custom_channels(self):
        """Custom channels are parsed from scope."""
        scope = {
            "type": "bssid",
            "bssids": ["aa:bb:cc:dd:ee:ff"],
            "channels": [1, 6, 11],
        }
        config = {}
        
        plugin = WifiReconPlugin("wifi-channels-1", scope, config, self.auth)
        
        self.assertEqual(plugin.channels, [1, 6, 11])

    def test_probe_burst_config(self):
        """Probe burst is configured from config."""
        scope = {"type": "bssid", "bssids": ["aa:bb:cc:dd:ee:ff"]}
        config = {"probe_burst": 3, "probe_interval": 1.5}
        
        plugin = WifiReconPlugin("wifi-burst-1", scope, config, self.auth)
        
        self.assertEqual(plugin.probe_burst, 3)
        self.assertEqual(plugin.probe_interval, 1.5)


if __name__ == "__main__":
    unittest.main()
