"""Tests for the authorized Wi-Fi reconnaissance plugin."""

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from netshaper import config
from netshaper.core.authorization import AuthorizationPolicy
from netshaper.core.plugin import PluginError
from netshaper.plugins.wifi_recon import (
    DiscoveredNetwork,
    TransmissionBudget,
    WifiError,
    WifiReconPlugin,
)


class _PacketBuilder:
    def __truediv__(self, other):
        del other
        return self


def _constructor(**kwargs):
    del kwargs
    return _PacketBuilder()


def _active_scapy():
    return {
        "RadioTap": _constructor,
        "Dot11": _constructor,
        "Dot11ProbeReq": _constructor,
        "Dot11Deauth": _constructor,
        "Dot11Beacon": _constructor,
        "Dot11Elt": _constructor,
        "sendp": mock.Mock(),
    }


class TransmissionBudgetTests(unittest.TestCase):
    def test_budget_never_exceeds_hard_cap(self):
        budget = TransmissionBudget(5)

        self.assertEqual(budget.reserve(3), 3)
        self.assertEqual(budget.reserve(4), 2)
        self.assertEqual(budget.reserve(1), 0)
        self.assertEqual(budget.attempted, 5)

    def test_budget_rejects_unbounded_maximum(self):
        with self.assertRaises(WifiError):
            TransmissionBudget(101)


class WifiScopeValidationTests(unittest.TestCase):
    def setUp(self):
        self.auth = AuthorizationPolicy(["192.0.2.0/24"])

    def test_bssid_scope_requires_unicast_bssid(self):
        WifiReconPlugin.validate_scope(
            {"type": "bssid", "bssids": ["aa:bb:cc:dd:ee:ff"]},
            self.auth,
        )
        with self.assertRaises(PluginError):
            WifiReconPlugin.validate_scope(
                {"type": "bssid", "bssids": ["ff:ff:ff:ff:ff:ff"]},
                self.auth,
            )

    def test_active_scan_requires_essid_allowlist(self):
        with self.assertRaisesRegex(PluginError, "ESSID allowlist"):
            WifiReconPlugin.validate_scope(
                {
                    "type": "bssid",
                    "bssids": ["aa:bb:cc:dd:ee:ff"],
                    "allow_active_scan": True,
                },
                self.auth,
            )

    def test_deauth_requires_specific_bssid_and_client(self):
        with self.assertRaisesRegex(PluginError, "client MAC"):
            WifiReconPlugin.validate_scope(
                {
                    "type": "bssid",
                    "bssids": ["aa:bb:cc:dd:ee:ff"],
                    "allow_deauth_test": True,
                },
                self.auth,
            )

    def test_beacon_tests_require_clearly_marked_lab_essids(self):
        with self.assertRaisesRegex(PluginError, "NETSHAPER-LAB"):
            WifiReconPlugin.validate_scope(
                {
                    "type": "essid",
                    "essids": ["AuthorizedNet"],
                    "allow_beacon_test": True,
                    "test_essids": ["Not-A-Lab-Network"],
                },
                self.auth,
            )

    def test_channels_are_bounded_and_validated(self):
        with self.assertRaisesRegex(PluginError, "channels"):
            WifiReconPlugin.validate_scope(
                {
                    "type": "bssid",
                    "bssids": ["aa:bb:cc:dd:ee:ff"],
                    "channels": [0, 999],
                },
                self.auth,
            )


class WifiReconLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.auth = AuthorizationPolicy(["192.0.2.0/24"])
        self.scope = {
            "type": "bssid",
            "bssids": ["aa:bb:cc:dd:ee:ff"],
        }

    def test_init_uses_safe_channel_defaults(self):
        plugin = WifiReconPlugin("wifi-test", self.scope, {}, self.auth)

        self.assertEqual(plugin.channels, [1, 6, 11])
        self.assertEqual(plugin.max_tx_frames, 50)

    @mock.patch.object(config, "DRY_RUN", True)
    def test_dry_run_does_not_import_scapy_or_touch_radio(self):
        plugin = WifiReconPlugin("wifi-dry", self.scope, {}, self.auth)
        plugin._load_scapy = mock.Mock(side_effect=AssertionError("must not load"))

        self.assertTrue(plugin.start())
        self.assertTrue(plugin.active)
        self.assertTrue(plugin.stop())
        self.assertFalse(plugin.active)

    def test_monitor_mode_uses_the_existing_interface_name(self):
        plugin = WifiReconPlugin(
            "wifi-monitor",
            self.scope,
            {"interface": "wlan0"},
            self.auth,
        )
        plugin._binary = mock.Mock(side_effect=lambda value: f"/sbin/{value}")
        plugin._run = mock.Mock(return_value=True)

        plugin._activate_monitor_mode()

        self.assertEqual(plugin.monitor_iface, "wlan0")
        self.assertIn(
            mock.call(["/sbin/iw", "dev", "wlan0", "set", "type", "monitor"]),
            plugin._run.call_args_list,
        )

    @mock.patch.object(config, "DRY_RUN", False)
    def test_start_cleans_up_when_radio_activation_fails(self):
        plugin = WifiReconPlugin("wifi-fail", self.scope, {}, self.auth)
        plugin._load_scapy = mock.Mock(return_value={"PcapWriter": mock.Mock()})
        plugin._open_capture = mock.Mock()
        plugin._activate_monitor_mode = mock.Mock(side_effect=WifiError("boom"))
        plugin._close_writers = mock.Mock()
        plugin._restore_managed_mode = mock.Mock(return_value=True)

        self.assertFalse(plugin.start())
        plugin._close_writers.assert_called_once()
        plugin._restore_managed_mode.assert_called_once()

    def test_failed_managed_mode_restore_remains_retryable(self):
        plugin = WifiReconPlugin(
            "wifi-restore",
            self.scope,
            {"interface": "wlan0"},
            self.auth,
        )
        plugin._monitor_enabled = True
        plugin._binary = mock.Mock(side_effect=lambda value: f"/sbin/{value}")
        plugin._run = mock.Mock(side_effect=[True, False, True])

        self.assertFalse(plugin._restore_managed_mode())
        self.assertTrue(plugin._monitor_enabled)

    def test_capture_directory_cannot_be_a_system_directory(self):
        plugin = WifiReconPlugin(
            "wifi-system-path",
            self.scope,
            {"capture_dir": "/"},
            self.auth,
        )
        plugin._scapy = {"PcapWriter": mock.Mock()}

        with self.assertRaisesRegex(WifiError, "mode 0700"):
            plugin._open_capture()
        plugin._scapy["PcapWriter"].assert_not_called()

    def test_state_contains_capture_and_transmission_audit(self):
        plugin = WifiReconPlugin("wifi-state", self.scope, {}, self.auth)
        plugin._discovered_networks["aa:bb:cc:dd:ee:ff"] = DiscoveredNetwork(
            bssid="aa:bb:cc:dd:ee:ff",
            essid="Lab",
            band="2.4GHz",
            channel=6,
            signal_dbm=-40,
        )

        state = plugin.get_state_for_persistence()

        self.assertEqual(state["transmission_budget"]["maximum"], 50)
        self.assertEqual(
            state["discovered_networks"][0]["bssid"],
            "aa:bb:cc:dd:ee:ff",
        )


class WifiActiveActionTests(unittest.TestCase):
    def setUp(self):
        self.auth = AuthorizationPolicy(["192.0.2.0/24"])

    def test_probe_requests_are_essid_gated_and_capped(self):
        scope = {
            "type": "mixed",
            "bssids": ["aa:bb:cc:dd:ee:ff"],
            "essids": ["AuthorizedNet"],
            "allow_active_scan": True,
        }
        plugin = WifiReconPlugin(
            "wifi-probe",
            scope,
            {"max_tx_frames": 3, "probe_burst": 5},
            self.auth,
        )
        plugin._scapy = _active_scapy()
        plugin.monitor_iface = "wlan0"
        plugin._source_mac = mock.Mock(return_value="02:00:00:00:00:01")

        self.assertEqual(plugin.send_probe_request("AuthorizedNet", 5), 3)
        self.assertEqual(plugin.send_probe_request("AuthorizedNet", 1), 0)
        plugin._scapy["sendp"].assert_called_once()

    def test_deauth_is_unicast_scoped_and_burst_capped(self):
        scope = {
            "type": "bssid",
            "bssids": ["aa:bb:cc:dd:ee:ff"],
            "client_macs": ["02:11:22:33:44:55"],
            "allow_deauth_test": True,
        }
        plugin = WifiReconPlugin(
            "wifi-deauth",
            scope,
            {"max_tx_frames": 5},
            self.auth,
        )
        plugin._scapy = _active_scapy()
        plugin.monitor_iface = "wlan0"

        self.assertEqual(
            plugin.send_deauth_test(
                "aa:bb:cc:dd:ee:ff",
                "02:11:22:33:44:55",
                frames=99,
            ),
            5,
        )
        self.assertEqual(plugin._tx_audit[0]["action"], "deauth-test")

    def test_beacon_test_is_marked_and_budgeted(self):
        scope = {
            "type": "essid",
            "essids": ["AuthorizedNet"],
            "allow_beacon_test": True,
            "test_essids": [
                "NETSHAPER-LAB-ONE",
                "NETSHAPER-LAB-TWO",
            ],
        }
        plugin = WifiReconPlugin(
            "wifi-beacon",
            scope,
            {"max_tx_frames": 3},
            self.auth,
        )
        plugin._scapy = _active_scapy()
        plugin.monitor_iface = "wlan0"

        self.assertEqual(plugin.send_beacon_test(frames_per_essid=2), 3)
        self.assertEqual(len(plugin._tx_audit), 2)

    def test_configured_deauth_requires_explicit_scope_flag(self):
        scope = {
            "type": "bssid",
            "bssids": ["aa:bb:cc:dd:ee:ff"],
            "client_macs": ["02:11:22:33:44:55"],
        }
        with self.assertRaisesRegex(WifiError, "allow_deauth_test"):
            WifiReconPlugin(
                "wifi-config",
                scope,
                {
                    "deauth_tests": [
                        {
                            "bssid": "aa:bb:cc:dd:ee:ff",
                            "client": "02:11:22:33:44:55",
                        }
                    ]
                },
                self.auth,
            )


class _Dot11:
    pass


class _Beacon:
    pass


class _ProbeResponse:
    pass


class _Auth:
    pass


class _Eapol:
    pass


class _Elt:
    def __init__(self, element_id=0, info=b"AuthorizedNet", payload=None):
        self.ID = element_id
        self.info = info
        self.payload = payload


class _Dot11Fields:
    FCfield = 0
    addr1 = "ff:ff:ff:ff:ff:ff"
    addr2 = "aa:bb:cc:dd:ee:ff"
    addr3 = "aa:bb:cc:dd:ee:ff"


class _CapturedPacket:
    def __init__(self, *, authorized=True, eapol=b"", beacon=True):
        self.dot11 = _Dot11Fields()
        if not authorized:
            self.dot11.addr2 = "02:99:88:77:66:55"
            self.dot11.addr3 = "02:99:88:77:66:55"
        self.elt = _Elt(payload=_Elt(element_id=3, info=b"\x06"))
        self.eapol = eapol
        self.beacon = beacon
        self.dBm_AntSignal = -42

    def haslayer(self, layer):
        if layer is _Dot11:
            return True
        if layer is _Elt:
            return True
        if layer is _Beacon:
            return self.beacon
        if layer is _Eapol:
            return bool(self.eapol)
        return False

    def getlayer(self, layer):
        if layer is _Elt:
            return self.elt
        return None

    def __getitem__(self, layer):
        if layer is _Dot11:
            return self.dot11
        if layer is _Eapol:
            return self.eapol
        raise KeyError(layer)

    def __bytes__(self):
        return b"packet"


def _capture_scapy(writer_factory=mock.Mock):
    return {
        "Dot11": _Dot11,
        "Dot11Beacon": _Beacon,
        "Dot11ProbeResp": _ProbeResponse,
        "Dot11Auth": _Auth,
        "Dot11Elt": _Elt,
        "EAPOL": _Eapol,
        "PcapWriter": writer_factory,
    }


class WifiCaptureTests(unittest.TestCase):
    def setUp(self):
        self.auth = AuthorizationPolicy(["192.0.2.0/24"])
        self.scope = {
            "type": "bssid",
            "bssids": ["aa:bb:cc:dd:ee:ff"],
        }

    def test_only_authorized_frames_reach_capture_writer(self):
        plugin = WifiReconPlugin("wifi-capture", self.scope, {}, self.auth)
        plugin._scapy = _capture_scapy()
        plugin._main_writer = mock.Mock()

        plugin._frame_callback(_CapturedPacket())
        plugin._frame_callback(_CapturedPacket(authorized=False))

        plugin._main_writer.write.assert_called_once()
        network = plugin._discovered_networks["aa:bb:cc:dd:ee:ff"]
        self.assertEqual(network.essid, "AuthorizedNet")
        self.assertEqual(network.channel, 6)
        self.assertEqual(network.signal_dbm, -42)

    def test_eapol_frames_are_written_to_restricted_pcap(self):
        with tempfile.TemporaryDirectory() as capture_dir:
            writer = mock.Mock()

            def writer_factory(path, **kwargs):
                del kwargs
                Path(path).touch()
                return writer

            plugin = WifiReconPlugin(
                "wifi-eapol",
                self.scope,
                {"capture_dir": capture_dir},
                self.auth,
            )
            plugin._scapy = _capture_scapy(writer_factory)
            plugin._main_writer = mock.Mock()
            for index in range(4):
                plugin._frame_callback(_CapturedPacket(eapol=f"frame-{index}".encode()))

            self.assertEqual(
                plugin._discovered_networks["aa:bb:cc:dd:ee:ff"].handshake_status,
                "complete",
            )
            self.assertEqual(writer.write.call_count, 4)
            pcap = Path(plugin.pcap_handshake_files["aa:bb:cc:dd:ee:ff"])
            self.assertTrue(pcap.exists())


if __name__ == "__main__":
    unittest.main()
