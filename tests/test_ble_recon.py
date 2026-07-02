"""Tests for passive BLE discovery and GATT auditing."""

import asyncio
import unittest
from unittest import mock

from netshaper import config
from netshaper.core.authorization import AuthorizationPolicy
from netshaper.core.plugin import PluginError
from netshaper.plugins.ble_recon import BleError, BleReconPlugin


class BleScopeTests(unittest.TestCase):
    def setUp(self):
        self.auth = AuthorizationPolicy(["192.0.2.0/24"])

    def test_address_scope_requires_valid_address(self):
        BleReconPlugin.validate_scope(
            {
                "type": "ble-address",
                "addresses": ["AA:BB:CC:DD:EE:FF"],
            },
            self.auth,
        )
        with self.assertRaisesRegex(PluginError, "invalid BLE address"):
            BleReconPlugin.validate_scope(
                {"type": "ble-address", "addresses": ["bad"]},
                self.auth,
            )

    def test_short_service_uuid_is_normalized(self):
        plugin = BleReconPlugin(
            "ble-heart",
            {"type": "ble-service", "service_uuids": ["180d"]},
            {},
            self.auth,
        )

        self.assertEqual(
            plugin.authorized_service_uuids,
            ("0000180d-0000-1000-8000-00805f9b34fb",),
        )
        self.assertIn((0, 0x03, b"\x0d\x18"), plugin.passive_patterns)

    def test_address_only_scope_requires_narrow_passive_pattern(self):
        with self.assertRaisesRegex(BleError, "passive_patterns"):
            BleReconPlugin(
                "ble-address",
                {
                    "type": "ble-address",
                    "addresses": ["AA:BB:CC:DD:EE:FF"],
                },
                {},
                self.auth,
            )

    def test_unpaired_audit_requires_service_enumeration(self):
        with self.assertRaisesRegex(PluginError, "allow_service_enumeration"):
            BleReconPlugin.validate_scope(
                {
                    "type": "ble-address",
                    "addresses": ["AA:BB:CC:DD:EE:FF"],
                    "audit_unpaired_access": True,
                },
                self.auth,
            )


class _Device:
    address = "AA:BB:CC:DD:EE:FF"
    name = "Sensor"


class _Advertisement:
    local_name = "Lab Sensor"
    rssi = -55
    service_uuids = ["180d"]
    manufacturer_data = {76: b"test"}


class BleDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.auth = AuthorizationPolicy(["192.0.2.0/24"])

    @mock.patch.object(config, "DRY_RUN", True)
    def test_dry_run_never_imports_bleak(self):
        plugin = BleReconPlugin(
            "ble-dry",
            {
                "type": "ble-address",
                "addresses": ["AA:BB:CC:DD:EE:FF"],
            },
            {
                "passive_patterns": [
                    {
                        "ad_data_type": 255,
                        "content_hex": "4c00",
                    }
                ]
            },
            self.auth,
        )
        plugin._load_bleak = mock.Mock(side_effect=AssertionError("must not import"))

        self.assertTrue(plugin.start())
        self.assertTrue(plugin.stop())

    def test_passive_callback_stores_only_authorized_devices(self):
        plugin = BleReconPlugin(
            "ble-scan",
            {
                "type": "ble-address",
                "addresses": ["AA:BB:CC:DD:EE:FF"],
            },
            {
                "passive_patterns": [
                    {
                        "ad_data_type": 255,
                        "content_hex": "4c00",
                    }
                ]
            },
            self.auth,
        )

        plugin._detection_callback(_Device(), _Advertisement())
        unauthorized = mock.Mock(
            address="02:11:22:33:44:55",
            name="Other",
        )
        plugin._detection_callback(unauthorized, _Advertisement())

        state = plugin.get_state_for_persistence()
        self.assertTrue(state["passive"])
        self.assertEqual(len(state["devices"]), 1)
        self.assertEqual(state["devices"][0]["name"], "Lab Sensor")
        self.assertEqual(state["devices"][0]["manufacturer_ids"], [76])

    def test_service_scope_authorizes_advertised_uuid(self):
        plugin = BleReconPlugin(
            "ble-service",
            {"type": "ble-service", "service_uuids": ["180d"]},
            {},
            self.auth,
        )

        plugin._detection_callback(_Device(), _Advertisement())

        self.assertIn("aa:bb:cc:dd:ee:ff", plugin._devices)

    def test_linux_scanner_receives_authorized_or_patterns(self):
        captured = {}

        class Scanner:
            def __init__(self, **kwargs):
                captured.update(kwargs)

            async def start(self):
                return None

            async def stop(self):
                return None

        plugin = BleReconPlugin(
            "ble-pattern",
            {"type": "ble-service", "service_uuids": ["180d"]},
            {"scan_timeout": 1},
            self.auth,
        )
        plugin._bleak = {"BleakScanner": Scanner}
        plugin._stop_event.set()

        asyncio.run(plugin._scan_and_enumerate())

        self.assertEqual(captured["scanning_mode"], "passive")
        self.assertEqual(
            captured["bluez"]["or_patterns"],
            plugin.passive_patterns,
        )

    def test_service_serialization_is_read_only_and_scoped(self):
        plugin = BleReconPlugin(
            "ble-enum",
            {
                "type": "ble-service",
                "service_uuids": ["180d"],
                "allow_service_enumeration": True,
                "audit_unpaired_access": True,
            },
            {},
            self.auth,
        )
        allowed = mock.Mock(
            uuid="0000180d-0000-1000-8000-00805f9b34fb",
            description="Heart Rate",
            characteristics=[
                mock.Mock(
                    uuid="00002a37-0000-1000-8000-00805f9b34fb",
                    properties=["notify", "read"],
                )
            ],
        )
        blocked = mock.Mock(
            uuid="0000180f-0000-1000-8000-00805f9b34fb",
            description="Battery",
            characteristics=[],
        )

        services = plugin._serialize_services([allowed, blocked])

        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["description"], "Heart Rate")
        self.assertEqual(
            services[0]["characteristics"][0]["properties"],
            ["notify", "read"],
        )


if __name__ == "__main__":
    unittest.main()
