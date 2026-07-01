import unittest

from netshaper.wifirecon import (
    BurstPolicy,
    WirelessOperation,
    WirelessSafetyPolicy,
    build_ble_service_enum_plan,
    build_passive_wifi_scan_plan,
)


class WirelessSafetyPolicyTests(unittest.TestCase):
    def test_passive_wifi_scan_is_allowed_with_authorized_scope(self):
        policy = WirelessSafetyPolicy(authorized=True, dry_run=True)

        decision = policy.evaluate(WirelessOperation.PASSIVE_WIFI_SCAN)

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.operation, WirelessOperation.PASSIVE_WIFI_SCAN)
        self.assertIn("passive", decision.reason)

    def test_deauth_and_injection_operations_are_never_supported(self):
        policy = WirelessSafetyPolicy(authorized=True, dry_run=True)

        for operation in (
            WirelessOperation.WIFI_DEAUTH,
            WirelessOperation.DEAUTH_FRAME_INJECTION,
            WirelessOperation.BEACON_FLOODING,
            WirelessOperation.HANDSHAKE_CAPTURE,
            WirelessOperation.BLE_PAIR_BYPASS,
            WirelessOperation.BLE_INJECT,
        ):
            with self.subTest(operation=operation):
                decision = policy.evaluate(operation)
                self.assertFalse(decision.allowed)
                self.assertIn("not supported", decision.reason)

    def test_active_probe_requires_dry_run_and_authorization(self):
        self.assertFalse(
            WirelessSafetyPolicy(authorized=False, dry_run=True)
            .evaluate(WirelessOperation.ACTIVE_BEACON_PROBE)
            .allowed
        )
        self.assertFalse(
            WirelessSafetyPolicy(authorized=True, dry_run=False)
            .evaluate(WirelessOperation.ACTIVE_BEACON_PROBE)
            .allowed
        )
        self.assertTrue(
            WirelessSafetyPolicy(authorized=True, dry_run=True)
            .evaluate(WirelessOperation.ACTIVE_BEACON_PROBE)
            .allowed
        )


class WirelessReconPlanTests(unittest.TestCase):
    def test_passive_wifi_scan_plan_uses_read_only_iw_scan(self):
        plan = build_passive_wifi_scan_plan("wlan0", seconds=10)

        self.assertEqual(plan.operation, WirelessOperation.PASSIVE_WIFI_SCAN)
        self.assertEqual(plan.command, ["iw", "dev", "wlan0", "scan", "passive"])
        self.assertEqual(plan.timeout_seconds, 10)

    def test_ble_service_enum_plan_is_bounded_to_known_device(self):
        plan = build_ble_service_enum_plan("AA:BB:CC:DD:EE:FF", seconds=20)

        self.assertEqual(plan.operation, WirelessOperation.BLE_SERVICE_ENUM)
        self.assertEqual(plan.command, ["bluetoothctl", "info", "AA:BB:CC:DD:EE:FF"])
        self.assertEqual(plan.timeout_seconds, 20)

    def test_burst_policy_caps_transmission_parameters(self):
        policy = BurstPolicy(max_frames=20, max_seconds=5)

        self.assertEqual(policy.cap_frames(100), 20)
        self.assertEqual(policy.cap_seconds(99), 5)
        self.assertEqual(policy.cap_frames(7), 7)
        self.assertEqual(policy.cap_seconds(3), 3)


if __name__ == "__main__":
    unittest.main()
