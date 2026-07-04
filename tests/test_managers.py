import tempfile
import unittest
from unittest import mock

from netshaper import config
from netshaper.core.authorization import AuthorizationError, AuthorizationPolicy
from netshaper.core.firewall_manager import FirewallManager
from netshaper.core.mitm_manager import MitmProxyManager
from netshaper.core.recovery_manager import RecoveryManager
from netshaper.system import InspectionStatus


class ManagerTests(unittest.TestCase):
    def test_authorization_policy_ok(self):
        policy = AuthorizationPolicy(["10.0.0.0/8"])
        policy.assert_target_authorized("10.1.2.3")

    def test_authorization_policy_outside(self):
        policy = AuthorizationPolicy(["10.0.0.0/8"])
        with self.assertRaises(AuthorizationError):
            policy.assert_target_authorized("192.0.2.1")

    def test_firewall_manager_state_and_remove(self):
        manager = FirewallManager("lo", "TEST")
        state = manager.get_state_for_persistence()
        self.assertIsInstance(state, dict)
        self.assertTrue(manager.remove_global_rules())

    def test_mitm_manager_dry_run(self):
        with mock.patch.object(config, "DRY_RUN", True):
            manager = MitmProxyManager("127.0.0.1")
            self.assertTrue(manager.launch(port=8088, web_port=8083))

    def test_recovery_manager_no_state_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = f"{tmp}/nosuch"
            with mock.patch.object(config, "STATE_DIR", missing):
                manager = RecoveryManager("lo")
                self.assertTrue(manager.recover_stale_state())

    def test_recovery_fails_when_recorded_global_binary_is_missing(self):
        manager = RecoveryManager("eth0")
        state = {
            "global_rules_applied": True,
            "global_firewall_binaries": ["iptables"],
            "global_rule_comment": "netshaper:NS-OLD:global",
        }

        with mock.patch(
            "netshaper.core.recovery_manager.shutil.which",
            return_value=None,
        ):
            self.assertFalse(manager._cleanup_global_rules(state, "eth0"))

    def test_recovery_fails_when_target_input_delete_fails(self):
        manager = RecoveryManager("eth0")
        state = {
            "targets": [{
                "ip": "192.0.2.10",
                "dns": True,
                "http_redirect_port": 8088,
                "mangle_chain": "NS-MNG-TEST",
                "nat_chain": "NS-NAT-TEST",
            }]
        }

        with mock.patch(
            "netshaper.core.recovery_manager.shutil.which",
            return_value="/sbin/iptables",
        ), mock.patch.object(
            manager,
            "_inspect_stale_resource",
            return_value=InspectionStatus.PRESENT,
        ), mock.patch.object(
            manager,
            "_cleanup_target_chain",
            return_value=True,
        ), mock.patch(
            "netshaper.core.recovery_manager.SubprocessRunner.run",
            return_value=False,
        ):
            self.assertFalse(manager._cleanup_target_rules(state, "eth0"))

    def test_recovery_restores_wifi_plugin_managed_mode(self):
        state = {
            "plugins": [{
                "plugin_id": "wifi-recon",
                "active": True,
                "config": {"interface": "wlan0"},
                "state": {"monitor_iface": "wlan0"},
            }]
        }

        with mock.patch(
            "netshaper.core.recovery_manager.shutil.which",
            side_effect=lambda name: f"/sbin/{name}",
        ), mock.patch(
            "netshaper.core.recovery_manager.SubprocessRunner.run",
            return_value=True,
        ) as runner:
            self.assertTrue(RecoveryManager._cleanup_plugins(state))

        self.assertEqual(runner.call_count, 3)
        runner.assert_any_call(
            ["/sbin/iw", "dev", "wlan0", "set", "type", "managed"],
            check=False,
            silent=True,
        )

    def test_recovery_keeps_unknown_active_plugin_manifest(self):
        state = {
            "plugins": [{
                "plugin_id": "custom-plugin",
                "active": True,
            }]
        }

        self.assertFalse(RecoveryManager._cleanup_plugins(state))


if __name__ == "__main__":
    unittest.main()
