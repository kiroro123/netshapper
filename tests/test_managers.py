import tempfile
import unittest
from unittest import mock

from netshaper import config
from netshaper.core.authorization import AuthorizationError, AuthorizationPolicy
from netshaper.core.firewall_manager import FirewallManager
from netshaper.core.mitm_manager import MitmProxyManager
from netshaper.core.recovery_manager import RecoveryManager


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


if __name__ == "__main__":
    unittest.main()
