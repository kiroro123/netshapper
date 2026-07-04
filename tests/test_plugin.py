import unittest
from ipaddress import ip_network
from unittest import mock

from netshaper.core.authorization import AuthorizationPolicy
from netshaper.core.orchestrator import NetShaper
from netshaper.core.plugin import PluginInterface, PluginManager, plugin


class DummyPlugin(PluginInterface):
    PLUGIN_ID = "dummy"
    PLUGIN_NAME = "Dummy Plugin"

    def start(self) -> bool:
        self.active = True
        return True

    def stop(self) -> bool:
        self.active = False
        return True

    def get_state_for_persistence(self) -> dict[str, object]:
        return {"dummy": True}


@plugin
class RegisteredDummyPlugin(DummyPlugin):
    pass


class PluginManagerTests(unittest.TestCase):
    def test_register_duplicate_plugin_fails(self):
        with self.assertRaises(ValueError):
            PluginManager.register(RegisteredDummyPlugin)


class NetShaperPluginTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ns = NetShaper.__new__(NetShaper)
        self.ns._auth_policy = AuthorizationPolicy(["192.0.2.0/24"])
        self.ns._lifecycle_lock = mock.Mock()
        self.ns.sessions = {}
        self.ns.plugins = {}
        self.ns._active_cleanup_attempted = False
        self.ns.session_id = "NS-TEST"
        self.ns.interface = "eth0"
        self.ns._owner_metadata = {}
        self.ns.state_snapshot = mock.Mock()
        self.ns.shaper = mock.Mock()
        self.ns.firewall_manager = mock.Mock()
        self.ns._sync_firewall_state = mock.Mock()
        self.ns._state_path = mock.Mock(return_value="/tmp/state.json")
        self.ns.gw = "192.0.2.254"
        self.ns.own_ip = "192.0.2.1"
        self.ns._own_ipv6 = None
        self.ns.save_state = mock.Mock(return_value=True)

    def test_register_and_start_plugin(self):
        plugin_id = self.ns.register_plugin(
            "dummy",
            {"type": "cidr", "cidr": "192.0.2.0/24"},
            config={"foo": "bar"},
        )
        self.assertIn(plugin_id, self.ns.plugins)
        self.assertTrue(self.ns.start_plugin(plugin_id))
        self.assertTrue(self.ns.plugins[plugin_id].active)

    def test_stop_plugin_removes_plugin(self):
        plugin_id = self.ns.register_plugin(
            "dummy",
            {"type": "cidr", "cidr": "192.0.2.0/24"},
        )
        self.ns.start_plugin(plugin_id)
        self.assertTrue(self.ns.stop_plugin(plugin_id))
        self.assertNotIn(plugin_id, self.ns.plugins)

    def test_save_state_includes_plugin(self):
        plugin_id = self.ns.register_plugin(
            "dummy",
            {"type": "cidr", "cidr": "192.0.2.0/24"},
        )
        self.ns.plugins[plugin_id].active = True
        self.ns.save_state = mock.Mock(return_value=True)

        state = self.ns.plugins[plugin_id].get_state_for_persistence()
        self.assertEqual(state, {"dummy": True})

        self.ns.save_state.assert_not_called()
        self.ns.plugins[plugin_id].get_state_for_persistence()

    def test_start_plugin_rolls_back_when_final_state_save_fails(self):
        plugin_id = self.ns.register_plugin(
            "dummy",
            {"type": "cidr", "cidr": "192.0.2.0/24"},
        )
        self.ns.save_state.side_effect = [True, False, True]

        self.assertFalse(self.ns.start_plugin(plugin_id))
        self.assertFalse(self.ns.plugins[plugin_id].active)

    def test_failed_plugin_cleanup_is_retained_for_retry(self):
        plugin_id = self.ns.register_plugin(
            "dummy",
            {"type": "cidr", "cidr": "192.0.2.0/24"},
        )
        self.ns.plugins[plugin_id].stop = mock.Mock(return_value=False)

        self.assertFalse(self.ns._cleanup_plugins())
        self.assertIn(plugin_id, self.ns.plugins)

    def test_json_safe_serializes_default_network_scope(self):
        scope = {
            "type": "cidr",
            "cidrs": [ip_network("192.0.2.0/24")],
        }

        self.assertEqual(
            self.ns._json_safe(scope),
            {"type": "cidr", "cidrs": ["192.0.2.0/24"]},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
