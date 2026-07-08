import json
import os
import tempfile
import unittest
from ipaddress import IPv4Network
from unittest import mock

from netshaper import config
from netshaper.core.authorization import AuthorizationError, AuthorizationPolicy
from netshaper.core.firewall_manager import FirewallManager
from netshaper.core.mitm_manager import MitmProxyManager
from netshaper.core.owner import OwnerStatus
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

    def test_authorization_rejects_connected_network_boundaries(self):
        policy = AuthorizationPolicy(["10.0.0.0/8"])
        connected = [IPv4Network("10.1.1.0/24")]

        with self.assertRaisesRegex(AuthorizationError, "network/broadcast"):
            policy.assert_target_authorized(
                "10.1.1.0",
                connected_networks=connected,
            )
        with self.assertRaisesRegex(AuthorizationError, "network/broadcast"):
            policy.assert_target_authorized(
                "10.1.1.255",
                connected_networks=connected,
            )

        policy.assert_target_authorized(
            "10.1.1.254",
            connected_networks=connected,
        )

    def test_firewall_manager_state_and_remove(self):
        manager = FirewallManager("lo", "TEST")
        state = manager.get_state_for_persistence()
        self.assertIsInstance(state, dict)
        self.assertTrue(manager.remove_global_rules())

    def test_mitm_manager_dry_run(self):
        with mock.patch.object(config, "DRY_RUN", True):
            manager = MitmProxyManager("127.0.0.1")
            self.assertTrue(manager.launch(port=8088, web_port=8083))
            self.assertIsNone(manager._open_log("/tmp/netshaper-test"))

    def test_mitm_manager_terminate_without_process_is_clean(self):
        manager = MitmProxyManager("127.0.0.1")

        self.assertTrue(manager.terminate())

    def test_mitm_manager_state_includes_owned_process(self):
        manager = MitmProxyManager("127.0.0.1")
        process = mock.Mock()
        process.pid = 4321
        process.poll.side_effect = [None, 0]
        manager._mitm_proc = process
        manager._mitm_command = [
            "mitmweb",
            "--mode",
            "transparent",
            "--listen-port",
            "8088",
        ]
        manager._mitm_log_path = "/run/netshaper/NS-TEST/mitmproxy.log"

        with mock.patch(
            "netshaper.core.mitm_manager.process_owner_metadata",
            return_value={
                "pid": 4321,
                "process_create_time": 123.0,
                "created_at": 456.0,
            },
        ):
            state = manager.get_state_for_persistence()

        self.assertEqual(state["service"], "mitmproxy")
        self.assertEqual(state["pid"], 4321)
        self.assertEqual(state["executable"], "mitmweb")
        self.assertEqual(state["mitm_log_path"], "/run/netshaper/NS-TEST/mitmproxy.log")

    def test_mitm_manager_stops_process_when_launch_journal_fails(self):
        process = mock.Mock()
        process.pid = 4321
        process.poll.side_effect = [None, 0]
        manager = MitmProxyManager("127.0.0.1", journal=lambda: False)

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "STATE_DIR", tmp), \
             mock.patch.object(config, "DRY_RUN", False), \
             mock.patch("netshaper.core.mitm_manager.check_local_port",
                        return_value=False), \
             mock.patch("netshaper.core.mitm_manager.subprocess.Popen",
                        return_value=process), \
             mock.patch("netshaper.core.mitm_manager.log"):
            result = manager.launch(port=8088, web_port=8083)

        self.assertFalse(result)
        process.terminate.assert_called_once()
        self.assertIsNone(manager._mitm_proc)

    def test_mitm_manager_refuses_existing_listener(self):
        manager = MitmProxyManager("127.0.0.1")

        with mock.patch.object(config, "DRY_RUN", False), \
             mock.patch("netshaper.core.mitm_manager.check_local_port",
                        return_value=True), \
             mock.patch("netshaper.core.mitm_manager.subprocess.Popen") as popen:
            result = manager.launch(port=8088, web_port=8083)

        self.assertFalse(result)
        popen.assert_not_called()

    def test_recovery_manager_no_state_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = f"{tmp}/nosuch"
            with mock.patch.object(config, "STATE_DIR", missing):
                manager = RecoveryManager("lo")
                self.assertTrue(manager.recover_stale_state())

    def test_recovery_unknown_owner_leaves_manifest(self):
        state = {
            "interface": "eth0",
            "owner": {"pid": 1234, "process_start_time": "legacy"},
        }

        with tempfile.TemporaryDirectory() as tmp:
            state_path = f"{tmp}/state.json"
            with open(state_path, "w", encoding="utf-8") as handle:
                json.dump(state, handle)

            with mock.patch(
                "netshaper.core.recovery_manager.owner_status",
                return_value=OwnerStatus.UNKNOWN,
            ):
                result = RecoveryManager("eth0")._cleanup_stale_session(
                    state_path
                )

            self.assertFalse(result)
            self.assertTrue(os.path.exists(state_path))

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

    def test_recovery_terminates_verified_managed_service(self):
        process = mock.Mock()
        process.cmdline.return_value = [
            "/usr/bin/python3",
            "-m",
            "netshaper.portal",
            "--health-token",
            "token",
        ]
        record = {
            "service": "portal",
            "pid": 1234,
            "process_create_time": 1.0,
            "executable": "/usr/bin/python3",
            "argv": process.cmdline.return_value,
            "ownership_token": "token",
        }

        with mock.patch(
            "netshaper.core.recovery_manager.owner_status",
            return_value=OwnerStatus.LIVE,
        ), mock.patch(
            "netshaper.core.recovery_manager.psutil.Process",
            return_value=process,
        ):
            self.assertTrue(
                RecoveryManager._cleanup_managed_service("portal", record)
            )

        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=5)

    def test_recovery_kills_verified_managed_service_after_timeout(self):
        process = mock.Mock()
        process.cmdline.return_value = [
            "mitmweb",
            "--mode",
            "transparent",
        ]
        process.wait.side_effect = [Exception("timeout"), None]
        record = {
            "service": "mitmproxy",
            "pid": 4321,
            "process_create_time": 1.0,
            "executable": "mitmweb",
            "argv": process.cmdline.return_value,
        }

        with mock.patch(
            "netshaper.core.recovery_manager.owner_status",
            return_value=OwnerStatus.LIVE,
        ), mock.patch(
            "netshaper.core.recovery_manager.psutil.Process",
            return_value=process,
        ), mock.patch(
            "netshaper.core.recovery_manager.psutil.TimeoutExpired",
            Exception,
        ):
            self.assertTrue(
                RecoveryManager._cleanup_managed_service("mitmproxy", record)
            )

        process.terminate.assert_called_once()
        process.kill.assert_called_once()

    def test_recovery_refuses_managed_service_identity_mismatch(self):
        process = mock.Mock()
        process.cmdline.return_value = ["python", "-m", "other.portal"]
        record = {
            "service": "portal",
            "pid": 1234,
            "process_create_time": 1.0,
            "executable": "/usr/bin/python3",
            "argv": [
                "/usr/bin/python3",
                "-m",
                "netshaper.portal",
                "--health-token",
                "token",
            ],
            "ownership_token": "token",
        }

        with mock.patch(
            "netshaper.core.recovery_manager.owner_status",
            return_value=OwnerStatus.LIVE,
        ), mock.patch(
            "netshaper.core.recovery_manager.psutil.Process",
            return_value=process,
        ):
            self.assertFalse(
                RecoveryManager._cleanup_managed_service("portal", record)
            )

        process.terminate.assert_not_called()

    def test_recovery_fails_closed_for_unknown_managed_service_owner(self):
        record = {
            "service": "mitmproxy",
            "pid": 4321,
            "process_create_time": None,
            "executable": "mitmweb",
            "argv": ["mitmweb", "--mode", "transparent"],
        }

        with mock.patch(
            "netshaper.core.recovery_manager.owner_status",
            return_value=OwnerStatus.UNKNOWN,
        ), mock.patch(
            "netshaper.core.recovery_manager.psutil.Process"
        ) as process_cls:
            self.assertFalse(
                RecoveryManager._cleanup_managed_service("mitmproxy", record)
            )

        process_cls.assert_not_called()

    def test_recovery_treats_stale_managed_service_as_clean(self):
        record = {
            "service": "mitmproxy",
            "pid": 4321,
            "process_create_time": 1.0,
            "executable": "mitmweb",
            "argv": ["mitmweb", "--mode", "transparent"],
        }

        with mock.patch(
            "netshaper.core.recovery_manager.owner_status",
            return_value=OwnerStatus.STALE,
        ):
            self.assertTrue(
                RecoveryManager._cleanup_managed_service("mitmproxy", record)
            )


if __name__ == "__main__":
    unittest.main()
