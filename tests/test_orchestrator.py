import json
import os
import tempfile
import threading
import unittest
from ipaddress import IPv4Network
from unittest import mock

from netshaper.core.authorization import AuthorizationError, AuthorizationPolicy
from netshaper.core.mitm_manager import MitmProxyManager
from netshaper.core.orchestrator import NetShaper
from netshaper.models import Device
from netshaper.system import InspectionStatus


class NetShaperCleanupTests(unittest.TestCase):
    @staticmethod
    def _set_authorized(
            ns: NetShaper,
            cidrs: tuple[str, ...] = ("192.0.2.0/24",)) -> None:
        ns._auth_policy = AuthorizationPolicy(cidrs)

    def test_constructor_requires_authorized_cidrs_before_system_checks(self):
        with mock.patch("netshaper.core.orchestrator.SystemChecker.check"
                        ) as check_mock:
            with self.assertRaisesRegex(ValueError, "authorized_cidrs"):
                NetShaper("eth0", authorized_cidrs=[])

        check_mock.assert_not_called()

    def test_constructor_accepts_string_authorized_cidrs(self):
        with mock.patch("netshaper.core.orchestrator.SystemChecker.check",
                        side_effect=RuntimeError("stop after auth")):
            with self.assertRaisesRegex(RuntimeError, "stop after auth") as cm:
                NetShaper("eth0", authorized_cidrs=["192.0.2.0/24"])

        self.assertIn("stop after auth", str(cm.exception))

    def test_add_target_rejects_duplicate_target(self):
        ns = NetShaper.__new__(NetShaper)
        ns._lifecycle_lock = threading.RLock()
        ns.sessions = {"192.0.2.10": mock.Mock()}

        with self.assertRaisesRegex(ValueError, "already active"):
            ns.add_target(Device(ip="192.0.2.10", mac="00:11:22:33:44:55"))

    def test_cleanup_keeps_session_incomplete_when_steps_fail(self):
        ns = NetShaper.__new__(NetShaper)
        ns._lifecycle_lock = threading.RLock()
        ns._cleanup_running = False
        ns._cleanup_complete = False
        ns.is_shutting_down = False
        ns.stop_event = threading.Event()
        ns.sessions = {}
        ns.sniffer = mock.Mock()
        ns.sniffer.stop.side_effect = RuntimeError("sniffer stop failed")
        ns.mitm_manager = mock.Mock()
        ns.mitm_manager.terminate.side_effect = RuntimeError("mitm stop failed")
        ns._remove_global_rules = mock.Mock(side_effect=RuntimeError("rules failed"))
        ns.state_snapshot = mock.Mock()
        ns.shaper = mock.Mock()
        ns.shaper.cleanup.side_effect = RuntimeError("shaper failed")
        ns.session_id = "NS-TEST"

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
             mock.patch("netshaper.core.orchestrator.print_flush"), \
             mock.patch("netshaper.core.orchestrator.log"), \
             mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                        side_effect=RuntimeError("restore failed")) as restore_mock:
            ns.cleanup()

        ns.sniffer.stop.assert_called_once()
        ns.mitm_manager.terminate.assert_called_once()
        ns._remove_global_rules.assert_called_once()
        restore_mock.assert_called_once_with(
            ns.state_snapshot,
            restore_firewall=False,
        )
        ns.shaper.cleanup.assert_called_once()
        self.assertFalse(ns._cleanup_complete)

    def test_cleanup_retains_state_when_rolling_capture_flush_fails(self):
        ns = NetShaper.__new__(NetShaper)
        ns._lifecycle_lock = threading.RLock()
        ns._cleanup_running = False
        ns._cleanup_complete = False
        ns.is_shutting_down = False
        ns.stop_event = threading.Event()
        ns.sessions = {}
        ns.sniffer = mock.Mock()
        ns.sniffer.stop.return_value = False
        ns.mitm_manager = mock.Mock()
        ns.mitm_manager.terminate.return_value = True
        ns._terminate_fake_server = mock.Mock(return_value=True)
        ns._cleanup_plugins = mock.Mock(return_value=True)
        ns._stop_arp_amplification = mock.Mock(return_value=True)
        ns._remove_global_rules = mock.Mock(return_value=True)
        ns._remove_state_file = mock.Mock(return_value=True)
        ns.state_snapshot = mock.Mock()
        ns.shaper = mock.Mock()
        ns.shaper.cleanup.return_value = True
        ns.session_id = "NS-TEST"

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
             mock.patch("netshaper.core.orchestrator.print_flush"), \
             mock.patch("netshaper.core.orchestrator.log"), \
             mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                        return_value=True):
            ns.cleanup()

        ns.sniffer.stop.assert_called_once()
        ns._remove_state_file.assert_not_called()
        self.assertFalse(ns._cleanup_complete)

    def test_cleanup_retains_state_when_arp_amplification_stop_fails(self):
        ns = NetShaper.__new__(NetShaper)
        ns._lifecycle_lock = threading.RLock()
        ns._cleanup_running = False
        ns._cleanup_complete = False
        ns.is_shutting_down = False
        ns.stop_event = threading.Event()
        ns.sessions = {}
        ns.sniffer = None
        ns.mitm_manager = mock.Mock()
        ns.mitm_manager.terminate.return_value = True
        ns._terminate_fake_server = mock.Mock(return_value=True)
        ns._cleanup_plugins = mock.Mock(return_value=True)
        ns._stop_arp_amplification = mock.Mock(return_value=False)
        ns._remove_global_rules = mock.Mock(return_value=True)
        ns._remove_state_file = mock.Mock(return_value=True)
        ns.state_snapshot = mock.Mock()
        ns.shaper = mock.Mock()
        ns.shaper.cleanup.return_value = True
        ns.session_id = "NS-TEST"

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
             mock.patch("netshaper.core.orchestrator.print_flush"), \
             mock.patch("netshaper.core.orchestrator.log"), \
             mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                        return_value=True):
            ns.cleanup()

        ns._stop_arp_amplification.assert_called_once()
        ns._remove_state_file.assert_not_called()
        self.assertFalse(ns._cleanup_complete)

    def test_stop_arp_amplification_retains_reference_when_shutdown_fails(self):
        ns = NetShaper.__new__(NetShaper)
        amplifier = mock.Mock()
        amplifier.shutdown.return_value = False
        ns._arp_amplifier = amplifier

        with mock.patch("netshaper.core.orchestrator.log"):
            self.assertFalse(ns._stop_arp_amplification())

        amplifier.shutdown.assert_called_once()
        self.assertIs(ns._arp_amplifier, amplifier)

    def test_stop_arp_amplification_clears_reference_when_shutdown_succeeds(self):
        ns = NetShaper.__new__(NetShaper)
        amplifier = mock.Mock()
        amplifier.shutdown.return_value = True
        ns._arp_amplifier = amplifier

        self.assertTrue(ns._stop_arp_amplification())

        amplifier.shutdown.assert_called_once()
        self.assertIsNone(ns._arp_amplifier)

    def test_add_target_rolls_back_partially_created_session(self):
        ns = NetShaper.__new__(NetShaper)
        self._set_authorized(ns)
        ns._lifecycle_lock = threading.RLock()
        ns.sessions = {}
        ns.mark_pool = mock.Mock()
        ns.mark_pool.acquire.return_value = 10
        ns.interface = "eth0"
        ns.own_mac = "aa:bb:cc:dd:ee:ff"
        ns.own_ip = "192.0.2.1"
        ns.own_ipv6 = None
        ns.gw = "192.0.2.254"
        ns.gw_mac = "ff:ee:dd:cc:bb:aa"
        ns.gw_ipv6 = None
        ns.shaper = mock.Mock()
        target = Device(ip="192.0.2.10", mac="00:11:22:33:44:55")

        with mock.patch("netshaper.core.orchestrator.TargetSession") as session_cls:
            session = session_cls.return_value
            session.setup.side_effect = RuntimeError("setup failed")

            with self.assertRaises(RuntimeError):
                ns.add_target(target)

        self.assertEqual(ns.sessions, {})
        session.cleanup.assert_called_once()
        ns.mark_pool.release.assert_called_once_with("192.0.2.10")

    def test_add_target_rolls_back_target_forwarding_when_spoof_start_fails(self):
        ns = NetShaper.__new__(NetShaper)
        self._set_authorized(ns)
        ns._lifecycle_lock = threading.RLock()
        ns.sessions = {}
        ns.mark_pool = mock.Mock()
        ns.mark_pool.acquire.return_value = 10
        ns.interface = "eth0"
        ns.own_mac = "aa:bb:cc:dd:ee:ff"
        ns.own_ip = "192.0.2.1"
        ns.own_ipv6 = None
        ns.gw = "192.0.2.254"
        ns.gw_mac = "ff:ee:dd:cc:bb:aa"
        ns.gw_ipv6 = None
        ns.shaper = mock.Mock()
        ns.firewall_manager = mock.Mock()
        ns.firewall_manager.remove_target_rules.return_value = True
        target = Device(ip="192.0.2.10", mac="00:11:22:33:44:55")

        with mock.patch("netshaper.core.orchestrator.TargetSession") as session_cls:
            session = session_cls.return_value
            session.cleanup.return_value = True
            session.start_spoof.side_effect = RuntimeError("spoof failed")

            with self.assertRaisesRegex(RuntimeError, "spoof failed"):
                ns.add_target(target)

        ns.firewall_manager.add_target_rules.assert_called_once_with(
            "192.0.2.10"
        )
        ns.firewall_manager.remove_target_rules.assert_called_once_with(
            "192.0.2.10"
        )
        self.assertEqual(ns.sessions, {})
        ns.mark_pool.release.assert_called_once_with("192.0.2.10")

    def test_failed_rollback_keeps_session_for_retry(self):
        ns = NetShaper.__new__(NetShaper)
        self._set_authorized(ns)
        ns._lifecycle_lock = threading.RLock()
        ns.sessions = {}
        ns.mark_pool = mock.Mock()
        ns.mark_pool.acquire.return_value = 10
        ns.interface = "eth0"
        ns.own_mac = "aa:bb:cc:dd:ee:ff"
        ns.own_ip = "192.0.2.1"
        ns.own_ipv6 = None
        ns.gw = "192.0.2.254"
        ns.gw_mac = "ff:ee:dd:cc:bb:aa"
        ns.gw_ipv6 = None
        ns.shaper = mock.Mock()
        ns.save_state = mock.Mock(return_value=True)
        target = Device(ip="192.0.2.10", mac="00:11:22:33:44:55")

        with mock.patch("netshaper.core.orchestrator.TargetSession") as session_cls, \
             mock.patch("netshaper.core.orchestrator.log"):
            session = session_cls.return_value
            session.setup.side_effect = RuntimeError("setup failed")
            session.cleanup.return_value = False

            with self.assertRaises(RuntimeError):
                ns.add_target(target)

        self.assertIs(ns.sessions["192.0.2.10"], session)
        session.cleanup.assert_called_once()
        ns.mark_pool.release.assert_not_called()
        ns.save_state.assert_called_once()

    def test_add_target_rejects_out_of_scope_before_resolution(self):
        ns = NetShaper.__new__(NetShaper)
        self._set_authorized(ns)
        ns._lifecycle_lock = threading.RLock()
        ns.sessions = {}
        ns.own_ip = "192.0.2.1"
        ns.own_ipv6 = None
        ns.gw = "192.0.2.254"
        ns.gw_ipv6 = None
        ns.disc = mock.Mock()

        with self.assertRaisesRegex(AuthorizationError, "outside authorized"):
            ns.add_target("198.51.100.10")

        ns.disc.resolve_mac.assert_not_called()

    def test_add_target_rejects_out_of_scope_ipv6_before_mutation(self):
        ns = NetShaper.__new__(NetShaper)
        self._set_authorized(ns)
        ns._lifecycle_lock = threading.RLock()
        ns.sessions = {}
        ns.own_ip = "192.0.2.1"
        ns.own_ipv6 = None
        ns.gw = "192.0.2.254"
        ns.gw_ipv6 = None
        ns.mark_pool = mock.Mock()
        target = Device(
            ip="192.0.2.10",
            ipv6="2001:db8::10",
            mac="00:11:22:33:44:55",
        )

        with self.assertRaisesRegex(AuthorizationError, "outside authorized"):
            ns.add_target(target)

        ns.mark_pool.acquire.assert_not_called()

    def test_add_target_rejects_connected_network_boundary_before_mutation(self):
        ns = NetShaper.__new__(NetShaper)
        self._set_authorized(ns, ("10.0.0.0/8",))
        ns._lifecycle_lock = threading.RLock()
        ns.sessions = {}
        ns.own_ip = "10.1.1.10"
        ns.own_ipv6 = None
        ns.gw = "10.1.1.1"
        ns.gw_ipv6 = None
        ns.mark_pool = mock.Mock()
        ns.disc = mock.Mock()
        ns.disc.get_connected_networks.return_value = (
            IPv4Network("10.1.1.0/24"),
        )

        for target_ip in ("10.1.1.0", "10.1.1.255"):
            with self.subTest(target_ip=target_ip), \
                 self.assertRaisesRegex(AuthorizationError, "network/broadcast"):
                ns.add_target(
                    Device(ip=target_ip, mac="00:11:22:33:44:55")
                )

        ns.mark_pool.acquire.assert_not_called()

    def test_remove_target_keeps_failed_cleanup_registered(self):
        ns = NetShaper.__new__(NetShaper)
        ns._lifecycle_lock = threading.RLock()
        session = mock.Mock()
        session.cleanup.return_value = False
        ns.sessions = {"192.0.2.10": session}
        ns.mark_pool = mock.Mock()

        with mock.patch("netshaper.core.orchestrator.log"):
            result = ns.remove_target("192.0.2.10")

        self.assertFalse(result)
        self.assertIs(ns.sessions["192.0.2.10"], session)
        ns.mark_pool.release.assert_not_called()

    def test_dry_run_launch_sniffer_does_not_start_capture(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.sniffer = None

        with mock.patch("netshaper.core.orchestrator.config.DRY_RUN", True), \
             mock.patch("netshaper.core.orchestrator.PacketSniffer") as sniffer_cls, \
             mock.patch("netshaper.core.orchestrator.print_flush"):
            ns.launch_sniffer(["192.0.2.10"])

        sniffer_cls.assert_not_called()
        self.assertIsNone(ns.sniffer)

    def test_dry_run_launch_mitmproxy_does_not_start_process(self):
        ns = NetShaper.__new__(NetShaper)
        ns.own_ip = "192.0.2.1"

        with mock.patch("netshaper.core.orchestrator.config.DRY_RUN", True), \
             mock.patch("netshaper.core.mitm_manager.subprocess.Popen") as popen_mock, \
             mock.patch("netshaper.core.orchestrator.print_flush"):
            result = ns.launch_mitmproxy()

        self.assertTrue(result)
        popen_mock.assert_not_called()

    def test_fake_server_launch_wires_spoof_mode_dnssec_and_allowlist(self):
        ns = NetShaper.__new__(NetShaper)
        self._set_authorized(ns)
        ns.own_ip = "192.0.2.1"
        ns._fake_server_proc = None
        ns._fake_server_health_token = "test-health-token"
        process = mock.Mock()
        process.pid = 1234
        process.poll.return_value = None

        with mock.patch(
            "netshaper.core.portal_manager.check_local_port",
            side_effect=[False, False],
        ), mock.patch(
            "netshaper.core.portal_manager.PortalManager.health_ready",
            side_effect=[False, True],
        ), mock.patch(
            "netshaper.core.portal_manager.subprocess.Popen",
            return_value=process,
        ) as popen, mock.patch(
            "netshaper.core.portal_manager.process_owner_metadata",
            return_value={
                "pid": 1234,
                "process_create_time": 456.0,
                "created_at": 789.0,
            },
        ):
            self.assertTrue(
                ns.launch_fake_server(
                    dnssec_mode="nxdomain",
                    smart_spoof_all=True,
                )
            )

        command = popen.call_args.args[0]
        self.assertIn("--smart-spoof-all", command)
        self.assertIn("nxdomain", command)
        self.assertIn("192.0.2.0/24", command)
        self.assertIn("192.0.2.1/32", command)
        self.assertIn("--health-token", command)
        self.assertIn("test-health-token", command)

    def test_fake_server_health_token_is_stable_for_manual_launch(self):
        ns = NetShaper.__new__(NetShaper)
        ns._fake_server_health_token = None

        with mock.patch(
            "netshaper.core.portal_manager.secrets.token_urlsafe",
            return_value="manual-token",
        ):
            self.assertEqual(ns.fake_server_health_token(), "manual-token")
            self.assertEqual(ns.fake_server_health_token(), "manual-token")

    def test_fake_server_launch_refuses_unverified_claimed_listener(self):
        ns = NetShaper.__new__(NetShaper)
        ns.own_ip = "192.0.2.1"
        ns._fake_server_proc = None
        ns._fake_server_health_token = "test-health-token"

        with mock.patch(
            "netshaper.core.portal_manager.PortalManager.health_ready",
            return_value=False,
        ), mock.patch(
            "netshaper.core.portal_manager.check_local_port",
            side_effect=[True, True],
        ), mock.patch(
            "netshaper.core.portal_manager.subprocess.Popen"
        ) as popen, mock.patch(
            "netshaper.core.portal_manager.log"
        ) as log:
            self.assertFalse(ns.launch_fake_server())

        popen.assert_not_called()
        self.assertIn("health token", log.error.call_args.args[0])

    def test_dry_run_discover_does_not_touch_network(self):
        ns = NetShaper.__new__(NetShaper)
        self._set_authorized(ns)
        ns.disc = mock.Mock()

        with mock.patch("netshaper.core.orchestrator.config.DRY_RUN", True), \
             mock.patch("netshaper.core.orchestrator.print_flush"):
            result = ns.discover()

        self.assertEqual(result, [])
        ns.disc.get_subnet_v4.assert_not_called()
        ns.disc.arp_sweep.assert_not_called()

    def test_discover_fails_closed_without_authorized_cidrs(self):
        ns = NetShaper.__new__(NetShaper)
        ns._auth_policy = None
        ns.disc = mock.Mock()

        with self.assertRaisesRegex(ValueError, "authorized_cidrs"):
            ns.discover()

        ns.disc.get_subnet_v4.assert_not_called()

    def test_discover_uses_core_authorized_cidrs(self):
        ns = NetShaper.__new__(NetShaper)
        self._set_authorized(ns, ("192.0.2.64/28",))
        ns.gw = "192.0.2.1"
        ns.disc = mock.Mock()
        ns.disc.get_subnet_v4.return_value = "192.0.2.0/24"
        ns.disc.arp_sweep.return_value = []

        with mock.patch("netshaper.core.orchestrator.config.DRY_RUN", False):
            result = ns.discover()

        self.assertEqual(result, [])
        ns.disc.arp_sweep.assert_called_once_with(
            "192.0.2.0/24",
            "192.0.2.1",
            ns.authorized_cidrs,
        )

    def test_arp_amplification_fails_closed_without_connected_authorization(self):
        ns = NetShaper.__new__(NetShaper)
        self._set_authorized(ns, ("10.0.0.0/8",))
        ns.own_ip = "192.168.1.10"
        ns.gw = "192.168.1.1"
        ns.disc = mock.Mock()
        ns.disc.get_subnet_v4.return_value = "192.168.1.0/24"

        with self.assertRaisesRegex(RuntimeError, "directly connected"):
            ns._ipv4_subnet_for_amplification()

    def test_arp_amplification_uses_connected_scope_with_broad_authorization(self):
        ns = NetShaper.__new__(NetShaper)
        self._set_authorized(ns, ("192.168.0.0/16",))
        ns.own_ip = "192.168.1.10"
        ns.gw = "192.168.1.1"
        ns.disc = mock.Mock()
        ns.disc.get_subnet_v4.return_value = "192.168.1.0/24"

        subnet = ns._ipv4_subnet_for_amplification()

        self.assertEqual(subnet, IPv4Network("192.168.1.0/24"))

    def test_arp_amplification_requires_connected_gateway(self):
        ns = NetShaper.__new__(NetShaper)
        self._set_authorized(ns, ("192.168.1.0/24",))
        ns.own_ip = "192.168.1.10"
        ns.gw = "192.168.2.1"
        ns.disc = mock.Mock()
        ns.disc.get_subnet_v4.return_value = "192.168.1.0/24"

        with self.assertRaisesRegex(RuntimeError, "gateway directly connected"):
            ns._ipv4_subnet_for_amplification()

    def test_launch_mitmproxy_reaps_process_when_readiness_fails(self):
        ns = NetShaper.__new__(NetShaper)
        ns.own_ip = "192.0.2.1"
        ns.session_id = "NS-TEST"
        ns._mitm_log_path = None
        proc = mock.Mock()
        proc.pid = 4321
        proc.poll.side_effect = [None, None, 0]

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
             mock.patch("netshaper.core.orchestrator.config.DRY_RUN", False), \
             mock.patch("netshaper.core.orchestrator.check_local_port",
                        return_value=False), \
             mock.patch("netshaper.core.mitm_manager.check_local_port",
                        return_value=False), \
             mock.patch("netshaper.core.mitm_manager.subprocess.Popen",
                        return_value=proc), \
             mock.patch(
                 "netshaper.core.mitm_manager.process_owner_metadata",
                 return_value={
                     "pid": 4321,
                     "process_create_time": 123.0,
                     "created_at": 456.0,
                 },
             ), \
             mock.patch("netshaper.core.mitm_manager.time.sleep"), \
             mock.patch("netshaper.core.mitm_manager.log"):
            result = ns.launch_mitmproxy()

        self.assertFalse(result)
        proc.terminate.assert_not_called()
        proc.wait.assert_not_called()
        self.assertIsNone(ns.mitm_manager._mitm_proc)
        self.assertIsNone(ns.mitm_manager._mitm_log_handle)
        self.assertTrue(ns._mitm_log_path.endswith("mitmproxy.log"))

    def test_failed_mitmproxy_termination_keeps_process_for_retry(self):
        ns = NetShaper.__new__(NetShaper)
        proc = mock.Mock()
        proc.poll.return_value = None
        proc.terminate.side_effect = RuntimeError("nope")
        ns.mitm_manager = MitmProxyManager("192.0.2.1")
        ns.mitm_manager._mitm_proc = proc

        with mock.patch("netshaper.core.orchestrator.log"):
            first = ns._terminate_mitmproxy()

        proc.terminate.side_effect = None
        proc.poll.side_effect = [None, 0]
        second = ns._terminate_mitmproxy()

        self.assertFalse(first)
        self.assertTrue(second)
        self.assertIsNone(ns.mitm_manager._mitm_proc)
        self.assertEqual(proc.terminate.call_count, 2)

    def test_start_monitor_thread_records_crashes(self):
        ns = NetShaper.__new__(NetShaper)
        ns.session_id = "NS-TEST"
        ns.stop_event = threading.Event()
        ns._monitor_thread = None
        ns._runtime_errors = []
        ns.monitor = mock.Mock(side_effect=RuntimeError("counter failed"))

        with mock.patch("netshaper.core.orchestrator.log"):
            thread = ns.start_monitor_thread()
            thread.join(timeout=1.0)

        self.assertFalse(thread.is_alive())
        self.assertTrue(ns.stop_event.is_set())
        self.assertTrue(
            any("counter failed" in error for error in ns._runtime_errors)
        )

    def test_runtime_health_reports_failed_components(self):
        ns = NetShaper.__new__(NetShaper)
        ns.stop_event = threading.Event()
        ns._runtime_errors = []
        monitor = mock.Mock()
        monitor.is_alive.return_value = False
        ns._monitor_thread = monitor
        ns.sniffer = mock.Mock()
        ns.sniffer.is_running.return_value = False
        ns.sniffer.last_error = "disk full"
        ns.own_ip = "192.0.2.1"

        with mock.patch("netshaper.core.orchestrator.config.DRY_RUN", False):
            issues = ns.runtime_health_issues(
                expect_sniffer=True,
                expect_monitor=True,
            )

        self.assertIn("bandwidth monitor thread is not running", issues)
        self.assertTrue(any("disk full" in issue for issue in issues))

    def test_scale_bytes_starts_at_bytes(self):
        self.assertEqual(NetShaper.scale_bytes(500), "500.0 B")
        self.assertEqual(NetShaper.scale_bytes(2048), "2.0 KB")
        self.assertEqual(NetShaper.scale_bytes(3 * 1024 * 1024), "3.0 MB")

    def test_runtime_health_includes_arp_amplifier_failures(self):
        ns = NetShaper.__new__(NetShaper)
        ns.stop_event = threading.Event()
        ns._runtime_errors = []
        ns._monitor_thread = None
        ns.sniffer = None
        ns._arp_amplifier = mock.Mock()
        ns._arp_amplifier.health_issues.return_value = [
            "ARP amplification worker failed: send failed"
        ]

        with mock.patch("netshaper.core.orchestrator.config.DRY_RUN", True):
            issues = ns.runtime_health_issues()

        self.assertEqual(
            issues,
            ["ARP amplification worker failed: send failed"],
        )

    def test_instance_lock_rejects_second_holder(self):
        first = NetShaper.__new__(NetShaper)
        second = NetShaper.__new__(NetShaper)
        first._lock_file = None
        second._lock_file = None
        first._owner_metadata = {"pid": 111, "process_start_time": "1"}
        second._owner_metadata = {"pid": 222, "process_start_time": "2"}

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
             mock.patch("netshaper.core.orchestrator.config.DRY_RUN", False):
            first._acquire_instance_lock()
            try:
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    second._acquire_instance_lock()
            finally:
                first._release_instance_lock()
                second._release_instance_lock()

    def test_apply_global_rules_only_enables_forwarding_sysctls(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.session_id = "NS-TEST"
        ns.sessions = {}
        ns.state_snapshot = mock.Mock()
        ns._global_rules_applied = False
        ns._global_firewall_binaries_applied = []
        ns._global_rules_created = []
        ns.save_state = mock.Mock(return_value=True)

        with mock.patch("netshaper.core.firewall_manager.SubprocessRunner.run",
                        return_value=True) as runner_mock:
            ns._apply_global_rules()

        commands = [
            call.args[0] for call in runner_mock.call_args_list
        ]
        self.assertEqual(
            commands,
            [
                ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
                ["sysctl", "-w", "net.ipv4.conf.eth0.route_localnet=1"],
            ],
        )
        ns.save_state.assert_called_once()
        self.assertEqual(ns._global_rules_created, [])

    def test_remove_global_rules_skips_firewall_when_never_applied(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.session_id = "NS-TEST"
        ns.state_snapshot = mock.Mock(
            ipv4_forwarding=None,
            ipv6_forwarding=None,
            route_localnet=None,
        )
        ns._global_rules_applied = False
        ns._global_firewall_binaries_applied = []
        ns._global_rules_created = []

        with mock.patch("netshaper.core.firewall_manager.shutil.which",
                        return_value="/sbin/iptables"), \
             mock.patch("netshaper.system.subprocess.run") as run_mock, \
             mock.patch("netshaper.core.firewall_manager.SubprocessRunner.run"
                        ) as runner_mock:
            result = ns._remove_global_rules()

        self.assertTrue(result)
        run_mock.assert_not_called()
        runner_mock.assert_not_called()

    def test_stale_cleanup_removes_recorded_tc_root_qdisc(self):
        ns = NetShaper.__new__(NetShaper)
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [],
            "global_rules_applied": False,
            "shaper_base_initialized": True,
            "shaper_root_qdisc": {
                "format": "netshaper.tc-root.v1",
                "interface": "eth0",
                "session_id": "NS-OLD",
                "handle": "7abc:",
                "state": "active",
            },
            "snapshot": snapshot,
        }

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.system.subprocess.run",
                            return_value=mock.Mock(
                                returncode=0,
                                stdout="qdisc htb 7abc: root refcnt 2\n",
                            )), \
                 mock.patch("netshaper.core.recovery_manager.shutil.which",
                            return_value="/sbin/tool"), \
                 mock.patch("netshaper.core.recovery_manager.SubprocessRunner.run",
                            return_value=True) as runner_mock, \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True) as restore_mock:
                ns.load_state_and_cleanup()

            runner_mock.assert_any_call(
                ["tc", "qdisc", "del", "dev", "eth0", "root"],
                check=False,
                silent=True,
            )
            restore_mock.assert_called_once_with(
                mock.ANY,
                restore_firewall=False,
            )
            self.assertFalse(os.path.exists(state_path))

    def test_stale_cleanup_removes_pending_tc_root_qdisc(self):
        ns = NetShaper.__new__(NetShaper)
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [],
            "global_rules_applied": False,
            "shaper_base_initialized": False,
            "shaper_root_qdisc_pending": True,
            "shaper_root_qdisc": {
                "format": "netshaper.tc-root.v1",
                "interface": "eth0",
                "session_id": "NS-OLD",
                "handle": "7abd:",
                "state": "pending",
            },
            "snapshot": snapshot,
        }

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.system.subprocess.run",
                            return_value=mock.Mock(
                                returncode=0,
                                stdout="qdisc htb 7abd: root refcnt 2\n",
                            )), \
                 mock.patch("netshaper.core.recovery_manager.shutil.which",
                            return_value="/sbin/tool"), \
                 mock.patch("netshaper.core.recovery_manager.SubprocessRunner.run",
                            return_value=True) as runner_mock, \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True):
                result = ns.load_state_and_cleanup()

            self.assertTrue(result)
            runner_mock.assert_any_call(
                ["tc", "qdisc", "del", "dev", "eth0", "root"],
                check=False,
                silent=True,
            )
            self.assertFalse(os.path.exists(state_path))

    def test_stale_cleanup_preserves_mismatched_tc_root_qdisc(self):
        ns = NetShaper.__new__(NetShaper)
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [],
            "global_rules_applied": False,
            "shaper_base_initialized": True,
            "shaper_root_qdisc": {
                "format": "netshaper.tc-root.v1",
                "interface": "eth0",
                "session_id": "NS-OLD",
                "handle": "7abe:",
                "state": "active",
            },
            "snapshot": snapshot,
        }

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.system.subprocess.run",
                            return_value=mock.Mock(
                                returncode=0,
                                stdout="qdisc htb 9000: root refcnt 2\n",
                            )), \
                 mock.patch("netshaper.core.recovery_manager.shutil.which",
                            return_value="/sbin/tool"), \
                 mock.patch("netshaper.core.recovery_manager.SubprocessRunner.run",
                            return_value=True) as runner_mock, \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True):
                result = ns.load_state_and_cleanup()

            self.assertFalse(result)
            runner_mock.assert_not_called()
            self.assertTrue(os.path.exists(state_path))

    def test_stale_cleanup_removes_only_commented_global_rules(self):
        ns = NetShaper.__new__(NetShaper)
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        comment = "netshaper:NS-OLD:global"
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [],
            "global_rules_applied": True,
            "global_rule_comment": comment,
            "global_firewall_binaries": ["iptables"],
            "shaper_base_initialized": False,
            "snapshot": snapshot,
        }

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.core.recovery_manager.shutil.which",
                            return_value="/sbin/iptables"), \
                 mock.patch("netshaper.system.subprocess.run",
                            return_value=mock.Mock(returncode=0, stdout="")), \
                 mock.patch(
                     "netshaper.core.recovery_manager."
                     "RecoveryManager._inspect_stale_resource",
                     side_effect=[
                         InspectionStatus.PRESENT,
                         InspectionStatus.ABSENT,
                         InspectionStatus.PRESENT,
                         InspectionStatus.ABSENT,
                         InspectionStatus.PRESENT,
                         InspectionStatus.ABSENT,
                     ],
                 ), \
                 mock.patch("netshaper.core.recovery_manager.SubprocessRunner.run",
                            return_value=True) as runner_mock, \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True):
                result = ns.load_state_and_cleanup()

            delete_commands = [call.args[0] for call in runner_mock.call_args_list]
            self.assertTrue(result)
            self.assertEqual(len(delete_commands), 3)
            for command in delete_commands:
                self.assertIn("--comment", command)
                self.assertIn(comment, command)
            self.assertNotIn(
                ["iptables", "-D", "FORWARD",
                 "-i", "eth0", "-o", "eth0", "-j", "ACCEPT"],
                delete_commands,
            )
            self.assertFalse(os.path.exists(state_path))

    def test_stale_cleanup_keeps_manifest_when_inspection_errors(self):
        ns = NetShaper.__new__(NetShaper)
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [],
            "global_rules_applied": True,
            "global_rule_comment": "netshaper:NS-OLD:global",
            "global_firewall_binaries": ["iptables"],
            "shaper_base_initialized": False,
            "snapshot": snapshot,
        }
        inspect_error = mock.Mock(
            returncode=4,
            stdout="",
            stderr="Permission denied (you must be root)",
        )

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.core.recovery_manager.shutil.which",
                            return_value="/sbin/iptables"), \
                 mock.patch("netshaper.system.subprocess.run",
                            return_value=inspect_error), \
                 mock.patch("netshaper.core.recovery_manager.SubprocessRunner.run"
                            ) as runner_mock, \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True), \
                 mock.patch("netshaper.core.orchestrator.log"):
                result = ns.load_state_and_cleanup()

            self.assertFalse(result)
            self.assertTrue(os.path.exists(state_path))
            runner_mock.assert_not_called()

    def test_stale_cleanup_uses_target_input_rule_comment(self):
        ns = NetShaper.__new__(NetShaper)
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        comment = "netshaper:NS-OLD:192.0.2.10"
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [{
                "ip": "192.0.2.10",
                "dns": True,
                "http_redirect_port": 8088,
                "firewall_rule_comment": comment,
                "mangle_chain": "NS-MNG-TEST",
                "nat_chain": "NS-NAT-TEST",
            }],
            "global_rules_applied": False,
            "shaper_base_initialized": False,
            "snapshot": snapshot,
        }

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.core.recovery_manager.shutil.which",
                            return_value="/sbin/iptables"), \
                 mock.patch("netshaper.system.subprocess.run",
                            return_value=mock.Mock(returncode=0, stdout="")), \
                 mock.patch("netshaper.core.recovery_manager.SubprocessRunner.run",
                            return_value=True) as runner_mock, \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True):
                result = ns.load_state_and_cleanup()

            input_deletes = [
                call.args[0]
                for call in runner_mock.call_args_list
                if call.args[0][1:3] == ["-D", "INPUT"]
            ]
            self.assertTrue(result)
            self.assertEqual(len(input_deletes), 3)
            for command in input_deletes:
                self.assertIn("--comment", command)
                self.assertIn(comment, command)

    def test_stale_cleanup_rejects_legacy_global_state_without_ownership(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.session_id = "NS-NEW"
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [{
                "ip": "192.0.2.10",
                "dns": True,
                "http_redirect_port": 8088,
                "mangle_chain": "NS-MNG-TEST",
                "nat_chain": "NS-NAT-TEST",
            }],
            "global_rules_applied": True,
            "global_firewall_binaries": ["iptables"],
            "shaper_base_initialized": True,
            "snapshot": snapshot,
        }
        absent = mock.Mock(returncode=1, stdout="")

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.core.recovery_manager.shutil.which",
                            return_value="/sbin/tool"), \
                 mock.patch("netshaper.system.subprocess.run",
                            return_value=absent), \
                 mock.patch(
                     "netshaper.core.recovery_manager.SubprocessRunner.run"
                 ) as runner_mock, \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True), \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.capture",
                            return_value=mock.Mock()):
                result = ns.load_state_and_cleanup()

            self.assertFalse(result)
            self.assertTrue(os.path.exists(state_path))
            runner_mock.assert_not_called()

    def test_stale_cleanup_recaptures_current_snapshot_after_recovery(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.session_id = "NS-NEW"
        ns.state_snapshot = mock.Mock()
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": 1,
            "ipv6_forwarding": 1,
            "route_localnet": 1,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [],
            "global_rules_applied": False,
            "shaper_base_initialized": False,
            "snapshot": snapshot,
        }
        recaptured = mock.Mock()

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True), \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.capture",
                            return_value=recaptured) as capture_mock:
                result = ns.load_state_and_cleanup()

        self.assertTrue(result)
        capture_mock.assert_called_once_with("eth0", "NS-NEW")
        self.assertIs(ns.state_snapshot, recaptured)

    def test_stale_cleanup_keeps_manifest_when_target_binary_missing(self):
        ns = NetShaper.__new__(NetShaper)
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [{
                "ip": "192.0.2.10",
                "dns": False,
                "http_redirect_port": None,
                "mangle_chain": "NS-MNG-TEST",
                "nat_chain": "NS-NAT-TEST",
            }],
            "global_rules_applied": False,
            "shaper_base_initialized": False,
            "snapshot": snapshot,
        }

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.core.recovery_manager.shutil.which",
                            return_value=None), \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True), \
                 mock.patch("netshaper.core.orchestrator.log"):
                result = ns.load_state_and_cleanup()

            self.assertFalse(result)
            self.assertTrue(os.path.exists(state_path))

    def test_stale_cleanup_does_not_recapture_after_failure(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.session_id = "NS-NEW"
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [],
            "global_rules_applied": False,
            "shaper_base_initialized": True,
            "snapshot": snapshot,
        }

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.core.recovery_manager.shutil.which",
                            return_value=None), \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True), \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.capture") as capture_mock, \
                 mock.patch("netshaper.core.orchestrator.log"):
                result = ns.load_state_and_cleanup()

        self.assertFalse(result)
        capture_mock.assert_not_called()

    def test_remove_state_file_removes_empty_session_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-TEST")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                fh.write("{}")

            NetShaper._remove_state_file(state_path)

            self.assertFalse(os.path.exists(state_path))
            self.assertFalse(os.path.exists(state_dir))


if __name__ == "__main__":
    unittest.main(verbosity=2)
