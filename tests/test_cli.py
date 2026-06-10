import threading
import unittest
from unittest import mock

from netshaper.models import Device
from netshaper.ui import cli


class CliTests(unittest.TestCase):
    def test_parse_args_accepts_version_flag(self):
        with mock.patch("sys.argv", ["netshaper", "--version"]):
            args = cli.parse_args()
        self.assertTrue(args.version)

    def test_parse_args_accepts_targets_flag(self):
        with mock.patch("sys.argv", ["netshaper", "--targets", "192.0.2.10,192.0.2.11"]):
            args = cli.parse_args()
        self.assertEqual(args.targets, ["192.0.2.10", "192.0.2.11"])

    def test_parse_args_accepts_limit_flag(self):
        with mock.patch("sys.argv", ["netshaper", "--limit", "7.5"]):
            args = cli.parse_args()
        self.assertEqual(args.limit, 7.5)

    def test_parse_args_accepts_authorized_cidr_flag(self):
        with mock.patch("sys.argv", ["netshaper", "--allow-cidr", "192.0.2.0/24"]):
            args = cli.parse_args()
        self.assertEqual(args.allow_cidr, ["192.0.2.0/24"])

    def test_parse_args_rejects_limit_outside_interactive_range(self):
        with mock.patch("sys.argv", ["netshaper", "--limit", "0.01"]), \
             mock.patch("sys.stderr"), \
             self.assertRaises(SystemExit):
            cli.parse_args()

    def test_normalize_feature_choices_rejects_bad_input(self):
        features, invalid = cli.normalize_feature_choices("1 9 x")
        self.assertEqual(features, {1})
        self.assertEqual(invalid, ["9", "x"])

    def test_normalize_feature_choices_accepts_comma_separated_values(self):
        features, invalid = cli.normalize_feature_choices("1, 3,5 6")
        self.assertEqual(features, {1, 3, 5, 6})
        self.assertEqual(invalid, [])

    def test_pick_limit_ui_returns_new_10_mbps_preset(self):
        with mock.patch("netshaper.ui.cli.safe_input", return_value="5"), \
             mock.patch("netshaper.ui.cli.print_flush"):
            self.assertEqual(cli.pick_limit_ui(), 10.0)

    def test_pick_limit_ui_accepts_custom_value_from_new_menu(self):
        with mock.patch("netshaper.ui.cli.safe_input", side_effect=["6", "12.5"]), \
             mock.patch("netshaper.ui.cli.print_flush"):
            self.assertEqual(cli.pick_limit_ui(), 12.5)

    def test_parse_authorized_cidrs_requires_explicit_scope(self):
        with self.assertRaisesRegex(ValueError, "--allow-cidr is required"):
            cli.parse_authorized_cidrs([])

    def test_validate_targets_accepts_authorized_manual_ip(self):
        networks = cli.parse_authorized_cidrs(["192.0.2.0/24"])

        with mock.patch("netshaper.ui.cli.psutil.net_if_addrs",
                        return_value={"eth0": []}):
            result = cli.validate_targets(
                ["192.0.2.10"],
                networks,
                interface="eth0",
                own_ip="192.0.2.1",
                own_ipv6=None,
                gateway_ip="192.0.2.254",
                gateway_ipv6=None,
            )

        self.assertEqual(result, ["192.0.2.10"])

    def test_validate_targets_rejects_gateway_and_out_of_scope(self):
        networks = cli.parse_authorized_cidrs(["192.0.2.0/24"])

        with mock.patch("netshaper.ui.cli.psutil.net_if_addrs",
                        return_value={"eth0": []}):
            with self.assertRaisesRegex(ValueError, "own/gateway"):
                cli.validate_targets(
                    ["192.0.2.254"],
                    networks,
                    interface="eth0",
                    own_ip="192.0.2.1",
                    own_ipv6=None,
                    gateway_ip="192.0.2.254",
                    gateway_ipv6=None,
                )
            with self.assertRaisesRegex(ValueError, "outside authorized"):
                cli.validate_targets(
                    ["198.51.100.10"],
                    networks,
                    interface="eth0",
                    own_ip="192.0.2.1",
                    own_ipv6=None,
                    gateway_ip="192.0.2.254",
                    gateway_ipv6=None,
                )

    def test_choose_interface_rejects_missing_requested_interface(self):
        with mock.patch("netshaper.ui.cli.psutil.net_if_addrs",
                        return_value={}):
            with self.assertRaises(SystemExit):
                cli.choose_interface("missing0")

    def test_choose_interface_reports_inspection_errors_cleanly(self):
        with mock.patch("netshaper.ui.cli.psutil.net_if_addrs",
                        side_effect=PermissionError("blocked")):
            with self.assertRaisesRegex(SystemExit, "Could not inspect"):
                cli.choose_interface("eth0")

    def test_run_active_session_cleans_up_when_sniffer_start_fails(self):
        ns = mock.Mock()
        ns.stop_event = threading.Event()
        ns.save_state.return_value = True
        ns.launch_sniffer.side_effect = RuntimeError("sniffer failed")
        targets = ["192.0.2.10"]

        with mock.patch("netshaper.ui.cli.print_flush"), \
             self.assertRaises(RuntimeError):
            cli.run_active_session(
                ns,
                targets,
                arp_on=True,
                dns_spoof_on=False,
                captive_portal=False,
                http_redirect_port=None,
                throttle_on=False,
                limit=None,
                sniff_on=True,
                save_pcap=False,
                rolling=False,
            )

        ns._apply_global_rules.assert_called_once()
        ns.add_target.assert_called_once_with(
            "192.0.2.10",
            arp_on=True,
            dns_spoof=False,
            captive_portal=False,
            http_redirect_port=None,
            limit=None,
        )
        ns.launch_sniffer.assert_called_once_with(
            target_ips=targets,
            save_pcap=False,
            rolling=False,
        )
        self.assertEqual(ns.save_state.call_count, 3)
        ns.cleanup.assert_called_once()

    def test_run_active_session_passes_discovered_device_to_add_target(self):
        ns = mock.Mock()
        ns.stop_event = threading.Event()
        ns.save_state.return_value = True
        ns.launch_sniffer.side_effect = RuntimeError("sniffer failed")
        target = Device(ip="192.0.2.10", mac="00:11:22:33:44:55")

        with mock.patch("netshaper.ui.cli.print_flush"), \
             self.assertRaises(RuntimeError):
            cli.run_active_session(
                ns,
                [target],
                arp_on=True,
                dns_spoof_on=False,
                captive_portal=False,
                http_redirect_port=None,
                throttle_on=False,
                limit=None,
                sniff_on=True,
                save_pcap=False,
                rolling=False,
            )

        ns.add_target.assert_called_once_with(
            target,
            arp_on=True,
            dns_spoof=False,
            captive_portal=False,
            http_redirect_port=None,
            limit=None,
        )
        ns.launch_sniffer.assert_called_once_with(
            target_ips=["192.0.2.10"],
            save_pcap=False,
            rolling=False,
        )
        ns.cleanup.assert_called_once()

    def test_run_active_session_aborts_before_mutation_when_state_save_fails(self):
        ns = mock.Mock()
        ns.stop_event = threading.Event()
        ns.save_state.return_value = False

        with mock.patch("netshaper.ui.cli.print_flush"), \
             self.assertRaises(RuntimeError):
            cli.run_active_session(
                ns,
                ["192.0.2.10"],
                arp_on=True,
                dns_spoof_on=False,
                captive_portal=False,
                http_redirect_port=None,
                throttle_on=False,
                limit=None,
                sniff_on=False,
                save_pcap=False,
                rolling=False,
            )

        ns._apply_global_rules.assert_not_called()
        ns.add_target.assert_not_called()
        ns.cleanup.assert_called_once()

    def test_run_active_session_rejects_unhealthy_startup(self):
        ns = mock.Mock()
        ns.stop_event = threading.Event()
        ns.save_state.return_value = True
        ns.runtime_health_issues.return_value = [
            "packet sniffer stopped unexpectedly"
        ]

        with mock.patch("netshaper.ui.cli.print_flush"), \
             self.assertRaisesRegex(RuntimeError, "Startup verification failed"):
            cli.run_active_session(
                ns,
                ["192.0.2.10"],
                arp_on=True,
                dns_spoof_on=False,
                captive_portal=False,
                http_redirect_port=None,
                throttle_on=False,
                limit=None,
                sniff_on=False,
                save_pcap=False,
                rolling=False,
            )

        ns.start_monitor_thread.assert_called_once()
        ns.runtime_evidence_lines.assert_not_called()
        ns.cleanup.assert_called_once()

    def test_run_active_session_reports_runtime_health_failure(self):
        class LoopOnceEvent:
            def wait(self, _timeout):
                return False

            def set(self):
                pass

        ns = mock.Mock()
        ns.stop_event = LoopOnceEvent()
        ns.save_state.return_value = True
        ns.runtime_health_issues.side_effect = [
            [],
            ["bandwidth monitor thread is not running"],
        ]
        ns.runtime_evidence_lines.return_value = ["Session ID: NS-TEST"]

        with mock.patch("netshaper.ui.cli.print_flush"), \
             self.assertRaisesRegex(RuntimeError, "Runtime health check failed"):
            cli.run_active_session(
                ns,
                ["192.0.2.10"],
                arp_on=True,
                dns_spoof_on=False,
                captive_portal=False,
                http_redirect_port=None,
                throttle_on=False,
                limit=None,
                sniff_on=False,
                save_pcap=False,
                rolling=False,
            )

        ns.start_monitor_thread.assert_called_once()
        ns.runtime_evidence_lines.assert_called_once()
        ns.cleanup.assert_called_once()

    def test_main_exits_when_stale_recovery_fails(self):
        ns = mock.Mock()
        ns.load_state_and_cleanup.return_value = False

        with mock.patch("sys.argv", [
                "netshaper", "-i", "eth0", "--allow-cidr", "192.0.2.0/24"
             ]), \
             mock.patch("netshaper.ui.cli.SystemChecker.check"), \
             mock.patch("netshaper.ui.cli.choose_interface", return_value="eth0"), \
             mock.patch("netshaper.ui.cli.config.configure_logging"), \
             mock.patch("netshaper.ui.cli.print_flush"), \
             mock.patch("netshaper.core.orchestrator.NetShaper",
                        return_value=ns), \
             self.assertRaises(SystemExit) as cm:
            cli.main()

        self.assertIn(
            "stale NetShaper session could not be fully recovered",
            str(cm.exception),
        )
        ns.close.assert_called_once()

    def test_main_checks_root_before_configuring_file_logging(self):
        with mock.patch("sys.argv", [
                "netshaper", "-i", "eth0", "--allow-cidr", "192.0.2.0/24"
             ]), \
             mock.patch("netshaper.ui.cli.SystemChecker.check",
                        side_effect=SystemExit("[NetShaper] Root required.")), \
             mock.patch("netshaper.ui.cli.config.configure_logging") as logging_mock, \
             self.assertRaises(SystemExit):
            cli.main()

        logging_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
