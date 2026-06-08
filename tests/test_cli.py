import threading
import unittest
from unittest import mock

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

    def test_parse_args_rejects_limit_outside_interactive_range(self):
        with mock.patch("sys.argv", ["netshaper", "--limit", "0.01"]), \
             mock.patch("sys.stderr"), \
             self.assertRaises(SystemExit):
            cli.parse_args()

    def test_normalize_feature_choices_rejects_bad_input(self):
        features, invalid = cli.normalize_feature_choices("1 9 x")
        self.assertEqual(features, {1})
        self.assertEqual(invalid, ["9", "x"])

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
