import unittest
from unittest import mock

from netshaper.core.session import TargetSession
from netshaper.models import Device
from netshaper.network.firewall import FirewallManager
from netshaper.system import InspectionStatus


class FirewallManagerTests(unittest.TestCase):
    @mock.patch("netshaper.system.subprocess.run")
    def test_chain_ok_dry_run_skips_subprocess(self, run_mock):
        fw = FirewallManager.__new__(FirewallManager)

        with mock.patch("netshaper.network.firewall.config.DRY_RUN", True):
            result = fw._chain_ok("iptables", "mangle", "NS-MNG-TEST")

        self.assertFalse(result)
        run_mock.assert_not_called()

    @mock.patch("netshaper.system.subprocess.run")
    def test_chain_ok_handles_missing_binary(self, run_mock):
        run_mock.side_effect = FileNotFoundError
        fw = FirewallManager.__new__(FirewallManager)

        with mock.patch("netshaper.network.firewall.config.DRY_RUN", False):
            result = fw._chain_ok("iptables", "mangle", "NS-MNG-TEST")

        self.assertFalse(result)

    @mock.patch("netshaper.network.firewall.SubprocessRunner.run")
    def test_cleanup_reports_any_command_failure(self, runner_mock):
        runner_mock.side_effect = [True, False, True, True, True, True]
        fw = FirewallManager.__new__(FirewallManager)
        fw.target_ip = "192.0.2.10"
        fw.interface = "eth0"
        fw._v6 = False
        fw.MANGLE = "NS-MNG-TEST"
        fw.NAT = "NS-NAT-TEST"
        fw._managed_chains = {
            ("iptables", "mangle", "NS-MNG-TEST"),
            ("iptables", "nat", "NS-NAT-TEST"),
        }
        fw._linked_chains = set()
        fw._created_chains = set()
        fw._dns_added = False
        fw._http_added = False
        fw._http_redirect_port = None
        fw._shaping_added = False
        fw._shaping_mark_base = None

        with mock.patch.object(
                fw, "_chain_state",
                return_value=InspectionStatus.PRESENT), \
             mock.patch("netshaper.network.firewall.shutil.which",
                        return_value="/sbin/iptables"):
            result = fw.cleanup()

        self.assertFalse(result)

    def test_cleanup_reports_missing_binary_for_managed_resources(self):
        fw = FirewallManager.__new__(FirewallManager)
        fw.target_ip = "192.0.2.10"
        fw.interface = "eth0"
        fw._v6 = False
        fw.MANGLE = "NS-MNG-TEST"
        fw.NAT = "NS-NAT-TEST"
        fw._managed_chains = {
            ("iptables", "mangle", "NS-MNG-TEST"),
        }
        fw._linked_chains = set()
        fw._created_chains = set()
        fw._dns_added = False
        fw._http_added = False
        fw._http_redirect_port = None
        fw._shaping_added = False
        fw._shaping_mark_base = None

        with mock.patch("netshaper.network.firewall.config.DRY_RUN", False), \
             mock.patch("netshaper.network.firewall.shutil.which",
                        return_value=None), \
             mock.patch("netshaper.network.firewall.log"):
            result = fw.cleanup()

        self.assertFalse(result)
        self.assertEqual(
            fw._managed_chains,
            {("iptables", "mangle", "NS-MNG-TEST")},
        )

    @mock.patch("netshaper.network.firewall.SubprocessRunner.run")
    def test_cleanup_retries_only_remaining_resources(self, runner_mock):
        runner_mock.side_effect = [
            True, True, True,
            True, False,
            True, True, True,
        ]
        fw = FirewallManager.__new__(FirewallManager)
        fw.target_ip = "192.0.2.10"
        fw.interface = "eth0"
        fw._v6 = False
        fw._rule_comment = "netshaper:NS-TEST:192.0.2.10"
        fw.MANGLE = "NS-MNG-TEST"
        fw.NAT = "NS-NAT-TEST"
        fw._managed_chains = {
            ("iptables", "mangle", "NS-MNG-TEST"),
            ("iptables", "nat", "NS-NAT-TEST"),
        }
        fw._linked_chains = set(fw._managed_chains)
        fw._created_chains = set(fw._managed_chains)
        fw._dns_added = False
        fw._http_added = False
        fw._http_redirect_port = None
        fw._dns_input_rules = set()
        fw._http_input_rules = set()
        fw._shaping_added = False
        fw._shaping_mark_base = None

        with mock.patch.object(
                fw, "_chain_state",
                return_value=InspectionStatus.PRESENT), \
             mock.patch.object(
                 fw, "_rule_state",
                 return_value=InspectionStatus.PRESENT), \
             mock.patch("netshaper.network.firewall.shutil.which",
                        return_value="/sbin/iptables"):
            first = fw.cleanup()
            second = fw.cleanup()

        self.assertFalse(first)
        self.assertTrue(second)
        self.assertEqual(fw._managed_chains, set())
        self.assertEqual(fw._linked_chains, set())
        self.assertEqual(fw._created_chains, set())
        self.assertEqual(runner_mock.call_count, 8)

    def test_cleanup_preserves_tracking_when_chain_inspection_errors(self):
        fw = FirewallManager.__new__(FirewallManager)
        fw.target_ip = "192.0.2.10"
        fw.interface = "eth0"
        fw._v6 = False
        fw._rule_comment = "netshaper:NS-TEST:192.0.2.10"
        fw.MANGLE = "NS-MNG-TEST"
        fw.NAT = "NS-NAT-TEST"
        fw._managed_chains = {("iptables", "mangle", "NS-MNG-TEST")}
        fw._linked_chains = set()
        fw._created_chains = set()
        fw._dns_added = False
        fw._http_added = False
        fw._http_redirect_port = None
        fw._dns_input_rules = set()
        fw._http_input_rules = set()
        fw._shaping_added = False
        fw._shaping_mark_base = None

        with mock.patch.object(
                fw, "_chain_state",
                return_value=InspectionStatus.ERROR), \
             mock.patch("netshaper.network.firewall.shutil.which",
                        return_value="/sbin/iptables"), \
             mock.patch("netshaper.network.firewall.log"):
            result = fw.cleanup()

        self.assertFalse(result)
        self.assertEqual(
            fw._managed_chains,
            {("iptables", "mangle", "NS-MNG-TEST")},
        )

    def test_cleanup_preserves_input_rule_when_inspection_errors(self):
        fw = FirewallManager.__new__(FirewallManager)
        fw.target_ip = "192.0.2.10"
        fw.interface = "eth0"
        fw._v6 = False
        fw._rule_comment = "netshaper:NS-TEST:192.0.2.10"
        fw.MANGLE = "NS-MNG-TEST"
        fw.NAT = "NS-NAT-TEST"
        fw._managed_chains = set()
        fw._linked_chains = set()
        fw._created_chains = set()
        fw._dns_added = True
        fw._http_added = False
        fw._http_redirect_port = None
        fw._dns_input_rules = {("iptables", "udp")}
        fw._http_input_rules = set()
        fw._shaping_added = False
        fw._shaping_mark_base = None

        with mock.patch.object(
                fw, "_chain_state",
                return_value=InspectionStatus.ABSENT), \
             mock.patch.object(
                 fw, "_rule_state",
                 return_value=InspectionStatus.ERROR), \
             mock.patch("netshaper.network.firewall.shutil.which",
                        return_value="/sbin/iptables"), \
             mock.patch("netshaper.network.firewall.log"):
            result = fw.cleanup()

        self.assertFalse(result)
        self.assertEqual(fw._dns_input_rules, {("iptables", "udp")})

    @mock.patch("netshaper.network.firewall.SubprocessRunner.run")
    def test_redirect_input_rules_use_session_comment(self, runner_mock):
        runner_mock.return_value = True
        fw = FirewallManager(
            "192.0.2.10",
            "eth0",
            session_id="NS-TEST",
            auto_setup=False,
        )

        result = fw.add_redirect_rules(
            dns_spoof=True,
            http_redirect_port=8088,
        )

        self.assertTrue(result)
        input_commands = [
            call.args[0]
            for call in runner_mock.call_args_list
            if call.args[0][1:3] == ["-I", "INPUT"]
        ]
        self.assertEqual(len(input_commands), 3)
        for command in input_commands:
            self.assertIn("--comment", command)
            self.assertIn("netshaper:NS-TEST:192.0.2.10", command)
        self.assertEqual(
            fw._dns_input_rules,
            {("iptables", "udp"), ("iptables", "tcp")},
        )
        self.assertEqual(fw._http_input_rules, {("iptables", 8088)})

    @mock.patch("netshaper.network.firewall.SubprocessRunner.run")
    def test_setup_journals_each_created_chain_resource(self, runner_mock):
        runner_mock.return_value = True
        journal = mock.Mock(return_value=True)
        fw = FirewallManager(
            "192.0.2.10",
            "eth0",
            session_id="NS-TEST",
            auto_setup=False,
            journal=journal,
        )

        with mock.patch.object(
                fw, "_chain_state",
                return_value=InspectionStatus.ABSENT):
            fw.setup()

        self.assertEqual(journal.call_count, 4)

    def test_setup_fails_on_preexisting_chain(self):
        fw = FirewallManager(
            "192.0.2.10",
            "eth0",
            session_id="NS-TEST",
            auto_setup=False,
        )

        with mock.patch.object(
                fw, "_chain_state",
                return_value=InspectionStatus.PRESENT), \
             mock.patch("netshaper.network.firewall.log"):
            with self.assertRaisesRegex(RuntimeError, "Failed to create firewall chains"):
                fw.setup()

    @mock.patch("netshaper.core.session.FirewallManager.setup")
    def test_target_session_persists_firewall_intent_before_firewall_setup(self, setup_mock):
        events = []

        def journal():
            events.append("journal")
            return True

        def fake_setup(*args, **kwargs):
            events.append("firewall_setup")
            return True

        setup_mock.side_effect = fake_setup
        session = TargetSession(
            Device(ip="192.0.2.10", mac="00:11:22:33:44:55"),
            "eth0",
            "aa:bb:cc:dd:ee:ff",
            "192.0.2.1",
            None,
            "192.0.2.254",
            "ff:ee:dd:cc:bb:aa",
            None,
            None,
            session_id="NS-TEST",
            journal=journal,
        )

        session.setup()

        self.assertEqual(events, ["journal", "firewall_setup"])

    @mock.patch("netshaper.network.firewall.SubprocessRunner.run")
    def test_failed_explicit_setup_keeps_resources_tracked(self, runner_mock):
        runner_mock.side_effect = [
            True, True,
            True, False,
            True, True, True,
            True, False,
        ]
        fw = FirewallManager(
            "192.0.2.10",
            "eth0",
            session_id="NS-TEST",
            auto_setup=False,
        )

        with mock.patch.object(
                fw, "_chain_state",
                side_effect=[
                    InspectionStatus.ABSENT,
                    InspectionStatus.ABSENT,
                    InspectionStatus.PRESENT,
                    InspectionStatus.PRESENT,
                    InspectionStatus.PRESENT,
                    InspectionStatus.PRESENT,
                    InspectionStatus.PRESENT,
                ]), \
             mock.patch.object(
                 fw, "_rule_state",
                 return_value=InspectionStatus.PRESENT), \
             self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            fw.setup()

        self.assertIn(("iptables", "nat", fw.NAT), fw._created_chains)
        self.assertIn(("iptables", "nat", fw.NAT), fw._managed_chains)

    def test_session_scoped_chain_names_are_short(self):
        suffix = FirewallManager._chain_suffix(
            "2001:db8::1234", "NS-ABCDEF")

        self.assertEqual(len(suffix), 10)
        self.assertRegex(suffix, r"^[0-9A-F]+$")


if __name__ == "__main__":
    unittest.main(verbosity=2)
