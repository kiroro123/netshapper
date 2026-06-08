import unittest
from unittest import mock

from netshaper.network.firewall import FirewallManager


class FirewallManagerTests(unittest.TestCase):
    @mock.patch("netshaper.network.firewall.subprocess.run")
    def test_chain_ok_dry_run_skips_subprocess(self, run_mock):
        fw = FirewallManager.__new__(FirewallManager)

        with mock.patch("netshaper.network.firewall.config.DRY_RUN", True):
            result = fw._chain_ok("iptables", "mangle", "NS-MNG-TEST")

        self.assertFalse(result)
        run_mock.assert_not_called()

    @mock.patch("netshaper.network.firewall.subprocess.run")
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
        fw._dns_added = False
        fw._http_added = False
        fw._http_redirect_port = None

        with mock.patch.object(fw, "_chain_ok", return_value=True):
            result = fw.cleanup()

        self.assertFalse(result)

    def test_session_scoped_chain_names_are_short(self):
        suffix = FirewallManager._chain_suffix(
            "2001:db8::1234", "NS-ABCDEF")

        self.assertEqual(len(suffix), 10)
        self.assertRegex(suffix, r"^[0-9A-F]+$")


if __name__ == "__main__":
    unittest.main(verbosity=2)
