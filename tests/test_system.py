import unittest
from unittest import mock

from netshaper import config
from netshaper.system import (
    InspectionStatus,
    SubprocessRunner,
    SystemChecker,
    inspect_resource,
)


class SystemCheckerTests(unittest.TestCase):
    @mock.patch("netshaper.system.log")
    @mock.patch("netshaper.system.subprocess.run")
    def test_subprocess_runner_logs_failures_even_with_check_false(self, run_mock, logger_mock):
        run_mock.return_value = mock.Mock(returncode=1, stderr="boom")

        result = SubprocessRunner.run(["false"], check=False, silent=False)

        self.assertFalse(result)
        logger_mock.error.assert_called_once()

    @mock.patch("netshaper.system.os.geteuid", return_value=1000)
    @mock.patch("netshaper.system.os.makedirs")
    def test_check_allows_dry_run_without_root(self, makedirs_mock, getuid_mock):
        config.DRY_RUN = True
        try:
            SystemChecker.check()
        finally:
            config.DRY_RUN = False

        makedirs_mock.assert_not_called()
        getuid_mock.assert_not_called()

    @mock.patch("netshaper.system.subprocess.run")
    def test_inspect_resource_classifies_present_absent_and_error(self, run_mock):
        run_mock.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        self.assertIs(
            inspect_resource(["iptables", "-C", "FORWARD"]).status,
            InspectionStatus.PRESENT,
        )

        run_mock.return_value = mock.Mock(
            returncode=1,
            stdout="",
            stderr="Bad rule (does a matching rule exist in that chain?).",
        )
        self.assertIs(
            inspect_resource(["iptables", "-C", "FORWARD"]).status,
            InspectionStatus.ABSENT,
        )

        run_mock.return_value = mock.Mock(
            returncode=4,
            stdout="",
            stderr="Permission denied (you must be root)",
        )
        self.assertIs(
            inspect_resource(["iptables", "-C", "FORWARD"]).status,
            InspectionStatus.ERROR,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
