import unittest
from unittest import mock

from netshaper import config
from netshaper.system import SystemChecker


class SystemCheckerTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
