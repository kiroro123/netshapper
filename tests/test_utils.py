import unittest
from unittest import mock

from netshaper import utils


class UtilsTests(unittest.TestCase):
    def test_safe_input_skips_stty_when_not_tty(self):
        with mock.patch("netshaper.utils.sys.stdin.isatty", return_value=False), \
             mock.patch("netshaper.utils.sys.stdout.isatty", return_value=False), \
             mock.patch("netshaper.utils.subprocess.run") as run_mock, \
             mock.patch("builtins.input", return_value=" y "):
            result = utils.safe_input()

        self.assertEqual(result, "y")
        run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
