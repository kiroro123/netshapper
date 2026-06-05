import unittest
from unittest import mock

from netshaper.ui import cli


class CliTests(unittest.TestCase):
    def test_parse_args_accepts_version_flag(self):
        with mock.patch("sys.argv", ["netshaper", "--version"]):
            args = cli.parse_args()
        self.assertTrue(args.version)

    def test_normalize_feature_choices_rejects_bad_input(self):
        features, invalid = cli.normalize_feature_choices("1 9 x")
        self.assertEqual(features, {1})
        self.assertEqual(invalid, ["9", "x"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
