import unittest
from unittest import mock

import psutil

from netshaper.core.owner import OwnerStatus, owner_status


class OwnerStatusTests(unittest.TestCase):
    def test_missing_pid_is_stale(self):
        self.assertIs(owner_status({}), OwnerStatus.STALE)

    def test_matching_create_time_is_live(self):
        process = mock.Mock()
        process.create_time.return_value = 123.5

        with mock.patch("netshaper.core.owner.psutil.Process",
                        return_value=process):
            status = owner_status({"pid": 1234, "process_create_time": 123.5})

        self.assertIs(status, OwnerStatus.LIVE)

    def test_different_create_time_is_stale(self):
        process = mock.Mock()
        process.create_time.return_value = 456.0

        with mock.patch("netshaper.core.owner.psutil.Process",
                        return_value=process):
            status = owner_status({"pid": 1234, "process_create_time": 123.5})

        self.assertIs(status, OwnerStatus.STALE)

    def test_missing_process_is_stale(self):
        with mock.patch(
            "netshaper.core.owner.psutil.Process",
            side_effect=psutil.NoSuchProcess(1234),
        ):
            status = owner_status({"pid": 1234, "process_create_time": 123.5})

        self.assertIs(status, OwnerStatus.STALE)

    def test_ambiguous_process_lookup_is_unknown(self):
        with mock.patch(
            "netshaper.core.owner.psutil.Process",
            side_effect=psutil.AccessDenied(1234),
        ):
            status = owner_status({"pid": 1234, "process_create_time": 123.5})

        self.assertIs(status, OwnerStatus.UNKNOWN)

    def test_existing_process_with_legacy_start_time_is_unknown(self):
        process = mock.Mock()
        process.create_time.return_value = 456.0

        with mock.patch("netshaper.core.owner.psutil.Process",
                        return_value=process):
            status = owner_status({"pid": 1234, "process_start_time": "1"})

        self.assertIs(status, OwnerStatus.UNKNOWN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
