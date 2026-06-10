import unittest
from unittest import mock

from netshaper.network.shaper import TrafficShaper
from netshaper.system import InspectionResult, InspectionStatus


class TrafficShaperTests(unittest.TestCase):
    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.inspect_resource")
    def test_apply_target_refuses_to_replace_foreign_root_qdisc(
            self, inspect_mock, runner_mock):
        inspect_mock.return_value = InspectionResult(
            InspectionStatus.PRESENT,
            stdout="qdisc fq_codel 0: root refcnt 2",
        )
        shaper = TrafficShaper("eth0")

        with self.assertRaisesRegex(RuntimeError, "Refusing to replace"):
            shaper.apply_target("192.0.2.10", 5.0)

        runner_mock.assert_not_called()

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.inspect_resource")
    def test_apply_target_refuses_preexisting_htb_root_qdisc(
            self, inspect_mock, runner_mock):
        inspect_mock.return_value = InspectionResult(
            InspectionStatus.PRESENT,
            stdout="qdisc htb 1: root refcnt 2",
        )
        shaper = TrafficShaper("eth0")

        with self.assertRaisesRegex(RuntimeError, "Refusing to replace"):
            shaper.apply_target("192.0.2.10", 5.0)

        runner_mock.assert_not_called()

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.inspect_resource")
    def test_apply_target_allows_implicit_noqueue_root_qdisc(
            self, inspect_mock, runner_mock):
        inspect_mock.side_effect = [
            InspectionResult(
                InspectionStatus.PRESENT,
                stdout="qdisc noqueue 0: root refcnt 2",
            ),
            InspectionResult(
                InspectionStatus.PRESENT,
                stdout="qdisc htb 1: root refcnt 2",
            ),
        ]
        runner_mock.return_value = True
        shaper = TrafficShaper("eth0")

        shaper.apply_target("192.0.2.10", 5.0)

        runner_mock.assert_any_call(
            ["tc", "qdisc", "add", "dev", "eth0",
             "root", "handle", "1:", "htb"],
        )
        self.assertTrue(shaper._base_initialized)

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.inspect_resource")
    def test_cleanup_ignores_foreign_root_qdisc(
            self, inspect_mock, runner_mock):
        inspect_mock.return_value = InspectionResult(
            InspectionStatus.PRESENT,
            stdout="qdisc fq_codel 0: root refcnt 2",
        )
        shaper = TrafficShaper("eth0")
        shaper._base_initialized = True
        shaper._active_marks.add(10)

        result = shaper.cleanup()

        self.assertTrue(result)
        self.assertFalse(shaper._base_initialized)
        self.assertEqual(shaper._active_marks, set())
        runner_mock.assert_not_called()

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.inspect_resource")
    def test_cleanup_removes_netshaper_owned_root_qdisc(
            self, inspect_mock, runner_mock):
        inspect_mock.return_value = InspectionResult(
            InspectionStatus.PRESENT,
            stdout="qdisc htb 1: root refcnt 2",
        )
        shaper = TrafficShaper("eth0")
        shaper._base_initialized = True

        result = shaper.cleanup()

        self.assertTrue(result)
        runner_mock.assert_called_once_with(
            ["tc", "qdisc", "del", "dev", "eth0", "root"],
            check=False,
            silent=True,
        )

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.inspect_resource")
    def test_cleanup_clears_ownership_when_root_qdisc_absent(
            self, inspect_mock, runner_mock):
        inspect_mock.return_value = InspectionResult(InspectionStatus.ABSENT)
        shaper = TrafficShaper("eth0")
        shaper._base_initialized = True
        shaper._active_marks.add(10)
        shaper._target_filters.add((10, "ip"))
        shaper._target_classes.add(10)
        shaper._tracked_mark_bases.add(10)

        result = shaper.cleanup()

        self.assertTrue(result)
        self.assertFalse(shaper._base_initialized)
        self.assertEqual(shaper._active_marks, set())
        self.assertEqual(shaper._target_filters, set())
        self.assertEqual(shaper._target_classes, set())
        self.assertEqual(shaper._tracked_mark_bases, set())
        runner_mock.assert_not_called()

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.inspect_resource")
    def test_cleanup_preserves_ownership_when_root_inspection_errors(
            self, inspect_mock, runner_mock):
        inspect_mock.return_value = InspectionResult(
            InspectionStatus.ERROR,
            stderr="Operation not permitted",
        )
        shaper = TrafficShaper("eth0")
        shaper._base_initialized = True
        shaper._active_marks.add(10)

        result = shaper.cleanup()

        self.assertFalse(result)
        self.assertTrue(shaper._base_initialized)
        self.assertEqual(shaper._active_marks, {10})
        runner_mock.assert_not_called()

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.inspect_resource")
    def test_apply_target_fails_if_root_qdisc_cannot_be_created(
            self, inspect_mock, runner_mock):
        inspect_mock.return_value = InspectionResult(InspectionStatus.ABSENT)
        runner_mock.return_value = False
        shaper = TrafficShaper("eth0")

        with self.assertRaisesRegex(RuntimeError, "Failed to create"):
            shaper.apply_target("192.0.2.10", 5.0)

        self.assertFalse(shaper._base_initialized)

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.inspect_resource")
    def test_apply_target_rolls_back_partial_setup(
            self, inspect_mock, runner_mock):
        inspect_mock.side_effect = [
            InspectionResult(InspectionStatus.ABSENT),
            InspectionResult(
                InspectionStatus.PRESENT,
                stdout="qdisc htb 1: root refcnt 2",
            ),
            InspectionResult(
                InspectionStatus.PRESENT,
                stdout="qdisc htb 1: root refcnt 2",
            ),
        ]
        runner_mock.side_effect = [True, True, True, False, True, True, True]
        shaper = TrafficShaper("eth0")

        with self.assertRaisesRegex(RuntimeError, "traffic filter"):
            shaper.apply_target("192.0.2.10", 5.0)

        self.assertEqual(shaper._active_marks, set())
        self.assertFalse(shaper._base_initialized)
        runner_mock.assert_any_call(
            ["tc", "class", "del", "dev", "eth0", "classid", "1:10"],
            check=False,
            silent=True,
        )
        runner_mock.assert_any_call(
            ["tc", "qdisc", "del", "dev", "eth0", "root"],
            check=False,
            silent=True,
        )

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.inspect_resource")
    def test_failed_root_cleanup_preserves_ownership_for_retry(
            self, inspect_mock, runner_mock):
        inspect_mock.return_value = InspectionResult(
            InspectionStatus.PRESENT,
            stdout="qdisc htb 1: root refcnt 2",
        )
        runner_mock.side_effect = [False, True]
        shaper = TrafficShaper("eth0")
        shaper._base_initialized = True
        shaper._active_marks.add(10)

        first = shaper.cleanup()
        second = shaper.cleanup()

        self.assertFalse(first)
        self.assertTrue(second)
        self.assertFalse(shaper._base_initialized)
        self.assertEqual(shaper._active_marks, set())
        self.assertEqual(runner_mock.call_count, 2)

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.inspect_resource")
    def test_failed_partial_setup_keeps_root_owned_for_retry(
            self, inspect_mock, runner_mock):
        inspect_mock.side_effect = [
            InspectionResult(InspectionStatus.ABSENT),
            InspectionResult(
                InspectionStatus.PRESENT,
                stdout="qdisc htb 1: root refcnt 2",
            ),
            InspectionResult(
                InspectionStatus.PRESENT,
                stdout="qdisc htb 1: root refcnt 2",
            ),
        ]
        runner_mock.side_effect = [True, True, True, False, True, True, False]
        shaper = TrafficShaper("eth0")

        with self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            shaper.apply_target("192.0.2.10", 5.0)

        self.assertTrue(shaper._base_initialized)
        self.assertEqual(shaper._active_marks, set())

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.inspect_resource")
    def test_apply_target_journals_each_created_resource(
            self, inspect_mock, runner_mock):
        inspect_mock.side_effect = [
            InspectionResult(InspectionStatus.ABSENT),
            InspectionResult(
                InspectionStatus.PRESENT,
                stdout="qdisc htb 1: root refcnt 2",
            ),
        ]
        runner_mock.return_value = True
        journal = mock.Mock(return_value=True)
        shaper = TrafficShaper("eth0")

        shaper.apply_target(
            "192.0.2.10",
            5.0,
            journal=journal,
        )

        self.assertEqual(journal.call_count, 8)

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    def test_cleanup_target_removes_protocol_specific_filters(self, runner_mock):
        runner_mock.return_value = True
        shaper = TrafficShaper("eth0")
        shaper._active_marks.add(10)

        result = shaper.cleanup_target(10)

        self.assertTrue(result)
        runner_mock.assert_any_call(
            ["tc", "filter", "del", "dev", "eth0",
             "parent", "1:", "protocol", "ip",
             "handle", "10", "fw"],
            check=False,
            silent=True,
        )
        runner_mock.assert_any_call(
            ["tc", "filter", "del", "dev", "eth0",
             "parent", "1:", "protocol", "ipv6",
             "handle", "20", "fw"],
            check=False,
            silent=True,
        )
        self.assertNotIn(10, shaper._active_marks)

    @mock.patch("netshaper.network.shaper.inspect_resource")
    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    def test_failed_cleanup_target_preserves_active_mark(
            self, runner_mock, inspect_mock):
        runner_mock.side_effect = [False, True, True, True, True, True]
        inspect_mock.return_value = InspectionResult(
            InspectionStatus.PRESENT,
            stdout="filter protocol ip handle 0xa fw classid 1:10",
        )
        shaper = TrafficShaper("eth0")
        shaper._active_marks.add(10)

        result = shaper.cleanup_target(10)

        self.assertFalse(result)
        self.assertIn(10, shaper._active_marks)

    @mock.patch("netshaper.network.shaper.inspect_resource")
    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    def test_partial_cleanup_target_retries_only_remaining_resources(
            self, runner_mock, inspect_mock):
        runner_mock.side_effect = [True, False, True, True, True, True, True]
        inspect_mock.return_value = InspectionResult(
            InspectionStatus.PRESENT,
            stdout="filter protocol ipv6 handle 0xa fw classid 1:10",
        )
        shaper = TrafficShaper("eth0")
        shaper._active_marks.add(10)
        shaper._tracked_mark_bases.add(10)
        shaper._target_filters = {
            (10, "ip"),
            (10, "ipv6"),
            (20, "ip"),
            (20, "ipv6"),
        }
        shaper._target_classes = {10, 20}

        first = shaper.cleanup_target(10)
        second = shaper.cleanup_target(10)

        self.assertFalse(first)
        self.assertTrue(second)
        self.assertNotIn(10, shaper._active_marks)
        self.assertEqual(shaper._target_filters, set())
        self.assertEqual(shaper._target_classes, set())
        self.assertEqual(runner_mock.call_count, 7)

    @mock.patch("netshaper.network.shaper.inspect_resource")
    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    def test_cleanup_target_treats_absent_filter_as_clean(
            self, runner_mock, inspect_mock):
        runner_mock.return_value = False
        inspect_mock.return_value = InspectionResult(
            InspectionStatus.PRESENT,
            stdout="",
        )
        shaper = TrafficShaper("eth0")
        shaper._active_marks.add(10)
        shaper._tracked_mark_bases.add(10)
        shaper._target_filters = {(10, "ip")}
        shaper._target_classes = set()

        result = shaper.cleanup_target(10)

        self.assertTrue(result)
        self.assertEqual(shaper._target_filters, set())
        self.assertNotIn(10, shaper._active_marks)

    @mock.patch("netshaper.network.shaper.inspect_resource")
    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    def test_cleanup_target_treats_absent_class_as_clean(
            self, runner_mock, inspect_mock):
        runner_mock.return_value = False
        inspect_mock.return_value = InspectionResult(
            InspectionStatus.PRESENT,
            stdout="",
        )
        shaper = TrafficShaper("eth0")
        shaper._active_marks.add(10)
        shaper._tracked_mark_bases.add(10)
        shaper._target_filters = set()
        shaper._target_classes = {10}

        result = shaper.cleanup_target(10)

        self.assertTrue(result)
        self.assertEqual(shaper._target_classes, set())
        self.assertNotIn(10, shaper._active_marks)


if __name__ == "__main__":
    unittest.main(verbosity=2)
