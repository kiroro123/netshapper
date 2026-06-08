import unittest
from types import SimpleNamespace
from unittest import mock

from netshaper.network.shaper import TrafficShaper


class TrafficShaperTests(unittest.TestCase):
    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.subprocess.run")
    def test_apply_target_refuses_to_replace_foreign_root_qdisc(
            self, run_mock, runner_mock):
        run_mock.return_value = SimpleNamespace(
            returncode=0,
            stdout="qdisc fq_codel 0: root refcnt 2",
        )
        shaper = TrafficShaper("eth0")

        with self.assertRaisesRegex(RuntimeError, "Refusing to replace"):
            shaper.apply_target("192.0.2.10", 5.0)

        runner_mock.assert_not_called()

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.subprocess.run")
    def test_apply_target_refuses_preexisting_htb_root_qdisc(
            self, run_mock, runner_mock):
        run_mock.return_value = SimpleNamespace(
            returncode=0,
            stdout="qdisc htb 1: root refcnt 2",
        )
        shaper = TrafficShaper("eth0")

        with self.assertRaisesRegex(RuntimeError, "Refusing to replace"):
            shaper.apply_target("192.0.2.10", 5.0)

        runner_mock.assert_not_called()

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.subprocess.run")
    def test_cleanup_ignores_foreign_root_qdisc(self, run_mock, runner_mock):
        run_mock.return_value = SimpleNamespace(
            returncode=0,
            stdout="qdisc fq_codel 0: root refcnt 2",
        )
        shaper = TrafficShaper("eth0")

        result = shaper.cleanup()

        self.assertTrue(result)
        runner_mock.assert_not_called()

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.subprocess.run")
    def test_cleanup_removes_netshaper_owned_root_qdisc(
            self, run_mock, runner_mock):
        run_mock.return_value = SimpleNamespace(
            returncode=0,
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
    @mock.patch("netshaper.network.shaper.subprocess.run")
    def test_apply_target_fails_if_root_qdisc_cannot_be_created(
            self, run_mock, runner_mock):
        run_mock.return_value = SimpleNamespace(returncode=0, stdout="")
        runner_mock.return_value = False
        shaper = TrafficShaper("eth0")

        with self.assertRaisesRegex(RuntimeError, "Failed to create"):
            shaper.apply_target("192.0.2.10", 5.0)

        self.assertFalse(shaper._base_initialized)

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    @mock.patch("netshaper.network.shaper.subprocess.run")
    def test_apply_target_rolls_back_partial_setup(
            self, run_mock, runner_mock):
        run_mock.return_value = SimpleNamespace(returncode=0, stdout="")
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
    @mock.patch("netshaper.network.shaper.subprocess.run")
    def test_failed_root_cleanup_preserves_ownership_for_retry(
            self, run_mock, runner_mock):
        run_mock.return_value = SimpleNamespace(
            returncode=0,
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
    @mock.patch("netshaper.network.shaper.subprocess.run")
    def test_failed_partial_setup_keeps_root_owned_for_retry(
            self, run_mock, runner_mock):
        run_mock.return_value = SimpleNamespace(returncode=0, stdout="")
        runner_mock.side_effect = [True, True, True, False, True, True, False]
        shaper = TrafficShaper("eth0")

        with self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            shaper.apply_target("192.0.2.10", 5.0)

        self.assertTrue(shaper._base_initialized)
        self.assertEqual(shaper._active_marks, set())

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

    @mock.patch("netshaper.network.shaper.SubprocessRunner.run")
    def test_failed_cleanup_target_preserves_active_mark(self, runner_mock):
        runner_mock.side_effect = [False, True, True, True, True, True]
        shaper = TrafficShaper("eth0")
        shaper._active_marks.add(10)

        result = shaper.cleanup_target(10)

        self.assertFalse(result)
        self.assertIn(10, shaper._active_marks)


if __name__ == "__main__":
    unittest.main(verbosity=2)
