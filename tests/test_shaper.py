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
        runner_mock.side_effect = [True, True, False, True]
        shaper = TrafficShaper("eth0")

        with self.assertRaisesRegex(RuntimeError, "traffic filter"):
            shaper.apply_target("192.0.2.10", 5.0)

        self.assertEqual(shaper._active_marks, set())
        runner_mock.assert_any_call(
            ["tc", "class", "del", "dev", "eth0", "classid", "1:10"],
            check=False,
            silent=True,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
