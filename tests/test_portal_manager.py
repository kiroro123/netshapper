import subprocess
import unittest
from unittest import mock

from netshaper.core.portal_manager import PortalConfig, PortalManager


class PortalManagerTests(unittest.TestCase):
    def test_start_rejects_invalid_dnssec_mode(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])

        with self.assertRaisesRegex(ValueError, "invalid DNSSEC"):
            manager.start(PortalConfig(dnssec_mode="bogus"))

    def test_start_dry_run_reports_suppressed_dnssec_default(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])

        with mock.patch("netshaper.core.portal_manager.config.DRY_RUN", True), \
             mock.patch("netshaper.core.portal_manager.print_flush") as output:
            self.assertTrue(manager.start(PortalConfig(suppress_dnssec=True)))

        self.assertIn("dnssec=fail-open", output.call_args.args[0])

    def test_start_uses_verified_external_portal(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])

        with mock.patch.object(manager, "ready", return_value=True), \
             mock.patch("netshaper.core.portal_manager.check_local_port"
                        ) as port_check, \
             mock.patch("netshaper.core.portal_manager.subprocess.Popen"
                        ) as popen:
            self.assertTrue(manager.start(PortalConfig()))

        port_check.assert_not_called()
        popen.assert_not_called()
        self.assertEqual(manager.get_state_for_persistence(), {})

    def test_state_includes_owned_portal_process(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])
        process = mock.Mock()
        process.pid = 1234
        process.poll.return_value = None
        manager.process = process
        manager._command = [
            "/usr/bin/python3",
            "-m",
            "netshaper.portal",
            "--health-token",
            "token",
        ]
        manager._process_identity = {
            "pid": 1234,
            "process_create_time": 456.0,
            "created_at": 789.0,
        }
        manager._health_token = "token"

        with mock.patch(
            "netshaper.core.portal_manager.process_owner_metadata",
            side_effect=AssertionError("identity should be captured once"),
        ):
            state = manager.get_state_for_persistence()

        self.assertEqual(state["service"], "portal")
        self.assertEqual(state["pid"], 1234)
        self.assertEqual(state["ownership_token"], "token")
        self.assertIn("netshaper.portal", state["argv"])

    def test_attach_owned_process_captures_identity_and_command(self):
        journal = mock.Mock(return_value=True)
        manager = PortalManager(
            "192.0.2.10",
            ["192.0.2.0/24"],
            journal=journal,
        )
        process = mock.Mock()
        process.pid = 1234
        process.poll.return_value = None
        process.args = [
            "/usr/bin/python3",
            "-m",
            "netshaper.portal",
            "--health-token",
            "token",
        ]

        with mock.patch(
            "netshaper.core.portal_manager.process_owner_metadata",
            return_value={
                "pid": 1234,
                "process_create_time": 456.0,
                "created_at": 789.0,
            },
        ) as owner_metadata:
            self.assertTrue(
                manager.attach_owned_process(process, health_token="token")
            )
            state = manager.get_state_for_persistence()

        owner_metadata.assert_called_once_with(1234)
        journal.assert_called_once()
        self.assertEqual(state["pid"], 1234)
        self.assertEqual(state["process_create_time"], 456.0)
        self.assertEqual(state["argv"], process.args)
        self.assertEqual(state["ownership_token"], "token")

    def test_attach_owned_process_stops_when_command_is_missing(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])
        process = mock.Mock()
        process.pid = 1234
        process.poll.side_effect = [None, None, 0]

        self.assertFalse(manager.attach_owned_process(process, health_token="token"))

        process.terminate.assert_called_once()
        self.assertIsNone(manager.process)

    def test_attach_owned_process_stops_when_identity_capture_fails(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])
        process = mock.Mock()
        process.pid = 1234
        process.poll.side_effect = [None, None, 0]
        process.args = [
            "/usr/bin/python3",
            "-m",
            "netshaper.portal",
            "--health-token",
            "token",
        ]

        with mock.patch(
            "netshaper.core.portal_manager.process_owner_metadata",
            return_value={
                "pid": 1234,
                "process_create_time": None,
                "created_at": 789.0,
            },
        ):
            self.assertFalse(
                manager.attach_owned_process(process, health_token="token")
            )

        process.terminate.assert_called_once()
        self.assertIsNone(manager.process)

    def test_start_waits_for_existing_child(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])
        manager.process = mock.Mock()
        manager.process.pid = 1234
        manager.process.poll.return_value = None
        manager.process.args = [
            "/usr/bin/python3",
            "-m",
            "netshaper.portal",
            "--health-token",
            "token",
        ]

        with mock.patch.object(manager, "ready", side_effect=[False, True]), \
             mock.patch("netshaper.core.portal_manager.check_local_port"
                        ) as port_check, \
             mock.patch("netshaper.core.portal_manager.subprocess.Popen"
                        ) as popen, \
             mock.patch(
                 "netshaper.core.portal_manager.process_owner_metadata",
                 return_value={
                     "pid": 1234,
                     "process_create_time": 456.0,
                     "created_at": 789.0,
                 },
             ):
            self.assertTrue(manager.start(PortalConfig()))

        port_check.assert_not_called()
        popen.assert_not_called()

    def test_start_launches_public_portal_module(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])
        process = mock.Mock()
        process.pid = 1234
        process.poll.return_value = None

        with mock.patch.object(manager, "ready", side_effect=[False, True]), \
             mock.patch("netshaper.core.portal_manager.secrets.token_urlsafe",
                        return_value="health-token"), \
             mock.patch("netshaper.core.portal_manager.check_local_port",
                        side_effect=[False, False]), \
             mock.patch("netshaper.core.portal_manager.subprocess.Popen",
                        return_value=process) as popen, \
             mock.patch(
                 "netshaper.core.portal_manager.process_owner_metadata",
                 return_value={
                     "pid": 1234,
                     "process_create_time": 456.0,
                     "created_at": 789.0,
                 },
             ):
            self.assertTrue(
                manager.start(
                    PortalConfig(
                        dnssec_mode="nxdomain",
                        web_security_demo=True,
                        smart_spoof_all=True,
                    )
                )
            )

        command = popen.call_args.args[0]
        self.assertIn("netshaper.portal", command)
        self.assertNotIn("netshaper.fake_server3", command)
        self.assertIn("--smart-spoof-all", command)
        self.assertIn("--hsts-idn-demo", command)
        self.assertIn("nxdomain", command)
        self.assertIn("192.0.2.0/24", command)
        self.assertIn("192.0.2.10/32", command)

    def test_start_stops_child_when_identity_capture_fails(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])
        process = mock.Mock()
        process.pid = 1234
        process.poll.side_effect = [None, 0]

        with mock.patch.object(manager, "ready", return_value=False), \
             mock.patch("netshaper.core.portal_manager.check_local_port",
                        side_effect=[False, False]), \
             mock.patch("netshaper.core.portal_manager.subprocess.Popen",
                        return_value=process), \
             mock.patch(
                 "netshaper.core.portal_manager.process_owner_metadata",
                 return_value={
                     "pid": 1234,
                     "process_create_time": None,
                     "created_at": 789.0,
                 },
             ):
            self.assertFalse(manager.start(PortalConfig()))

        process.terminate.assert_called_once()
        self.assertIsNone(manager.process)

    def test_start_returns_false_when_popen_fails(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])

        with mock.patch.object(manager, "ready", return_value=False), \
             mock.patch("netshaper.core.portal_manager.check_local_port",
                        side_effect=[False, False]), \
             mock.patch("netshaper.core.portal_manager.subprocess.Popen",
                        side_effect=OSError("missing")):
            self.assertFalse(manager.start(PortalConfig()))

    def test_start_returns_false_when_child_exits_during_startup(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])
        process = mock.Mock()
        process.pid = 1234
        process.poll.return_value = 2
        process.returncode = 2

        with mock.patch.object(manager, "ready", side_effect=[False, False]), \
             mock.patch("netshaper.core.portal_manager.check_local_port",
                        side_effect=[False, False]), \
             mock.patch("netshaper.core.portal_manager.subprocess.Popen",
                        return_value=process), \
             mock.patch(
                 "netshaper.core.portal_manager.process_owner_metadata",
                 return_value={
                     "pid": 1234,
                     "process_create_time": 456.0,
                     "created_at": 789.0,
                 },
             ), \
             mock.patch.object(manager, "stop", wraps=manager.stop) as stop_mock:
            self.assertFalse(manager.start(PortalConfig()))

        stop_mock.assert_called_once()

    def test_start_times_out_and_stops_child(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])
        process = mock.Mock()
        process.pid = 1234
        process.poll.return_value = None

        with mock.patch.object(manager, "ready", return_value=False), \
             mock.patch("netshaper.core.portal_manager.check_local_port",
                        side_effect=[False, False]), \
             mock.patch("netshaper.core.portal_manager.subprocess.Popen",
                        return_value=process), \
             mock.patch(
                 "netshaper.core.portal_manager.process_owner_metadata",
                 return_value={
                     "pid": 1234,
                     "process_create_time": 456.0,
                     "created_at": 789.0,
                 },
             ), \
             mock.patch("netshaper.core.portal_manager.time.sleep"), \
             mock.patch.object(manager, "stop", return_value=True) as stop_mock:
            self.assertFalse(manager.start(PortalConfig()))

        self.assertEqual(stop_mock.call_count, 1)

    def test_health_ready_accepts_matching_health_response(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])
        response = mock.Mock()
        response.status = 200
        response.getheader.return_value = "token"
        response.read.return_value = b"token"
        conn = mock.Mock()
        conn.getresponse.return_value = response

        with mock.patch("netshaper.core.portal_manager.http.client.HTTPConnection",
                        return_value=conn):
            self.assertTrue(manager.health_ready("token"))

        conn.request.assert_called_once_with(
            "GET",
            "/_netshaper/health",
            headers={"X-NetShaper-Session": "token"},
        )
        conn.close.assert_called_once()

    def test_health_ready_returns_false_on_connection_error(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])

        with mock.patch("netshaper.core.portal_manager.http.client.HTTPConnection",
                        side_effect=OSError("refused")):
            self.assertFalse(manager.health_ready("token"))

    def test_stop_returns_true_without_process(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])

        self.assertTrue(manager.stop())

    def test_stop_terminates_live_process(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])
        process = mock.Mock()
        process.poll.side_effect = [None, 0]
        manager.process = process

        self.assertTrue(manager.stop())

        process.terminate.assert_called_once()
        process.kill.assert_not_called()
        self.assertIsNone(manager.process)

    def test_stop_kills_process_after_timeout(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])
        process = mock.Mock()
        process.poll.side_effect = [None, 0]
        process.wait.side_effect = [subprocess.TimeoutExpired("portal", 5), None]
        manager.process = process

        self.assertTrue(manager.stop())

        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertIsNone(manager.process)

    def test_stop_reports_cleanup_exception(self):
        manager = PortalManager("192.0.2.10", ["192.0.2.0/24"])
        process = mock.Mock()
        process.poll.side_effect = RuntimeError("boom")
        manager.process = process

        self.assertFalse(manager.stop())
        self.assertIs(manager.process, process)


if __name__ == "__main__":
    unittest.main(verbosity=2)
