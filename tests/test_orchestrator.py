import json
import os
import tempfile
import threading
import unittest
from unittest import mock

from netshaper.core.orchestrator import NetShaper
from netshaper.models import Device


class NetShaperCleanupTests(unittest.TestCase):
    def test_add_target_rejects_duplicate_target(self):
        ns = NetShaper.__new__(NetShaper)
        ns._lifecycle_lock = threading.RLock()
        ns.sessions = {"192.0.2.10": mock.Mock()}

        with self.assertRaisesRegex(ValueError, "already active"):
            ns.add_target(Device(ip="192.0.2.10", mac="00:11:22:33:44:55"))

    def test_cleanup_keeps_session_incomplete_when_steps_fail(self):
        ns = NetShaper.__new__(NetShaper)
        ns._lifecycle_lock = threading.RLock()
        ns._cleanup_running = False
        ns._cleanup_complete = False
        ns.is_shutting_down = False
        ns.stop_event = threading.Event()
        ns.sessions = {}
        ns.sniffer = mock.Mock()
        ns.sniffer.stop.side_effect = RuntimeError("sniffer stop failed")
        mitm_proc = mock.Mock()
        mitm_proc.poll.return_value = None
        mitm_proc.terminate.side_effect = RuntimeError("mitm stop failed")
        ns._mitm_proc = mitm_proc
        ns._remove_global_rules = mock.Mock(side_effect=RuntimeError("rules failed"))
        ns.state_snapshot = mock.Mock()
        ns.shaper = mock.Mock()
        ns.shaper.cleanup.side_effect = RuntimeError("shaper failed")
        ns.session_id = "NS-TEST"

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
             mock.patch("netshaper.core.orchestrator.print_flush"), \
             mock.patch("netshaper.core.orchestrator.log"), \
             mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                        side_effect=RuntimeError("restore failed")) as restore_mock:
            ns.cleanup()

        ns.sniffer.stop.assert_called_once()
        mitm_proc.terminate.assert_called_once()
        ns._remove_global_rules.assert_called_once()
        restore_mock.assert_called_once_with(ns.state_snapshot)
        ns.shaper.cleanup.assert_called_once()
        self.assertFalse(ns._cleanup_complete)

    def test_add_target_rolls_back_partially_created_session(self):
        ns = NetShaper.__new__(NetShaper)
        ns._lifecycle_lock = threading.RLock()
        ns.sessions = {}
        ns.mark_pool = mock.Mock()
        ns.mark_pool.acquire.return_value = 10
        ns.interface = "eth0"
        ns.own_mac = "aa:bb:cc:dd:ee:ff"
        ns.own_ip = "192.0.2.1"
        ns.own_ipv6 = None
        ns.gw = "192.0.2.254"
        ns.gw_mac = "ff:ee:dd:cc:bb:aa"
        ns.gw_ipv6 = None
        ns.shaper = mock.Mock()
        target = Device(ip="192.0.2.10", mac="00:11:22:33:44:55")

        with mock.patch("netshaper.core.orchestrator.TargetSession") as session_cls:
            session = session_cls.return_value
            session.setup.side_effect = RuntimeError("setup failed")

            with self.assertRaises(RuntimeError):
                ns.add_target(target)

        self.assertEqual(ns.sessions, {})
        session.cleanup.assert_called_once()
        ns.mark_pool.release.assert_called_once_with("192.0.2.10")

    def test_failed_rollback_keeps_session_for_retry(self):
        ns = NetShaper.__new__(NetShaper)
        ns._lifecycle_lock = threading.RLock()
        ns.sessions = {}
        ns.mark_pool = mock.Mock()
        ns.mark_pool.acquire.return_value = 10
        ns.interface = "eth0"
        ns.own_mac = "aa:bb:cc:dd:ee:ff"
        ns.own_ip = "192.0.2.1"
        ns.own_ipv6 = None
        ns.gw = "192.0.2.254"
        ns.gw_mac = "ff:ee:dd:cc:bb:aa"
        ns.gw_ipv6 = None
        ns.shaper = mock.Mock()
        ns.save_state = mock.Mock(return_value=True)
        target = Device(ip="192.0.2.10", mac="00:11:22:33:44:55")

        with mock.patch("netshaper.core.orchestrator.TargetSession") as session_cls, \
             mock.patch("netshaper.core.orchestrator.log"):
            session = session_cls.return_value
            session.setup.side_effect = RuntimeError("setup failed")
            session.cleanup.return_value = False

            with self.assertRaises(RuntimeError):
                ns.add_target(target)

        self.assertIs(ns.sessions["192.0.2.10"], session)
        session.cleanup.assert_called_once()
        ns.mark_pool.release.assert_not_called()
        ns.save_state.assert_called_once()

    def test_remove_target_keeps_failed_cleanup_registered(self):
        ns = NetShaper.__new__(NetShaper)
        ns._lifecycle_lock = threading.RLock()
        session = mock.Mock()
        session.cleanup.return_value = False
        ns.sessions = {"192.0.2.10": session}
        ns.mark_pool = mock.Mock()

        with mock.patch("netshaper.core.orchestrator.log"):
            result = ns.remove_target("192.0.2.10")

        self.assertFalse(result)
        self.assertIs(ns.sessions["192.0.2.10"], session)
        ns.mark_pool.release.assert_not_called()

    def test_dry_run_launch_sniffer_does_not_start_capture(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.sniffer = None

        with mock.patch("netshaper.core.orchestrator.config.DRY_RUN", True), \
             mock.patch("netshaper.core.orchestrator.PacketSniffer") as sniffer_cls, \
             mock.patch("netshaper.core.orchestrator.print_flush"):
            ns.launch_sniffer(["192.0.2.10"])

        sniffer_cls.assert_not_called()
        self.assertIsNone(ns.sniffer)

    def test_dry_run_launch_mitmproxy_does_not_start_process(self):
        ns = NetShaper.__new__(NetShaper)
        ns.own_ip = "192.0.2.1"

        with mock.patch("netshaper.core.orchestrator.config.DRY_RUN", True), \
             mock.patch("netshaper.core.orchestrator.subprocess.Popen") as popen_mock, \
             mock.patch("netshaper.core.orchestrator.print_flush"):
            result = ns.launch_mitmproxy()

        self.assertTrue(result)
        popen_mock.assert_not_called()

    def test_launch_mitmproxy_reaps_process_when_readiness_fails(self):
        ns = NetShaper.__new__(NetShaper)
        ns.own_ip = "192.0.2.1"
        proc = mock.Mock()
        proc.poll.side_effect = [None, 0]

        with mock.patch("netshaper.core.orchestrator.config.DRY_RUN", False), \
             mock.patch("netshaper.core.orchestrator.check_local_port",
                        return_value=False), \
             mock.patch("netshaper.core.orchestrator.subprocess.Popen",
                        return_value=proc), \
             mock.patch("netshaper.core.orchestrator.time.sleep"), \
             mock.patch("netshaper.core.orchestrator.log"):
            result = ns.launch_mitmproxy()

        self.assertFalse(result)
        proc.terminate.assert_called_once()
        proc.wait.assert_called_once_with(timeout=5)
        self.assertIsNone(ns._mitm_proc)

    def test_failed_mitmproxy_termination_keeps_process_for_retry(self):
        ns = NetShaper.__new__(NetShaper)
        proc = mock.Mock()
        proc.poll.return_value = None
        proc.terminate.side_effect = RuntimeError("nope")
        ns._mitm_proc = proc

        with mock.patch("netshaper.core.orchestrator.log"):
            first = ns._terminate_mitmproxy()

        proc.terminate.side_effect = None
        proc.poll.side_effect = [None, 0]
        second = ns._terminate_mitmproxy()

        self.assertFalse(first)
        self.assertTrue(second)
        self.assertIsNone(ns._mitm_proc)
        self.assertEqual(proc.terminate.call_count, 2)

    def test_instance_lock_rejects_second_holder(self):
        first = NetShaper.__new__(NetShaper)
        second = NetShaper.__new__(NetShaper)
        first._lock_file = None
        second._lock_file = None
        first._owner_metadata = {"pid": 111, "process_start_time": "1"}
        second._owner_metadata = {"pid": 222, "process_start_time": "2"}

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
             mock.patch("netshaper.core.orchestrator.config.DRY_RUN", False):
            first._acquire_instance_lock()
            try:
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    second._acquire_instance_lock()
            finally:
                first._release_instance_lock()
                second._release_instance_lock()

    def test_apply_global_rules_tags_firewall_rules_with_session_comment(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.session_id = "NS-TEST"
        ns._global_rules_applied = False

        with mock.patch("netshaper.core.orchestrator.shutil.which",
                        return_value="/sbin/tool"), \
             mock.patch("netshaper.core.orchestrator.SubprocessRunner.run",
                        return_value=True) as runner_mock:
            ns._apply_global_rules()

        comment = "netshaper:NS-TEST:global"
        firewall_cmds = [
            call.args[0]
            for call in runner_mock.call_args_list
            if call.args[0][0] in {"iptables", "ip6tables"}
        ]
        self.assertEqual(len(firewall_cmds), 6)
        for command in firewall_cmds:
            self.assertIn("-m", command)
            self.assertIn("comment", command)
            self.assertIn("--comment", command)
            self.assertIn(comment, command)
        self.assertTrue(ns._global_rules_applied)
        self.assertEqual(
            ns._global_firewall_binaries_applied,
            ["iptables", "ip6tables"],
        )

    def test_remove_global_rules_deletes_only_session_comment(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.session_id = "NS-TEST"
        ns.state_snapshot = mock.Mock(
            ipv4_forwarding=None,
            ipv6_forwarding=None,
            route_localnet=None,
        )
        ns._global_rules_applied = True
        ns._global_firewall_binaries_applied = ["iptables"]

        with mock.patch("netshaper.core.orchestrator.shutil.which",
                        return_value="/sbin/iptables"), \
             mock.patch("netshaper.core.orchestrator.SubprocessRunner.run",
                        return_value=True) as runner_mock:
            result = ns._remove_global_rules()

        comment = "netshaper:NS-TEST:global"
        delete_commands = [call.args[0] for call in runner_mock.call_args_list]
        self.assertTrue(result)
        self.assertEqual(len(delete_commands), 3)
        for command in delete_commands:
            self.assertIn("--comment", command)
            self.assertIn(comment, command)
        self.assertNotIn(
            ["iptables", "-D", "FORWARD",
             "-i", "eth0", "-o", "eth0", "-j", "ACCEPT"],
            delete_commands,
        )
        self.assertFalse(ns._global_rules_applied)
        self.assertEqual(ns._global_firewall_binaries_applied, [])

    def test_stale_cleanup_removes_recorded_tc_root_qdisc(self):
        ns = NetShaper.__new__(NetShaper)
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [],
            "global_rules_applied": False,
            "shaper_base_initialized": True,
            "snapshot": snapshot,
        }

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.core.orchestrator.subprocess.run",
                            return_value=mock.Mock(
                                returncode=0,
                                stdout="qdisc htb 1: root refcnt 2\n",
                            )), \
                 mock.patch("netshaper.core.orchestrator.SubprocessRunner.run",
                            return_value=True) as runner_mock, \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True):
                ns.load_state_and_cleanup()

            runner_mock.assert_any_call(
                ["tc", "qdisc", "del", "dev", "eth0", "root"],
                check=False,
                silent=True,
            )
            self.assertFalse(os.path.exists(state_path))

    def test_stale_cleanup_removes_only_commented_global_rules(self):
        ns = NetShaper.__new__(NetShaper)
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        comment = "netshaper:NS-OLD:global"
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [],
            "global_rules_applied": True,
            "global_rule_comment": comment,
            "global_firewall_binaries": ["iptables"],
            "shaper_base_initialized": False,
            "snapshot": snapshot,
        }

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.core.orchestrator.shutil.which",
                            return_value="/sbin/iptables"), \
                 mock.patch("netshaper.core.orchestrator.subprocess.run",
                            return_value=mock.Mock(returncode=0, stdout="")), \
                 mock.patch("netshaper.core.orchestrator.SubprocessRunner.run",
                            return_value=True) as runner_mock, \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True):
                result = ns.load_state_and_cleanup()

            delete_commands = [call.args[0] for call in runner_mock.call_args_list]
            self.assertTrue(result)
            self.assertEqual(len(delete_commands), 3)
            for command in delete_commands:
                self.assertIn("--comment", command)
                self.assertIn(comment, command)
            self.assertNotIn(
                ["iptables", "-D", "FORWARD",
                 "-i", "eth0", "-o", "eth0", "-j", "ACCEPT"],
                delete_commands,
            )
            self.assertFalse(os.path.exists(state_path))

    def test_stale_cleanup_treats_absent_recorded_resources_as_clean(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.session_id = "NS-NEW"
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [{
                "ip": "192.0.2.10",
                "dns": True,
                "http_redirect_port": 8088,
                "mangle_chain": "NS-MNG-TEST",
                "nat_chain": "NS-NAT-TEST",
            }],
            "global_rules_applied": True,
            "global_firewall_binaries": ["iptables"],
            "shaper_base_initialized": True,
            "snapshot": snapshot,
        }
        absent = mock.Mock(returncode=1, stdout="")

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.core.orchestrator.shutil.which",
                            return_value="/sbin/tool"), \
                 mock.patch("netshaper.core.orchestrator.subprocess.run",
                            return_value=absent), \
                 mock.patch(
                     "netshaper.core.orchestrator.SubprocessRunner.run"
                 ) as runner_mock, \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True), \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.capture",
                            return_value=mock.Mock()):
                result = ns.load_state_and_cleanup()

            self.assertTrue(result)
            self.assertFalse(os.path.exists(state_path))
            runner_mock.assert_not_called()

    def test_stale_cleanup_recaptures_current_snapshot_after_recovery(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.session_id = "NS-NEW"
        ns.state_snapshot = mock.Mock()
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": 1,
            "ipv6_forwarding": 1,
            "route_localnet": 1,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [],
            "global_rules_applied": False,
            "shaper_base_initialized": False,
            "snapshot": snapshot,
        }
        recaptured = mock.Mock()

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True), \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.capture",
                            return_value=recaptured) as capture_mock:
                result = ns.load_state_and_cleanup()

        self.assertTrue(result)
        capture_mock.assert_called_once_with("eth0", "NS-NEW")
        self.assertIs(ns.state_snapshot, recaptured)

    def test_stale_cleanup_keeps_manifest_when_target_binary_missing(self):
        ns = NetShaper.__new__(NetShaper)
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [{
                "ip": "192.0.2.10",
                "dns": False,
                "http_redirect_port": None,
                "mangle_chain": "NS-MNG-TEST",
                "nat_chain": "NS-NAT-TEST",
            }],
            "global_rules_applied": False,
            "shaper_base_initialized": False,
            "snapshot": snapshot,
        }

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.core.orchestrator.shutil.which",
                            return_value=None), \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True), \
                 mock.patch("netshaper.core.orchestrator.log"):
                result = ns.load_state_and_cleanup()

            self.assertFalse(result)
            self.assertTrue(os.path.exists(state_path))

    def test_stale_cleanup_does_not_recapture_after_failure(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.session_id = "NS-NEW"
        snapshot = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "ipv4_forwarding": None,
            "ipv6_forwarding": None,
            "route_localnet": None,
            "iptables_rules": "",
            "ip6tables_rules": "",
            "tc_configuration": "",
        }
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            "targets": [],
            "global_rules_applied": False,
            "shaper_base_initialized": True,
            "snapshot": snapshot,
        }

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)

            with mock.patch("netshaper.core.orchestrator.config.STATE_DIR", tmp), \
                 mock.patch("netshaper.core.orchestrator.print_flush"), \
                 mock.patch("netshaper.core.orchestrator.shutil.which",
                            return_value=None), \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.restore",
                            return_value=True), \
                 mock.patch("netshaper.core.orchestrator.StateSnapshotManager.capture") as capture_mock, \
                 mock.patch("netshaper.core.orchestrator.log"):
                result = ns.load_state_and_cleanup()

        self.assertFalse(result)
        capture_mock.assert_not_called()

    def test_remove_global_rules_fails_when_recorded_binary_missing(self):
        ns = NetShaper.__new__(NetShaper)
        ns.interface = "eth0"
        ns.state_snapshot = mock.Mock(
            ipv4_forwarding=None,
            ipv6_forwarding=None,
            route_localnet=None,
        )
        ns._global_rules_applied = True
        ns._global_firewall_binaries_applied = ["iptables"]

        with mock.patch("netshaper.core.orchestrator.shutil.which",
                        return_value=None), \
             mock.patch("netshaper.core.orchestrator.log"):
            result = ns._remove_global_rules()

        self.assertFalse(result)
        self.assertTrue(ns._global_rules_applied)
        self.assertEqual(ns._global_firewall_binaries_applied, ["iptables"])

    def test_remove_state_file_removes_empty_session_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = os.path.join(tmp, "NS-TEST")
            os.makedirs(state_dir)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as fh:
                fh.write("{}")

            NetShaper._remove_state_file(state_path)

            self.assertFalse(os.path.exists(state_path))
            self.assertFalse(os.path.exists(state_dir))


if __name__ == "__main__":
    unittest.main(verbosity=2)
