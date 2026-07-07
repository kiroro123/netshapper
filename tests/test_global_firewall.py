import copy
import json
import os
import tempfile
import unittest
from unittest import mock

from netshaper.core.firewall_manager import FirewallError, FirewallManager
from netshaper.core.recovery_manager import RecoveryManager
from netshaper.system import InspectionStatus


class _FirewallKernel:
    def __init__(self):
        self.present = set()
        self.apply_to_check = {}
        self.delete_to_check = {}
        self.commands = []
        self.events = []
        self.apply_count = 0
        self.fail_apply_at = None
        self.error_checks = set()

    def register(self, records):
        for record in records:
            check = tuple(record["check"])
            self.apply_to_check[tuple(record["apply"])] = check
            self.delete_to_check[tuple(record["delete"])] = check

    def inspect(self, command):
        key = tuple(command)
        if key in self.error_checks:
            return InspectionStatus.ERROR
        if key in self.present:
            return InspectionStatus.PRESENT
        return InspectionStatus.ABSENT

    def run(self, command, **_kwargs):
        key = tuple(command)
        self.commands.append(list(command))
        if key in self.apply_to_check:
            self.apply_count += 1
            self.events.append("apply")
            if self.apply_count == self.fail_apply_at:
                return False
            self.present.add(self.apply_to_check[key])
            return True
        if key in self.delete_to_check:
            self.events.append("delete")
            self.present.discard(self.delete_to_check[key])
            return True
        raise AssertionError(f"unexpected firewall command: {command!r}")


class TargetScopedFirewallTests(unittest.TestCase):
    def _manager(self, authorized=None, journal=None):
        authorized = authorized or {
            "192.0.2.10",
            "192.0.2.20",
            "2001:db8::10",
        }

        def authorize(target):
            if target not in authorized:
                raise ValueError(f"unauthorized target {target}")

        return FirewallManager(
            "eth0",
            "NS-TEST",
            journal=journal or (lambda: True),
            target_authorizer=authorize,
        )

    @staticmethod
    def _register(kernel, manager, *targets):
        for binary in {"iptables", "ip6tables"}:
            kernel.register(manager._shared_resource_specs(binary))
        for target in targets:
            binary = "ip6tables" if ":" in target else "iptables"
            kernel.register(manager._target_resource_specs(binary, target))

    def test_ipv4_rules_are_target_scoped_and_ipv6_does_not_add_nat(self):
        manager = self._manager()
        ipv4 = manager._target_resource_specs("iptables", "192.0.2.10")
        ipv6 = manager._target_resource_specs("ip6tables", "2001:db8::10")

        self.assertEqual(len(ipv4), 3)
        self.assertEqual(len(ipv6), 2)
        outbound, returned, nat = ipv4
        self.assertIn("192.0.2.10", outbound["apply"])
        self.assertIn("-s", outbound["apply"])
        self.assertIn("-i", outbound["apply"])
        self.assertIn("192.0.2.10", returned["apply"])
        self.assertIn("-d", returned["apply"])
        self.assertIn("ESTABLISHED,RELATED", returned["apply"])
        self.assertIn("192.0.2.10", nat["apply"])
        self.assertIn("-s", nat["apply"])
        self.assertIn("MASQUERADE", nat["apply"])
        self.assertFalse(
            any("MASQUERADE" in record["apply"] for record in ipv6)
        )
        self.assertFalse(
            any(
                command[:3] == ["iptables", "-I", "FORWARD"]
                and "-s" not in command
                for command in [record["apply"] for record in ipv4]
            )
        )

    def test_journals_pending_intent_before_each_mutation(self):
        kernel = _FirewallKernel()
        snapshots = []
        holder = {}

        def journal():
            kernel.events.append("journal")
            snapshots.append(
                copy.deepcopy(
                    holder["manager"].get_state_for_persistence()[
                        "global_rules_created"
                    ]
                )
            )
            return True

        manager = self._manager(journal=journal)
        holder["manager"] = manager
        self._register(kernel, manager, "192.0.2.10")

        with mock.patch.object(
            manager,
            "_inspect_rule",
            side_effect=kernel.inspect,
        ), mock.patch(
            "netshaper.core.firewall_manager.shutil.which",
            return_value="/sbin/iptables",
        ), mock.patch(
            "netshaper.core.firewall_manager.SubprocessRunner.run",
            side_effect=kernel.run,
        ):
            manager.add_target_rules("192.0.2.10")

        self.assertEqual(
            kernel.events,
            ["journal", "apply", "journal"] * 6,
        )
        pre_mutation_snapshots = snapshots[::2]
        self.assertEqual(len(pre_mutation_snapshots), 6)
        for index, snapshot in enumerate(pre_mutation_snapshots, start=1):
            self.assertEqual(len(snapshot), index)
            self.assertEqual(snapshot[-1]["state"], "pending")

    def test_adding_and_removing_targets_is_independent(self):
        kernel = _FirewallKernel()
        manager = self._manager()
        self._register(
            kernel,
            manager,
            "192.0.2.10",
            "192.0.2.20",
        )

        with mock.patch.object(
            manager,
            "_inspect_rule",
            side_effect=kernel.inspect,
        ), mock.patch(
            "netshaper.core.firewall_manager.shutil.which",
            return_value="/sbin/iptables",
        ), mock.patch(
            "netshaper.core.firewall_manager.SubprocessRunner.run",
            side_effect=kernel.run,
        ):
            manager.add_target_rules("192.0.2.10")
            first_target_records = copy.deepcopy(
                [
                    record
                    for record in manager._global_rules_created
                    if record["target_ip"] == "192.0.2.10"
                ]
            )
            command_count = len(kernel.commands)
            manager.add_target_rules("192.0.2.20")
            second_add_commands = kernel.commands[command_count:]

            self.assertEqual(
                first_target_records,
                [
                    record
                    for record in manager._global_rules_created
                    if record["target_ip"] == "192.0.2.10"
                ],
            )
            self.assertTrue(
                all("192.0.2.10" not in command for command in second_add_commands)
            )
            self.assertTrue(manager.remove_target_rules("192.0.2.10"))
            self.assertFalse(
                any(
                    record["target_ip"] == "192.0.2.10"
                    for record in manager._global_rules_created
                )
            )
            self.assertTrue(
                any(
                    record["target_ip"] == "192.0.2.20"
                    for record in manager._global_rules_created
                )
            )
            self.assertTrue(
                any(
                    record["target_ip"] is None
                    for record in manager._global_rules_created
                )
            )
            self.assertTrue(manager.remove_target_rules("192.0.2.20"))

        self.assertEqual(manager._global_rules_created, [])
        self.assertEqual(kernel.present, set())

    def test_middle_setup_failure_rolls_back_only_partial_target_resources(self):
        kernel = _FirewallKernel()
        manager = self._manager()
        self._register(kernel, manager, "192.0.2.10")
        kernel.fail_apply_at = 5

        with mock.patch.object(
            manager,
            "_inspect_rule",
            side_effect=kernel.inspect,
        ), mock.patch(
            "netshaper.core.firewall_manager.shutil.which",
            return_value="/sbin/iptables",
        ), mock.patch(
            "netshaper.core.firewall_manager.SubprocessRunner.run",
            side_effect=kernel.run,
        ), self.assertRaisesRegex(
            FirewallError,
            "Failed to add forwarding resources",
        ):
            manager.add_target_rules("192.0.2.10")

        self.assertEqual(manager._global_rules_created, [])
        self.assertEqual(kernel.present, set())

    def test_post_mutation_journal_failure_keeps_retry_evidence(self):
        kernel = _FirewallKernel()
        journal_results = iter([True, False])

        def journal():
            return next(journal_results, False)

        manager = self._manager(journal=journal)
        self._register(kernel, manager, "192.0.2.10")

        with mock.patch.object(
            manager,
            "_inspect_rule",
            side_effect=kernel.inspect,
        ), mock.patch(
            "netshaper.core.firewall_manager.shutil.which",
            return_value="/sbin/iptables",
        ), mock.patch(
            "netshaper.core.firewall_manager.SubprocessRunner.run",
            side_effect=kernel.run,
        ), self.assertRaisesRegex(FirewallError, "rollback incomplete"):
            manager.add_target_rules("192.0.2.10")

        self.assertEqual(len(manager._global_rules_created), 1)
        self.assertEqual(len(kernel.present), 1)
        self.assertEqual(
            manager._global_rules_created[0]["state"],
            "active",
        )
        self.assertFalse(any(command[3] == "-X" for command in kernel.commands))

    def test_inspection_error_preserves_records_for_cleanup_retry(self):
        kernel = _FirewallKernel()
        manager = self._manager()
        self._register(kernel, manager, "192.0.2.10")

        with mock.patch.object(
            manager,
            "_inspect_rule",
            side_effect=kernel.inspect,
        ), mock.patch(
            "netshaper.core.firewall_manager.shutil.which",
            return_value="/sbin/iptables",
        ), mock.patch(
            "netshaper.core.firewall_manager.SubprocessRunner.run",
            side_effect=kernel.run,
        ):
            manager.add_target_rules("192.0.2.10")
            nat_record = next(
                record
                for record in manager._global_rules_created
                if record["target_ip"] == "192.0.2.10"
                and "source NAT" in record["description"]
            )
            kernel.error_checks.add(tuple(nat_record["check"]))
            before = copy.deepcopy(manager._global_rules_created)
            self.assertFalse(manager.remove_target_rules("192.0.2.10"))
            self.assertEqual(manager._global_rules_created, before)

            kernel.error_checks.clear()
            self.assertTrue(manager.remove_target_rules("192.0.2.10"))

        self.assertEqual(manager._global_rules_created, [])

    def test_mutation_primitive_requires_authorization_policy(self):
        manager = FirewallManager(
            "eth0",
            "NS-TEST",
            journal=lambda: True,
        )
        with mock.patch(
            "netshaper.core.firewall_manager.SubprocessRunner.run"
        ) as runner:
            with self.assertRaisesRegex(FirewallError, "authorization policy"):
                manager.add_target_rules("192.0.2.10")
        runner.assert_not_called()

    def test_rejects_invalid_interface_session_and_target_values(self):
        with self.assertRaisesRegex(ValueError, "interface"):
            FirewallManager("bad interface", "NS-TEST")
        with self.assertRaisesRegex(ValueError, "session"):
            FirewallManager("eth0", "bad session")

        manager = self._manager()
        with self.assertRaisesRegex(FirewallError, "Invalid forwarding target"):
            manager.add_target_rules("not-an-ip")
        self.assertFalse(manager.remove_target_rules("not-an-ip"))

    def test_creation_refuses_inspection_error_and_existing_resource(self):
        manager = self._manager()
        record = manager._shared_resource_specs("iptables")[0]

        for status, message in [
            (InspectionStatus.ERROR, "Could not inspect"),
            (InspectionStatus.PRESENT, "pre-existing"),
        ]:
            with self.subTest(status=status), mock.patch.object(
                manager,
                "_inspect_rule",
                return_value=status,
            ), mock.patch(
                "netshaper.core.firewall_manager.SubprocessRunner.run"
            ) as runner, self.assertRaisesRegex(FirewallError, message):
                manager._create_resource(copy.deepcopy(record))
            runner.assert_not_called()

    def test_pre_mutation_journal_failure_creates_nothing(self):
        def raise_journal_error():
            raise OSError("disk failed")

        for journal in [lambda: False, raise_journal_error]:
            manager = self._manager(journal=journal)
            record = manager._shared_resource_specs("iptables")[0]

            with mock.patch.object(
                manager,
                "_inspect_rule",
                return_value=InspectionStatus.ABSENT,
            ), mock.patch(
                "netshaper.core.firewall_manager.SubprocessRunner.run"
            ) as runner, self.assertRaisesRegex(
                FirewallError,
                "recovery intent",
            ):
                manager._create_resource(record)

            self.assertEqual(manager._global_rules_created, [])
            runner.assert_not_called()

    def test_delete_intent_and_confirmation_failures_remain_retryable(self):
        template = self._manager()._shared_resource_specs("iptables")[0]
        template["state"] = "active"

        manager = self._manager(journal=lambda: False)
        manager._global_rules_created = [copy.deepcopy(template)]
        with mock.patch.object(
            manager,
            "_inspect_rule",
            return_value=InspectionStatus.PRESENT,
        ), mock.patch(
            "netshaper.core.firewall_manager.SubprocessRunner.run"
        ) as runner:
            self.assertFalse(
                manager._remove_record(manager._global_rules_created[0])
            )
        runner.assert_not_called()
        self.assertEqual(manager._global_rules_created[0]["state"], "active")

        manager = self._manager(journal=lambda: False)
        manager._global_rules_created = [copy.deepcopy(template)]
        with mock.patch.object(
            manager,
            "_inspect_rule",
            return_value=InspectionStatus.ABSENT,
        ):
            self.assertFalse(
                manager._remove_record(manager._global_rules_created[0])
            )
        self.assertEqual(
            manager._global_rules_created[0]["state"],
            "delete_pending",
        )

    def test_delete_verification_failure_keeps_delete_pending_record(self):
        for verification in [
            InspectionStatus.ERROR,
            InspectionStatus.PRESENT,
        ]:
            with self.subTest(verification=verification):
                manager = self._manager()
                record = manager._shared_resource_specs("iptables")[0]
                record["state"] = "active"
                manager._global_rules_created = [record]

                with mock.patch.object(
                    manager,
                    "_inspect_rule",
                    side_effect=[
                        InspectionStatus.PRESENT,
                        verification,
                    ],
                ), mock.patch(
                    "netshaper.core.firewall_manager.SubprocessRunner.run",
                    return_value=True,
                ):
                    self.assertFalse(manager._remove_record(record))

                self.assertEqual(record["state"], "delete_pending")
                self.assertEqual(manager._global_rules_created, [record])

    def test_global_sysctls_require_journal_and_report_command_failure(self):
        manager = self._manager(journal=lambda: False)
        with mock.patch(
            "netshaper.core.firewall_manager.SubprocessRunner.run"
        ) as runner, self.assertRaisesRegex(FirewallError, "recovery state"):
            manager.apply_global_rules()
        runner.assert_not_called()

        manager = self._manager()
        with mock.patch(
            "netshaper.core.firewall_manager.SubprocessRunner.run",
            return_value=False,
        ), self.assertRaisesRegex(FirewallError, "forwarding sysctls"):
            manager.apply_global_rules()

    def test_duplicate_target_and_missing_binary_fail_closed(self):
        manager = self._manager()
        record = manager._target_resource_specs(
            "iptables",
            "192.0.2.10",
        )[0]
        record["state"] = "active"
        manager._global_rules_created = [record]

        with mock.patch(
            "netshaper.core.firewall_manager.shutil.which",
            return_value="/sbin/iptables",
        ), self.assertRaisesRegex(FirewallError, "already tracked"):
            manager.add_target_rules("192.0.2.10")

        with mock.patch(
            "netshaper.core.firewall_manager.shutil.which",
            return_value=None,
        ):
            self.assertFalse(manager.remove_target_rules("192.0.2.10"))
            self.assertFalse(manager.remove_global_rules())

        empty_manager = self._manager()
        self.assertTrue(empty_manager._remove_record(record))
        with mock.patch(
            "netshaper.core.firewall_manager.shutil.which",
            return_value=None,
        ):
            self.assertTrue(
                empty_manager.remove_target_rules("192.0.2.20")
            )


class TargetScopedFirewallRecoveryTests(unittest.TestCase):
    def _owned_state(self):
        kernel = _FirewallKernel()
        manager = FirewallManager(
            "eth0",
            "NS-OLD",
            journal=lambda: True,
            target_authorizer=lambda _target: None,
        )
        kernel.register(manager._shared_resource_specs("iptables"))
        kernel.register(
            manager._target_resource_specs("iptables", "192.0.2.10")
        )
        with mock.patch.object(
            manager,
            "_inspect_rule",
            side_effect=kernel.inspect,
        ), mock.patch(
            "netshaper.core.firewall_manager.shutil.which",
            return_value="/sbin/iptables",
        ), mock.patch(
            "netshaper.core.firewall_manager.SubprocessRunner.run",
            side_effect=kernel.run,
        ):
            manager.add_target_rules("192.0.2.10")
        state = {
            "session_id": "NS-OLD",
            "interface": "eth0",
            **manager.get_state_for_persistence(),
        }
        return manager, kernel, json.loads(json.dumps(state))

    def test_stale_recovery_removes_exact_persisted_resources(self):
        _manager, kernel, state = self._owned_state()
        unrelated = (
            "iptables",
            "-t",
            "filter",
            "-C",
            "FORWARD",
            "-m",
            "comment",
            "--comment",
            "unrelated",
            "-j",
            "ACCEPT",
        )
        kernel.present.add(unrelated)

        with mock.patch(
            "netshaper.core.recovery_manager.shutil.which",
            return_value="/sbin/iptables",
        ), mock.patch.object(
            RecoveryManager,
            "_inspect_stale_resource",
            side_effect=lambda command, **_kwargs: kernel.inspect(command),
        ), mock.patch(
            "netshaper.core.recovery_manager.SubprocessRunner.run",
            side_effect=kernel.run,
        ):
            result = RecoveryManager("eth0")._cleanup_global_rules(
                state,
                "eth0",
                journal=lambda: True,
            )

        self.assertTrue(result)
        self.assertEqual(kernel.present, {unrelated})

    def test_malformed_persisted_command_fails_closed(self):
        _manager, _kernel, state = self._owned_state()
        state["global_rules_created"][0]["delete"] = [
            "iptables",
            "-F",
        ]

        with mock.patch(
            "netshaper.core.recovery_manager.SubprocessRunner.run"
        ) as runner:
            result = RecoveryManager("eth0")._cleanup_global_rules(
                state,
                "eth0",
            )

        self.assertFalse(result)
        runner.assert_not_called()

    def test_unknown_format_and_ownership_mismatch_fail_closed(self):
        _manager, _kernel, state = self._owned_state()
        state["global_firewall_format"] = 999
        self.assertFalse(
            RecoveryManager("eth0")._cleanup_global_rules(state, "eth0")
        )

    def test_legacy_record_ownership_and_shape_are_validated(self):
        comment = "netshaper:NS-OLD:global"
        spec = RecoveryManager._global_firewall_rule_specs(
            "iptables",
            "eth0",
            comment,
        )[0]
        record = {
            "binary": "iptables",
            "description": spec["description"],
            "delete": spec["delete"],
            "check": spec["check"],
        }
        state = {
            "session_id": "NS-OLD",
            "global_rules_applied": True,
            "global_rule_comment": "netshaper:OTHER:global",
            "global_firewall_binaries": ["iptables"],
            "global_rules_created": [record],
        }
        self.assertFalse(
            RecoveryManager("eth0")._cleanup_global_rules(state, "eth0")
        )

        state["global_rule_comment"] = comment
        record["delete"] = ["iptables", "-F"]
        self.assertFalse(
            RecoveryManager("eth0")._cleanup_global_rules(state, "eth0")
        )

        _manager, _kernel, state = self._owned_state()
        state["global_forward_chain"] = "NS-FWD-NOT-OURS"
        self.assertFalse(
            RecoveryManager("eth0")._cleanup_global_rules(state, "eth0")
        )

    def test_duplicate_and_family_mismatched_records_fail_closed(self):
        _manager, _kernel, state = self._owned_state()
        state["global_rules_created"].append(
            copy.deepcopy(state["global_rules_created"][0])
        )
        self.assertFalse(
            RecoveryManager("eth0")._cleanup_global_rules(state, "eth0")
        )

        _manager, _kernel, state = self._owned_state()
        target_record = next(
            record
            for record in state["global_rules_created"]
            if record["target_ip"] is not None
        )
        target_record["binary"] = "ip6tables"
        self.assertFalse(
            RecoveryManager("eth0")._cleanup_global_rules(state, "eth0")
        )

    def test_recovery_journal_failure_prevents_deletion(self):
        _manager, kernel, state = self._owned_state()
        before = set(kernel.present)

        with mock.patch(
            "netshaper.core.recovery_manager.shutil.which",
            return_value="/sbin/iptables",
        ), mock.patch.object(
            RecoveryManager,
            "_inspect_stale_resource",
            side_effect=lambda command, **_kwargs: kernel.inspect(command),
        ), mock.patch(
            "netshaper.core.recovery_manager.SubprocessRunner.run",
            side_effect=kernel.run,
        ) as runner:
            result = RecoveryManager("eth0")._cleanup_global_rules(
                state,
                "eth0",
                journal=lambda: False,
            )

        self.assertFalse(result)
        self.assertEqual(kernel.present, before)
        runner.assert_not_called()

    def test_recovery_requires_a_journal_before_scoped_deletion(self):
        _manager, kernel, state = self._owned_state()

        with mock.patch(
            "netshaper.core.recovery_manager.shutil.which",
            return_value="/sbin/iptables",
        ), mock.patch.object(
            RecoveryManager,
            "_inspect_stale_resource",
            side_effect=lambda command, **_kwargs: kernel.inspect(command),
        ), mock.patch(
            "netshaper.core.recovery_manager.SubprocessRunner.run"
        ) as runner:
            result = RecoveryManager("eth0")._cleanup_global_rules(
                state,
                "eth0",
            )

        self.assertFalse(result)
        runner.assert_not_called()

    def test_recovery_keeps_deleted_record_when_final_journal_fails(self):
        _manager, kernel, state = self._owned_state()
        journal_results = iter([True, False])

        with mock.patch(
            "netshaper.core.recovery_manager.shutil.which",
            return_value="/sbin/iptables",
        ), mock.patch.object(
            RecoveryManager,
            "_inspect_stale_resource",
            side_effect=lambda command, **_kwargs: kernel.inspect(command),
        ), mock.patch(
            "netshaper.core.recovery_manager.SubprocessRunner.run",
            side_effect=kernel.run,
        ):
            result = RecoveryManager("eth0")._cleanup_global_rules(
                state,
                "eth0",
                journal=lambda: next(journal_results, False),
            )

        self.assertFalse(result)
        self.assertEqual(
            state["global_rules_created"][-1]["state"],
            "delete_pending",
        )

    def test_stale_inspection_error_leaves_manifest_retryable(self):
        _manager, kernel, state = self._owned_state()
        state.update({
            "targets": [],
            "shaper_base_initialized": False,
            "owner": {"pid": 999999, "process_start_time": "0"},
            "snapshot": {
                "session_id": "NS-OLD",
                "interface": "eth0",
                "ipv4_forwarding": None,
                "ipv6_forwarding": None,
                "route_localnet": None,
                "iptables_rules": "",
                "ip6tables_rules": "",
                "tc_configuration": "",
            },
        })
        error_record = state["global_rules_created"][-1]
        kernel.error_checks.add(tuple(error_record["check"]))

        with tempfile.TemporaryDirectory() as tmp:
            session_dir = os.path.join(tmp, "NS-OLD")
            os.makedirs(session_dir)
            state_path = os.path.join(session_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as handle:
                json.dump(state, handle)

            with mock.patch(
                "netshaper.core.recovery_manager.shutil.which",
                return_value="/sbin/iptables",
            ), mock.patch.object(
                RecoveryManager,
                "_inspect_stale_resource",
                side_effect=lambda command, **_kwargs: kernel.inspect(command),
            ), mock.patch(
                "netshaper.core.recovery_manager.SubprocessRunner.run",
                side_effect=kernel.run,
            ), mock.patch(
                "netshaper.core.recovery_manager.StateSnapshotManager.restore",
                return_value=True,
            ):
                result = RecoveryManager("eth0")._cleanup_stale_session(
                    state_path
                )

            self.assertFalse(result)
            self.assertTrue(os.path.exists(state_path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
