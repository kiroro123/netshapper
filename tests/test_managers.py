import os
import tempfile

import pytest

from netshaper.core.authorization import AuthorizationPolicy, AuthorizationError
from netshaper.core.firewall_manager import FirewallManager
from netshaper.core.mitm_manager import MitmProxyManager
from netshaper.core.recovery_manager import RecoveryManager
from netshaper import config


def test_authorization_policy_ok():
    policy = AuthorizationPolicy(["10.0.0.0/8"])
    # should not raise
    policy.assert_target_authorized("10.1.2.3")


def test_authorization_policy_outside():
    policy = AuthorizationPolicy(["10.0.0.0/8"])
    with pytest.raises(AuthorizationError):
        policy.assert_target_authorized("192.0.2.1")


def test_firewall_manager_state_and_remove():
    fm = FirewallManager("lo", "TEST")
    st = fm.get_state_for_persistence()
    assert isinstance(st, dict)
    # Removing when nothing applied should be ok
    assert fm.remove_global_rules() is True


def test_mitm_manager_dry_run(monkeypatch):
    monkeypatch.setattr(config, "DRY_RUN", True)
    mm = MitmProxyManager("127.0.0.1")
    assert mm.launch(port=8088, web_port=8083) is True


def test_recovery_manager_no_state_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "STATE_DIR", str(tmp_path / "nosuch"))
    rm = RecoveryManager("lo")
    assert rm.recover_stale_state() is True
