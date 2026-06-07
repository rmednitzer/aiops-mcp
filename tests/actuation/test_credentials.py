"""Invariant 9: scoped, revocable credentials with a kill switch; no unscoped grants."""

from __future__ import annotations

import pytest

from praxis.actuation import CredentialBroker, CredentialError
from praxis.execution import KillSwitch, Tier


def test_grant_is_scoped_and_authorizes_within_scope() -> None:
    broker = CredentialBroker()
    handle = broker.grant("deployer", hosts=frozenset({"axiom"}), max_tier=Tier.T2)
    scope = broker.authorize(handle, host="axiom", tier=Tier.T2)
    assert scope.role == "deployer"


def test_unscoped_grant_is_refused() -> None:
    broker = CredentialBroker()
    with pytest.raises(CredentialError):
        broker.grant("deployer", hosts=frozenset(), max_tier=Tier.T1)


def test_t3_grant_must_be_single_host() -> None:
    broker = CredentialBroker()
    with pytest.raises(CredentialError):
        broker.grant("breakglass", hosts=frozenset({"a", "b"}), max_tier=Tier.T3)


def test_authorize_refuses_out_of_scope_host_and_tier() -> None:
    broker = CredentialBroker()
    handle = broker.grant("deployer", hosts=frozenset({"axiom"}), max_tier=Tier.T1)
    with pytest.raises(CredentialError):
        broker.authorize(handle, host="atlas", tier=Tier.T1)
    with pytest.raises(CredentialError):
        broker.authorize(handle, host="axiom", tier=Tier.T2)


def test_revoke_and_kill_switch() -> None:
    kill = KillSwitch()
    broker = CredentialBroker(kill_switch=kill)
    handle = broker.grant("deployer", hosts=frozenset({"axiom"}), max_tier=Tier.T2)
    broker.revoke(handle)
    with pytest.raises(CredentialError):
        broker.authorize(handle, host="axiom", tier=Tier.T1)

    handle2 = broker.grant("deployer", hosts=frozenset({"axiom"}), max_tier=Tier.T2)
    broker.kill_all()
    assert kill.is_tripped() is True
    with pytest.raises(CredentialError):
        broker.authorize(handle2, host="axiom", tier=Tier.T1)
