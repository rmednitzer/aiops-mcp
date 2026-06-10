"""Scoped, revocable credentials with a kill switch (invariant 9; SEC-8).

A credential grant is least-privilege by construction: it names the role, the exact
hosts it may touch, and the maximum tier it may reach. Grants are independently
revocable, and ``kill_all`` revokes everything at once (and trips a shared kill
switch if one is wired in). This is the authorization record; the actual secret
material (an SSH key, a Vault token) is injected into the adapter's environment out
of band and never stored here or logged.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from praxis.execution.patterns import Tier
from praxis.execution.runner import KillSwitch


class CredentialError(Exception):
    """Raised when a grant is missing, revoked, or exceeds its scope."""


@dataclass(frozen=True)
class Scope:
    role: str
    hosts: frozenset[str]
    max_tier: Tier


class CredentialBroker:
    """Tracks scoped grants. No NOPASSWD: ALL: every grant is bounded (invariant 9)."""

    def __init__(self, kill_switch: KillSwitch | None = None) -> None:
        self._grants: dict[str, Scope] = {}
        self._kill_switch = kill_switch

    def grant(self, role: str, *, hosts: frozenset[str], max_tier: Tier) -> str:
        if not hosts:
            raise CredentialError("a grant must name at least one host (no unscoped grants)")
        if max_tier >= Tier.T3 and len(hosts) != 1:
            raise CredentialError("a T3 grant must be scoped to exactly one host")
        handle = uuid.uuid4().hex
        self._grants[handle] = Scope(role=role, hosts=frozenset(hosts), max_tier=max_tier)
        return handle

    def revoke(self, handle: str) -> None:
        self._grants.pop(handle, None)

    def kill_all(self) -> None:
        self._grants.clear()
        if self._kill_switch is not None:
            self._kill_switch.trip()

    def authorize(self, handle: str, *, host: str, tier: Tier) -> Scope:
        scope = self._grants.get(handle)
        if scope is None:
            raise CredentialError("credential revoked or unknown")
        if host not in scope.hosts:
            raise CredentialError(f"credential not scoped for host {host!r}")
        if tier > scope.max_tier:
            raise CredentialError(f"credential capped at {scope.max_tier.label}, need {tier.label}")
        return scope

    def has_grants(self) -> bool:
        """True once the operator has issued at least one grant.

        Zero grants is the single-operator default posture: scoped-credential
        enforcement is off. Issuing the first grant flips the actuation path to
        deny-unless-authorized (BL-049, ADR-0016).
        """
        return bool(self._grants)

    def authorized(self, *, host: str, tier: Tier) -> bool:
        """True if ANY current grant covers this host at this tier (BL-049).

        This is the broker-level scan the actuation path uses as a HARD audited
        precondition: it asks whether the operator has scoped authority for the
        action at all, without naming a specific handle.
        """
        return any(
            host in scope.hosts and tier <= scope.max_tier for scope in self._grants.values()
        )
