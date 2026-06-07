"""The drift diff: observed facts vs a desired-state baseline (ADR-0007).

``diff`` is pure and T0 (read-only). It never actuates and never auto-fixes; it
only computes findings. Convergence is a separate, human-gated step
(`drift.converge`; SEC-6). Collected/observed values are untrusted data and are
only compared, never interpreted as instructions (SEC-4).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from praxis.drift.findings import DriftFinding, DriftKind, DriftSeverity
from praxis.model.facts import Fact

SeverityFn = Callable[[str, DriftKind], DriftSeverity]


def default_severity(predicate: str, kind: DriftKind) -> DriftSeverity:
    """A conservative default: missing/changed are warnings, unexpected is info.

    Security-relevant predicates escalate to critical so they cannot be lost in
    the noise (these names match the seed osquery/AIDE collectors).
    """
    security_predicates = {"file_integrity", "listening_ports", "ssh_config", "users"}
    if predicate in security_predicates and kind is not DriftKind.UNEXPECTED:
        return DriftSeverity.CRITICAL
    if kind is DriftKind.UNEXPECTED:
        return DriftSeverity.INFO
    return DriftSeverity.WARNING


def _index(facts: Iterable[Fact]) -> dict[tuple[str, str], Fact]:
    return {(f.subject, f.predicate): f for f in facts}


def diff(
    observed: Iterable[Fact],
    desired: Iterable[Fact],
    *,
    flag_unexpected: bool = False,
    severity_for: SeverityFn = default_severity,
) -> list[DriftFinding]:
    """Compute drift findings between observed and desired facts.

    For every desired key: a MISSING finding if absent from observed, a CHANGED
    finding if the value differs. With ``flag_unexpected`` (a strict known-good
    baseline), observed keys absent from desired produce UNEXPECTED findings.
    """
    obs = _index(observed)
    des = _index(desired)
    findings: list[DriftFinding] = []

    for key, want in des.items():
        subject, predicate = key
        have = obs.get(key)
        if have is None:
            findings.append(
                DriftFinding(
                    subject=subject,
                    predicate=predicate,
                    kind=DriftKind.MISSING,
                    severity=severity_for(predicate, DriftKind.MISSING),
                    observed=None,
                    desired=want.value,
                )
            )
        elif have.value != want.value:
            findings.append(
                DriftFinding(
                    subject=subject,
                    predicate=predicate,
                    kind=DriftKind.CHANGED,
                    severity=severity_for(predicate, DriftKind.CHANGED),
                    observed=have.value,
                    desired=want.value,
                )
            )

    if flag_unexpected:
        for key, have in obs.items():
            if key not in des:
                subject, predicate = key
                findings.append(
                    DriftFinding(
                        subject=subject,
                        predicate=predicate,
                        kind=DriftKind.UNEXPECTED,
                        severity=severity_for(predicate, DriftKind.UNEXPECTED),
                        observed=have.value,
                        desired=None,
                    )
                )

    findings.sort(key=lambda f: (f.subject, f.predicate, f.kind.value))
    return findings
