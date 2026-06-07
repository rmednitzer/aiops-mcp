"""The drift diff: missing, changed, unexpected, and severity escalation."""

from __future__ import annotations

from praxis.drift import DriftKind, DriftSeverity, diff
from praxis.model.facts import DESIRED, OBSERVED, Fact


def _fact(predicate: str, value: dict[str, object], fact_type: str) -> Fact:
    return Fact(
        subject="host:axiom",
        predicate=predicate,
        fact_type=fact_type,
        value=value,
        t_valid="2026-06-07T00:00:00.000000Z",
        actor="test",
    )


def test_no_drift_when_identical() -> None:
    observed = [_fact("os", {"v": "24.04"}, OBSERVED)]
    desired = [_fact("os", {"v": "24.04"}, DESIRED)]
    assert diff(observed, desired) == []


def test_changed_value_is_a_finding() -> None:
    observed = [_fact("os", {"v": "22.04"}, OBSERVED)]
    desired = [_fact("os", {"v": "24.04"}, DESIRED)]
    findings = diff(observed, desired)
    assert len(findings) == 1
    assert findings[0].kind is DriftKind.CHANGED
    assert findings[0].observed == {"v": "22.04"}
    assert findings[0].desired == {"v": "24.04"}


def test_missing_desired_is_a_finding() -> None:
    findings = diff([], [_fact("service:ufw", {"state": "active"}, DESIRED)])
    assert len(findings) == 1
    assert findings[0].kind is DriftKind.MISSING


def test_unexpected_only_when_strict() -> None:
    observed = [_fact("package:nmap", {"installed": True}, OBSERVED)]
    assert diff(observed, []) == []  # lenient: observed-only is ignored
    strict = diff(observed, [], flag_unexpected=True)
    assert len(strict) == 1
    assert strict[0].kind is DriftKind.UNEXPECTED


def test_security_predicate_escalates_to_critical() -> None:
    observed = [_fact("file_integrity", {"clean": False}, OBSERVED)]
    desired = [_fact("file_integrity", {"clean": True}, DESIRED)]
    findings = diff(observed, desired)
    assert findings[0].severity is DriftSeverity.CRITICAL


def test_findings_record_as_drift_facts() -> None:
    observed = [_fact("os", {"v": "22.04"}, OBSERVED)]
    desired = [_fact("os", {"v": "24.04"}, DESIRED)]
    fact = diff(observed, desired)[0].to_fact()
    assert fact.fact_type == "drift"
    assert fact.predicate == "drift:os"
