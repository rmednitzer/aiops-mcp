"""DoD regression: a fixture host snapshot diffed against a known-good baseline.

A frozen observed snapshot and a known-good baseline (under ``evaluation/drift/``)
must yield exactly the expected drift findings. This guards the drift engine
against regression (build-sequence step 5; DoD).
"""

from __future__ import annotations

import json
from pathlib import Path

from praxis.drift import DriftKind, DriftSeverity, diff
from praxis.model.facts import KNOWN_GOOD, OBSERVED, Fact

_FIXTURES = Path(__file__).resolve().parents[2] / "evaluation" / "drift"


def _load(name: str, fact_type: str) -> list[Fact]:
    data = json.loads((_FIXTURES / name).read_text(encoding="utf-8"))
    return [
        Fact(
            subject=str(row["subject"]),
            predicate=str(row["predicate"]),
            fact_type=fact_type,
            value=row["value"],
            t_valid="2026-06-07T00:00:00.000000Z",
            actor="fixture",
        )
        for row in data
    ]


def test_snapshot_vs_known_good_yields_expected_findings() -> None:
    observed = _load("observed.json", OBSERVED)
    desired = _load("known_good.json", KNOWN_GOOD)
    findings = diff(observed, desired, flag_unexpected=True)

    # Exactly four deltas; os_version matches and produces no finding.
    assert len(findings) == 4
    assert all(f.predicate != "os_version" for f in findings)

    kinds = {(f.predicate, f.kind) for f in findings}
    assert ("ssh_config", DriftKind.CHANGED) in kinds
    assert ("file_integrity", DriftKind.CHANGED) in kinds
    assert ("service:ufw", DriftKind.MISSING) in kinds
    assert ("package:nmap", DriftKind.UNEXPECTED) in kinds

    # The two security-relevant changes escalate to critical.
    critical = {f.predicate for f in findings if f.severity is DriftSeverity.CRITICAL}
    assert critical == {"ssh_config", "file_integrity"}
