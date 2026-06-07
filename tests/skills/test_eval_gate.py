"""The dispatch eval gate, run as part of the suite (ADR-0010)."""

from __future__ import annotations

from pathlib import Path

from praxis.skills.eval import run_eval

_ROOT = Path(__file__).resolve().parents[2]


def test_dispatch_eval_meets_thresholds() -> None:
    result = run_eval(_ROOT / "skills", _ROOT / "evaluation" / "skills_golden.json")
    assert result.n >= 8
    assert result.p_at_1 >= 0.80, result.failures
    assert result.mrr >= 0.85, result.failures
