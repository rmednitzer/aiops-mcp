"""Dispatch evaluation: P@1 and MRR over a golden set (ADR-0010; the eval gate).

A routing regression fails the build. The gate is exercised both by ``make eval``
(scripts/eval.py) and by the test suite, so drift in skill descriptions or the
dispatcher is caught early.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from praxis.skills.dispatch import RoutingChainDispatcher
from praxis.skills.registry import SkillRegistry


@dataclass(frozen=True)
class EvalResult:
    p_at_1: float
    mrr: float
    n: int
    failures: list[tuple[str, str, str]]  # (query, expected, got)


def load_golden(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [{"query": str(row["query"]), "expected": str(row["expected"])} for row in data]


def evaluate(dispatcher: RoutingChainDispatcher, golden: list[dict[str, str]]) -> EvalResult:
    n = len(golden)
    if n == 0:
        return EvalResult(1.0, 1.0, 0, [])
    hits = 0
    reciprocal_rank = 0.0
    failures: list[tuple[str, str, str]] = []
    for item in golden:
        expected = item["expected"]
        names = [match.name for match in dispatcher.route(item["query"])]
        top = names[0] if names else ""
        if top == expected:
            hits += 1
        else:
            failures.append((item["query"], expected, top))
        if expected in names:
            reciprocal_rank += 1.0 / (names.index(expected) + 1)
    return EvalResult(hits / n, reciprocal_rank / n, n, failures)


def run_eval(skills_dir: Path, golden_path: Path) -> EvalResult:
    registry = SkillRegistry.discover(skills_dir)
    dispatcher = RoutingChainDispatcher(registry.all())
    return evaluate(dispatcher, load_golden(golden_path))
