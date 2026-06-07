"""The drift engine: observe, diff, and human-gated convergence (ADR-0007).

``diff`` (read-only) computes structured findings from observed facts versus a
desired-state baseline. ``sources`` wraps the desired-state authorities (a stored
known-good snapshot, ``tofu plan``, ``ansible --check``). ``converge`` frames a fix
as a request that must pass DRY_RUN -> approve -> execute through the executor; a
finding never auto-fixes (SEC-6).
"""

from __future__ import annotations

from praxis.drift.converge import ConvergencePlan, propose
from praxis.drift.engine import default_severity, diff
from praxis.drift.findings import DriftFinding, DriftKind, DriftSeverity
from praxis.drift.sources import known_good_from_store, parse_ansible_check, parse_tofu_plan

__all__ = [
    "ConvergencePlan",
    "DriftFinding",
    "DriftKind",
    "DriftSeverity",
    "default_severity",
    "diff",
    "known_good_from_store",
    "parse_ansible_check",
    "parse_tofu_plan",
    "propose",
]
