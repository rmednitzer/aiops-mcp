"""Desired-state sources for the drift engine (ADR-0007).

Three authorities, each wrapped not reinvented:

- ``known_good_from_store``: the operator-blessed snapshot, stored as facts.
- ``parse_tofu_plan``: ``tofu plan -refresh-only -json`` (infrastructure drift).
- ``parse_ansible_check``: ``ansible-playbook --check --diff`` (config drift).

The known-good route returns desired facts to feed ``engine.diff``; the tofu and
ansible routes already express drift, so they return findings directly. All inputs
are untrusted and parsed defensively.
"""

from __future__ import annotations

import json
import re

from praxis.drift.findings import DriftFinding, DriftKind, DriftSeverity
from praxis.model.facts import KNOWN_GOOD, Fact
from praxis.store.base import StoreProtocol

_TASK = re.compile(r"^TASK \[(?P<task>.+?)\]")
_CHANGED = re.compile(r"^changed: \[(?P<host>[^\]]+)\]")


def known_good_from_store(store: StoreProtocol, *, subject: str | None = None) -> list[Fact]:
    """Return the known-good baseline facts (the operator-blessed snapshot)."""
    return store.list_active(subject=subject, fact_type=KNOWN_GOOD)


def _as_obj(value: object) -> dict[str, object] | None:
    return value if isinstance(value, dict) else None


def parse_tofu_plan(plan_json: str) -> list[DriftFinding]:
    """Parse ``tofu plan -refresh-only -json`` output into drift findings."""
    try:
        data = json.loads(plan_json)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    findings: list[DriftFinding] = []
    drifts = data.get("resource_drift")
    entries = drifts if isinstance(drifts, list) else []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        address = str(entry.get("address", "unknown"))
        change = entry.get("change")
        change_obj = change if isinstance(change, dict) else {}
        findings.append(
            DriftFinding(
                subject=f"tofu:{address}",
                predicate="resource",
                kind=DriftKind.CHANGED,
                severity=DriftSeverity.WARNING,
                observed=_as_obj(change_obj.get("before")),
                desired=_as_obj(change_obj.get("after")),
            )
        )
    return findings


def parse_ansible_check(output: str) -> list[DriftFinding]:
    """Parse ``ansible-playbook --check --diff`` output into drift findings.

    A task reported ``changed`` under ``--check`` is config that would change, that
    is, observed config drifting from the playbook's desired state.
    """
    findings: list[DriftFinding] = []
    current_task = "unknown"
    for line in output.splitlines():
        task = _TASK.match(line.strip())
        if task is not None:
            current_task = task.group("task")
            continue
        changed = _CHANGED.match(line.strip())
        if changed is not None:
            host = changed.group("host")
            findings.append(
                DriftFinding(
                    subject=f"host:{host}",
                    predicate=current_task,
                    kind=DriftKind.CHANGED,
                    severity=DriftSeverity.WARNING,
                    observed={"would_change": True},
                    desired={"task": current_task, "compliant": True},
                )
            )
    return findings
