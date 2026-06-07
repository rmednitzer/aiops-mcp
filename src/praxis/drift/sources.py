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
# A check run also reports task failures and unreachable hosts. These are stronger
# signals than a would-change and must not be dropped (BL-034). Ansible renders both
# as a `fatal:` line tagged FAILED! or UNREACHABLE!; a bare `failed:` is the summary.
_FATAL = re.compile(r"^fatal: \[(?P<host>[^\]]+)\][^:]*: (?P<why>UNREACHABLE|FAILED)")
_FAILED = re.compile(r"^failed: \[(?P<host>[^\]]+)\]")


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
    for raw_line in output.splitlines():
        line = raw_line.strip()
        task = _TASK.match(line)
        if task is not None:
            current_task = task.group("task")
            continue
        changed = _CHANGED.match(line)
        if changed is not None:
            findings.append(
                _ansible_finding(
                    changed.group("host"),
                    current_task,
                    DriftSeverity.WARNING,
                    {"would_change": True},
                )
            )
            continue
        fatal = _FATAL.match(line)
        if fatal is not None:
            why = fatal.group("why").upper()
            # A failed or unreachable host during a check is critical: the desired
            # state could not even be evaluated, which is worse than a known change.
            findings.append(
                _ansible_finding(
                    fatal.group("host"),
                    current_task,
                    DriftSeverity.CRITICAL,
                    {"failed": why == "FAILED", "unreachable": why == "UNREACHABLE"},
                )
            )
            continue
        failed = _FAILED.match(line)
        if failed is not None:
            findings.append(
                _ansible_finding(
                    failed.group("host"),
                    current_task,
                    DriftSeverity.CRITICAL,
                    {"failed": True},
                )
            )
    return findings


def _ansible_finding(
    host: str, task: str, severity: DriftSeverity, observed: dict[str, object]
) -> DriftFinding:
    return DriftFinding(
        subject=f"host:{host}",
        predicate=task,
        kind=DriftKind.CHANGED,
        severity=severity,
        observed=observed,
        desired={"task": task, "compliant": True},
    )
