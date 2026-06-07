"""Desired-state source parsers: tofu plan and ansible check."""

from __future__ import annotations

from praxis.drift import DriftKind, DriftSeverity, parse_ansible_check, parse_tofu_plan


def test_parse_tofu_plan_drift() -> None:
    plan = (
        '{"resource_drift": [{"address": "libvirt_domain.vm", '
        '"change": {"before": {"memory": 2048}, "after": {"memory": 4096}}}]}'
    )
    findings = parse_tofu_plan(plan)
    assert len(findings) == 1
    assert findings[0].subject == "tofu:libvirt_domain.vm"
    assert findings[0].kind is DriftKind.CHANGED
    assert findings[0].observed == {"memory": 2048}
    assert findings[0].desired == {"memory": 4096}


def test_parse_tofu_plan_malformed_or_empty() -> None:
    assert parse_tofu_plan("not json") == []
    assert parse_tofu_plan('{"no_drift_here": 1}') == []


def test_parse_ansible_check() -> None:
    output = (
        "TASK [ssh_hardening : set PermitRootLogin no] ***\n"
        "changed: [axiom]\n"
        "TASK [ufw : ensure enabled] ***\n"
        "ok: [axiom]\n"
    )
    findings = parse_ansible_check(output)
    assert len(findings) == 1
    assert findings[0].subject == "host:axiom"
    assert "PermitRootLogin" in findings[0].predicate
    assert findings[0].kind is DriftKind.CHANGED


def test_parse_ansible_check_escalates_failed_and_unreachable() -> None:
    # A failed or unreachable host during --check is critical: the desired state
    # could not be evaluated, a stronger signal than a would-change (BL-034).
    output = (
        "TASK [apt : install nginx] ***\n"
        'fatal: [db]: FAILED! => {"msg": "package not found"}\n'
        "TASK [ping check] ***\n"
        'fatal: [web]: UNREACHABLE! => {"msg": "timed out"}\n'
        "changed: [app]\n"
    )
    findings = parse_ansible_check(output)
    by_host = {f.subject: f for f in findings}
    assert by_host["host:db"].severity is DriftSeverity.CRITICAL
    assert by_host["host:db"].observed == {"failed": True, "unreachable": False}
    assert by_host["host:web"].severity is DriftSeverity.CRITICAL
    assert by_host["host:web"].observed["unreachable"] is True  # type: ignore[index]
    # A plain change stays a warning.
    assert by_host["host:app"].severity is DriftSeverity.WARNING
