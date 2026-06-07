"""Desired-state source parsers: tofu plan and ansible check."""

from __future__ import annotations

from praxis.drift import DriftKind, parse_ansible_check, parse_tofu_plan


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
