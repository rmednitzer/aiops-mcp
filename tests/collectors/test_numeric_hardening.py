"""BL-026: finite-or-default numeric parsing of collected (attacker-influenced) data."""

from __future__ import annotations

import json

from praxis.collectors import AideCollector, OsqueryCollector, TalosCollector


def test_aide_hostile_digit_run_does_not_raise() -> None:
    # int() on a very long digit string raises under CPython's conversion limit;
    # a hostile report must clamp to the default, not break the collector.
    raw = (
        f"Total number of entries: {'9' * 5000}\n"
        "Added entries: 1\nRemoved entries: 0\nChanged entries: 0\n"
        "Added entries:\n/added/file\n"
    )
    facts = AideCollector().parse(raw, subject="host:axiom")
    assert len(facts) == 1
    totals = facts[0].value["totals"]
    assert isinstance(totals, dict)
    assert totals["total"] == 0  # clamped, not parsed
    assert totals["added"] == 1


def test_osquery_json_constants_become_none() -> None:
    raw = '[{"load": Infinity, "temp": NaN, "name": "ok"}]'
    facts = OsqueryCollector("system_load").parse(raw, subject="host:axiom")
    assert len(facts) == 1
    rows = facts[0].value["rows"]
    assert isinstance(rows, list)
    assert rows[0]["load"] is None
    assert rows[0]["temp"] is None
    # The fact value stays JSON-serialisable under the strict store encoding.
    json.dumps(facts[0].value, allow_nan=False)


def test_talos_json_constants_become_none() -> None:
    raw = '{"metric": -Infinity, "node": "10.0.0.1"}'
    facts = TalosCollector("talos_metrics").parse(raw, subject="host:k8s")
    assert len(facts) == 1
    assert facts[0].value["metric"] is None
    json.dumps(facts[0].value, allow_nan=False)
