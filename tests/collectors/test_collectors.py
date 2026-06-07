"""Collectors normalize raw telemetry into facts; malformed input never raises."""

from __future__ import annotations

from praxis.collectors import (
    AideCollector,
    CommandProbeCollector,
    OsqueryCollector,
    TalosCollector,
)
from praxis.model.facts import OBSERVED

_AIDE_REPORT = """AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:  1234
  Added entries:            1
  Removed entries:          0
  Changed entries:          2

Added entries:
f++++++++++++++++: /etc/newfile

Changed entries:
f   ....    : /etc/passwd
f   ....    : /etc/ssh/sshd_config
"""


def test_osquery_parses_rows() -> None:
    collector = OsqueryCollector("packages")
    facts = collector.parse('[{"name": "nginx", "version": "1.24"}]', subject="host:axiom")
    assert len(facts) == 1
    assert facts[0].predicate == "packages"
    assert facts[0].fact_type == OBSERVED
    assert facts[0].value["count"] == 1


def test_osquery_malformed_yields_no_facts() -> None:
    assert OsqueryCollector("x").parse("not json", subject="host:axiom") == []


def test_aide_parses_change_summary() -> None:
    facts = AideCollector().parse(_AIDE_REPORT, subject="host:axiom")
    assert len(facts) == 1
    value = facts[0].value
    assert value["clean"] is False
    assert value["complete"] is True
    assert "/etc/passwd" in value["changed"]  # type: ignore[operator]
    assert "/etc/newfile" in value["added"]  # type: ignore[operator]
    totals = value["totals"]
    assert isinstance(totals, dict)
    assert totals["changed"] == 2


def test_aide_empty_output_is_not_clean() -> None:
    # A failed/empty probe must NOT be reported as a clean host (BL-058): clean
    # requires positive evidence of a completed run, not the absence of diffs.
    for raw in ("", "   \n  \n"):
        value = AideCollector().parse(raw, subject="host:axiom")[0].value
        assert value["complete"] is False
        assert value["clean"] is False


def test_aide_clean_report_is_clean() -> None:
    clean = (
        "AIDE found NO differences between database and filesystem. Looks okay!!\n\n"
        "Summary:\n  Total number of entries:  4242\n  Added entries:            0\n"
        "  Removed entries:          0\n  Changed entries:          0\n"
    )
    value = AideCollector().parse(clean, subject="host:axiom")[0].value
    assert value["complete"] is True
    assert value["clean"] is True


def test_probe_parses_key_value() -> None:
    raw = 'NAME="Ubuntu"\nVERSION_ID="24.04"\n# comment\nPRETTY: Ubuntu 24.04'
    facts = CommandProbeCollector("os_release").parse(raw, subject="host:axiom")
    assert facts[0].value["NAME"] == "Ubuntu"
    assert facts[0].value["VERSION_ID"] == "24.04"
    assert facts[0].value["PRETTY"] == "Ubuntu 24.04"


def test_talos_parses_json_list() -> None:
    facts = TalosCollector("members").parse('[{"id": "cp-1"}, {"id": "cp-2"}]', subject="host:k8s")
    assert facts[0].value["count"] == 2


def test_talos_non_json_degrades_to_status() -> None:
    facts = TalosCollector("health").parse("all checks passed", subject="host:k8s")
    assert facts[0].value["status"] == "all checks passed"
