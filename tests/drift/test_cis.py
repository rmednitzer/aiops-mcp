"""CIS-Talos drift baseline (BL-099, ADR-0024): schema, severity, suppression, collector."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from praxis.actuation.credentials import CredentialBroker
from praxis.collectors import CisCollector
from praxis.context import ServerContext
from praxis.drift import (
    CIS_BASELINE,
    CIS_SUPPRESSED,
    TALOS_SATISFIED,
    cis_baseline_facts,
    cis_drift,
    cis_severity,
    default_severity,
    normalize_value,
    seed_cis_baseline,
)
from praxis.drift.cis import active_control_keys, active_controls
from praxis.drift.findings import DriftKind, DriftSeverity
from praxis.execution import AuditLogger, ExecutionContext, Mode, Policy
from praxis.model.facts import KNOWN_GOOD, OBSERVED, Fact
from praxis.server import build_registry
from praxis.store import SqliteStore


def _observed(facts: list[Fact]) -> list[Fact]:
    """The collector's view: the same key/value, fact_type OBSERVED, no reason."""
    return [replace(f, fact_type=OBSERVED, reason=None) for f in facts]


def test_normalize_value_is_symmetric_and_order_insensitive() -> None:
    assert normalize_value(True) == "true"
    assert normalize_value(False) == "false"
    assert normalize_value("False") == "false"  # a boolean-like string lowercases too
    assert normalize_value(0) == "0"
    assert normalize_value(" 127.0.0.1 ") == "127.0.0.1"  # trimmed
    # A list and any comma-joined string of the same tokens normalize identically.
    assert normalize_value(["RBAC", "Node"]) == "Node,RBAC"
    assert normalize_value("RBAC,Node") == "Node,RBAC"
    assert normalize_value("Node,RBAC") == "Node,RBAC"
    # List items are trimmed too, so whitespace in a JSON array cannot drift against
    # the clean baseline list or the equivalent comma-string.
    assert normalize_value(["Node ", " RBAC"]) == "Node,RBAC"
    assert normalize_value([" true "]) == "true"


def test_baseline_facts_carry_the_adr_0024_schema() -> None:
    facts = cis_baseline_facts(nodes=["n1"], control_plane_nodes=["cp1"], clusters=["c1"])
    assert facts, "baseline must materialize facts"
    by_subject_prefix = {f.subject.split(":", 1)[0] for f in facts}
    assert by_subject_prefix <= {"host", "cluster"}
    for fact in facts:
        assert fact.fact_type == KNOWN_GOOD
        assert fact.predicate.startswith("cis:talos:")
        assert set(fact.value) == {"value"}
        assert isinstance(fact.value["value"], str)  # normalized to one comparable form
        meta = json.loads(fact.reason or "{}")
        assert {"id", "benchmark", "title", "level", "scored", "cis_ref"} <= set(meta)
    # Node controls attach to the node, control-plane components to the CP node, the
    # cluster singleton to the cluster.
    preds = {(f.subject, f.predicate.split(":")[-1]) for f in facts}
    assert ("host:n1", "kubelet-anonymous-auth") in preds
    assert ("host:cp1", "apiserver-anonymous-auth") in preds
    assert ("cluster:c1", "cluster-default-pod-security") in preds


def test_suppressed_and_satisfied_controls_are_excluded_from_the_active_set() -> None:
    keys = active_control_keys()
    # The suppressed control IS a baseline control, but is dropped from the active set
    # (a named waiver of a real control, not a vacuous entry).
    assert any(c.key == "talos:kubelet-event-qps" for c in CIS_BASELINE)
    assert "talos:kubelet-event-qps" not in keys
    for key in CIS_SUPPRESSED:
        assert key not in keys
    # Talos-satisfied controls are documented as structurally guaranteed and never
    # appear in the checkable set.
    for key in TALOS_SATISFIED:
        assert key not in keys
    facts = cis_baseline_facts(nodes=["n1"])
    assert all("kubelet-event-qps" not in f.predicate for f in facts)


def test_cis_severity_ranks_cis_critical_and_delegates_otherwise() -> None:
    assert cis_severity("cis:talos:kubelet-anon", DriftKind.CHANGED) is DriftSeverity.CRITICAL
    assert cis_severity("cis:talos:anything", DriftKind.MISSING) is DriftSeverity.CRITICAL
    # A non-CIS predicate falls back to the engine default unchanged.
    assert cis_severity("os_version", DriftKind.CHANGED) is default_severity(
        "os_version", DriftKind.CHANGED
    )
    assert cis_severity("os_version", DriftKind.CHANGED) is DriftSeverity.WARNING


def test_compliant_node_has_no_cis_drift() -> None:
    base = cis_baseline_facts(nodes=["n1"], control_plane_nodes=["cp1"], clusters=["c1"])
    observed = _observed(base)
    assert cis_drift(observed, nodes=["n1"], control_plane_nodes=["cp1"], clusters=["c1"]) == []


def test_changed_control_is_a_critical_finding() -> None:
    base = cis_baseline_facts(nodes=["n1"])
    observed = _observed(base)
    target = observed[0]
    drifted = [replace(target, value={"value": "DRIFTED"})] + observed[1:]
    findings = cis_drift(drifted, nodes=["n1"])
    assert len(findings) == 1
    assert findings[0].predicate == target.predicate
    assert findings[0].kind is DriftKind.CHANGED
    assert findings[0].severity is DriftSeverity.CRITICAL


def test_unevaluated_control_surfaces_as_missing() -> None:
    base = cis_baseline_facts(nodes=["n1"])
    observed = _observed(base)
    dropped = observed[0]
    findings = cis_drift(observed[1:], nodes=["n1"])
    assert len(findings) == 1
    assert findings[0].predicate == dropped.predicate
    assert findings[0].kind is DriftKind.MISSING
    assert findings[0].severity is DriftSeverity.CRITICAL


def test_collector_normalizes_and_filters_to_active_controls() -> None:
    evidence = {
        "benchmark": "talos",
        "controls": {
            "kubelet-anonymous-auth": "False",  # active -> normalized to "false"
            "kubelet-event-qps": 5,  # suppressed -> dropped
            "node-no-ssh": True,  # Talos-satisfied -> dropped
            "totally-unknown": 1,  # not in any benchmark -> dropped
        },
    }
    facts = CisCollector().parse(json.dumps(evidence), subject="host:n1")
    assert {f.predicate for f in facts} == {"cis:talos:kubelet-anonymous-auth"}
    assert facts[0].fact_type == OBSERVED
    assert facts[0].value == {"value": "false"}


def test_collector_is_fail_soft_on_bad_input() -> None:
    assert CisCollector().parse("", subject="host:n1") == []
    assert CisCollector().parse("not json", subject="host:n1") == []
    assert CisCollector().parse("[1, 2, 3]", subject="host:n1") == []  # not an object


def test_collector_output_round_trips_to_no_drift_when_compliant() -> None:
    node_controls = [c for c in active_controls() if c.scope == "node"]
    evidence = {"benchmark": "talos", "controls": {c.control_id: c.desired for c in node_controls}}
    observed = CisCollector().parse(json.dumps(evidence), subject="host:n1")
    assert len(observed) == len(node_controls)
    assert cis_drift(observed, nodes=["n1"]) == []


def test_seed_cis_baseline_writes_known_good_facts() -> None:
    store = SqliteStore()
    count = seed_cis_baseline(store, nodes=["n1"], control_plane_nodes=["n1"], clusters=["c1"])
    expected = cis_baseline_facts(nodes=["n1"], control_plane_nodes=["n1"], clusters=["c1"])
    assert count == len(expected)
    stored = store.list_active(fact_type=KNOWN_GOOD)
    assert len(stored) == count
    assert all(f.predicate.startswith("cis:talos:") for f in stored)


def _ctx(tmp_path: Path) -> ServerContext:
    execution = ExecutionContext(
        policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "audit.jsonl")
    )
    return ServerContext(execution=execution, store=SqliteStore(), broker=CredentialBroker())


def test_drift_scan_tool_ranks_cis_drift_critical(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    seed_cis_baseline(ctx.store, nodes=["n1"])
    # A node observed weaker than the baseline (anonymous auth enabled).
    ctx.store.put_fact(
        Fact(
            subject="host:n1",
            predicate="cis:talos:kubelet-anonymous-auth",
            fact_type=OBSERVED,
            value={"value": "true"},
            t_valid="2026-06-10T00:00:00.000000Z",
            actor="collector",
        )
    )
    body = json.loads(build_registry().call("drift_scan", {"subject": "host:n1"}, ctx))
    changed = [
        f
        for f in body["findings"]
        if f["predicate"] == "cis:talos:kubelet-anonymous-auth" and f["kind"] == "changed"
    ]
    assert len(changed) == 1
    assert changed[0]["severity"] == "critical"
    # Every CIS finding (the changed one and the unobserved-control MISSING ones) is
    # ranked critical by the CIS-aware severity now wired into the scan.
    assert all(f["severity"] == "critical" for f in body["findings"])
