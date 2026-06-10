"""BL-017/BL-062/BL-085: every tool call, read or write, is individually audited;
reads of observed facts arm the trifecta latch; BL-049: scoped credentials gate
actuation once the first grant exists."""

from __future__ import annotations

import json
from pathlib import Path

from praxis.actuation.credentials import CredentialBroker
from praxis.context import ServerContext
from praxis.execution import AuditLogger, ExecutionContext, Mode, Policy, Tier
from praxis.model.facts import KNOWN_GOOD, OBSERVED, Fact
from praxis.server import build_registry
from praxis.store import SqliteStore


def _ctx(tmp_path: Path) -> ServerContext:
    execution = ExecutionContext(
        policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "audit.jsonl")
    )
    return ServerContext(execution=execution, store=SqliteStore(), broker=CredentialBroker())


def _records(tmp_path: Path, ctx: ServerContext) -> list[dict[str, object]]:
    ctx.execution.audit.close()
    return [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _observed(predicate: str = "os_version") -> Fact:
    return Fact(
        subject="host:axiom",
        predicate=predicate,
        fact_type=OBSERVED,
        value={"v": "24.04"},
        t_valid="2026-06-10T00:00:00.000000Z",
        actor="collector",
    )


def test_every_tool_writes_an_audit_record(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    registry = build_registry()
    registry.call("query_facts", {}, ctx)
    registry.call("fact_history", {"subject": "host:axiom"}, ctx)
    registry.call("drift_scan", {}, ctx)
    registry.call(
        "ingest_observation",
        {"collector": "probe", "subject": "host:axiom", "raw": "NAME=Ubuntu"},
        ctx,
    )
    tools = [r["tool"] for r in _records(tmp_path, ctx)]
    for expected in ("query_facts", "fact_history", "drift_scan", "ingest_observation"):
        assert expected in tools, f"{expected} left no audit record (invariant 1)"


def test_ingest_audit_summarizes_raw_never_stores_it(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    raw = "SECRET-TELEMETRY-BODY-marker NAME=Ubuntu"
    build_registry().call(
        "ingest_observation",
        {"collector": "probe", "subject": "host:axiom", "raw": raw},
        ctx,
    )
    assert ctx.untrusted_ingested is True  # armed on the audited path (BL-083)
    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "SECRET-TELEMETRY-BODY-marker" not in text
    records = _records(tmp_path, ctx)
    ingest = next(r for r in records if r["tool"] == "ingest_observation")
    args = ingest["args"]
    assert isinstance(args, dict)
    assert args["raw_sha256"]
    assert args["raw_len"] == len(raw)


def test_reading_observed_facts_arms_the_latch(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    ctx.store.put_fact(_observed())
    assert ctx.untrusted_ingested is False
    build_registry().call("query_facts", {}, ctx)
    assert ctx.untrusted_ingested is True


def test_reading_only_desired_facts_does_not_arm_the_latch(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    ctx.store.put_fact(
        Fact(
            subject="host:axiom",
            predicate="os_version",
            fact_type=KNOWN_GOOD,
            value={"v": "24.04"},
            t_valid="2026-06-10T00:00:00.000000Z",
            actor="operator",
        )
    )
    build_registry().call("query_facts", {"fact_type": KNOWN_GOOD}, ctx)
    assert ctx.untrusted_ingested is False


def test_first_grant_flips_actuation_to_deny_unless_authorized(tmp_path: Path) -> None:
    # BL-049: zero grants = single-operator default (no scope gate); the first
    # grant makes every actuation require a covering scope, audited in-path.
    from praxis.tools.actuate import RunActionArgs, _run_action

    ctx = _ctx(tmp_path)
    args = RunActionArgs.model_validate(
        {
            "adapter": "ssh",
            "host": "axiom",
            "host_type": "ubuntu",
            "ssh_alias": "axiom",
            "action": "uptime",
            "dry_run": True,
        }
    )
    # Ungated by the broker while no grants exist.
    body = json.loads(_run_action(args, ctx))
    assert body["ok"] is True

    assert ctx.broker is not None
    ctx.broker.grant("ops", hosts=frozenset({"atlas"}), max_tier=Tier.T2)
    # axiom is not covered by any grant: refused as a HARD audited precondition.
    refused = json.loads(_run_action(args, ctx))
    assert refused["ok"] is False
    assert "credential" in refused["error"]

    # A covering grant authorizes it again.
    ctx.broker.grant("ops", hosts=frozenset({"axiom"}), max_tier=Tier.T2)
    allowed = json.loads(_run_action(args, ctx))
    assert allowed["ok"] is True
