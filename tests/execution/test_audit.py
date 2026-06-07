"""SEC-9 / SEC-8 / invariant 3: audit stores hash+len (never body), chains, never raises."""

from __future__ import annotations

import json
from pathlib import Path

from praxis.execution.audit import EMPTY_SHA256, AuditLogger, sha256_text, verify_chain
from praxis.execution.patterns import PATTERNS_VERSION


def test_no_body_only_hash_and_len(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    body = "sensitive command output that must never be written"
    logger.record(
        tool="collector",
        tier="T0",
        decision="allowed",
        args={"host": "axiom"},
        output_sha256=sha256_text(body),
        output_len=len(body),
        patterns_version=PATTERNS_VERSION,
    )
    logger.close()
    text = log.read_text(encoding="utf-8")
    record = json.loads(text.splitlines()[0])
    assert "output" not in record  # there is no body field at all
    assert record["output_sha256"] == sha256_text(body)
    assert record["output_len"] == len(body)
    assert body not in text  # the body itself was never written


def test_chain_verifies_and_detects_tamper(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    for i in range(3):
        logger.record(
            tool=f"tool{i}",
            tier="T0",
            decision="allowed",
            args={"i": i},
            patterns_version=PATTERNS_VERSION,
        )
    logger.close()
    assert verify_chain(log).ok is True

    lines = log.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["tool"] = "evil"
    lines[1] = json.dumps(tampered)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(log)
    assert result.ok is False
    assert result.broken_at == 1


def test_chain_continues_across_restart(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    first = AuditLogger(log)
    first.record(
        tool="a", tier="T0", decision="allowed", args={}, patterns_version=PATTERNS_VERSION
    )
    first.close()
    second = AuditLogger(log)
    second.record(
        tool="b", tier="T0", decision="allowed", args={}, patterns_version=PATTERNS_VERSION
    )
    second.close()
    result = verify_chain(log)
    assert result.ok is True
    assert result.count == 2


def test_logger_never_raises(tmp_path: Path) -> None:
    # Point the sink at a path whose parent is a regular file: opening must fail,
    # the logger must degrade to stderr rather than raise (SEC-8).
    blocker = tmp_path / "afile"
    blocker.write_text("x", encoding="utf-8")
    impossible = blocker / "sub" / "audit.jsonl"
    logger = AuditLogger(impossible)
    assert logger.degraded is True
    # Recording still works (degraded to stderr) and does not raise.
    record = logger.record(
        tool="t", tier="T0", decision="allowed", args={}, patterns_version=PATTERNS_VERSION
    )
    assert record.output_sha256 == EMPTY_SHA256
