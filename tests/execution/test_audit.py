"""SEC-9 / SEC-8 / invariant 3: audit stores hash+len (never body), chains, never raises."""

from __future__ import annotations

import json
import stat
import sys
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


def test_corrupt_tail_keeps_writing_to_file_as_visible_seam(tmp_path: Path) -> None:
    # A corrupt tail must NOT drop the sink to stderr (which would lose the record);
    # the logger resumes at genesis and keeps writing to the file. The seq reset is a
    # visible seam verify_chain reports, which is the security signal (BL-055).
    log = tmp_path / "audit.jsonl"
    first = AuditLogger(log)
    first.record(
        tool="a", tier="T0", decision="allowed", args={}, patterns_version=PATTERNS_VERSION
    )
    first.close()
    with log.open("a", encoding="utf-8") as handle:
        handle.write("{ this is not valid json\n")

    second = AuditLogger(log)
    assert second.degraded is False  # sink stayed on the file, not stderr
    second.record(
        tool="b", tier="T0", decision="allowed", args={}, patterns_version=PATTERNS_VERSION
    )
    second.close()

    lines = [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    last = json.loads(lines[-1])
    assert last["tool"] == "b"  # the new record reached the file, not stderr
    # The corruption is exposed by verification, not hidden by the writer.
    assert verify_chain(log).ok is False


def test_non_utf8_tail_does_not_raise_on_construction(tmp_path: Path) -> None:
    # A corrupted/poisoned audit file with invalid UTF-8 bytes must not crash
    # construction (UnicodeDecodeError is a ValueError, not an OSError); the logger
    # resumes at genesis and keeps recording (SEC-8, "construction never raises").
    log = tmp_path / "audit.jsonl"
    log.write_bytes(b"\xff\xfe not valid utf-8 \x80\x81\n")
    logger = AuditLogger(log)  # must not raise
    rec = logger.record(
        tool="a", tier="T0", decision="allowed", args={}, patterns_version=PATTERNS_VERSION
    )
    logger.close()
    assert rec.seq == 0  # resumed at genesis after the unreadable tail


def test_audit_file_is_owner_only(tmp_path: Path) -> None:
    if sys.platform.startswith("win"):  # pragma: no cover - POSIX mode bits only
        return
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    logger.record(
        tool="a", tier="T0", decision="allowed", args={}, patterns_version=PATTERNS_VERSION
    )
    logger.close()
    # The audit log holds redacted parameters; it must not be world/group readable.
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


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
