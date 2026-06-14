"""Audit hardening: non-JSON-native args never raise (BL-078) and hash exactly the
written rendering (BL-094); concurrent appends keep one unbroken chain (BL-029)."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from praxis.execution import AuditLogger, verify_chain
from praxis.execution.patterns import PATTERNS_VERSION


def test_record_never_raises_on_non_json_native_args(tmp_path: Path) -> None:
    # BL-078: a Path, a set, or any non-native value canonicalizes via str()
    # instead of raising out of the logger (logger-never-raises, invariant 3).
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    logger.record(
        tool="collector",
        tier="T0",
        decision="allowed",
        args={"path": Path("/etc/passwd"), "tags": {"a", "b"}},
        patterns_version=PATTERNS_VERSION,
    )
    logger.close()
    result = verify_chain(log)
    assert result.ok is True
    assert result.count == 1


class _CopySensitive:
    """str() differs between an object and its deep copy.

    The honest stand-in for a set under an unlucky hash seed: deepcopy preserves
    equality but not iteration order, so str(copy) can differ from str(original).
    """

    def __init__(self, generation: int = 0) -> None:
        self.generation = generation

    def __deepcopy__(self, memo: dict[int, Any]) -> _CopySensitive:
        return _CopySensitive(self.generation + 1)

    def __str__(self) -> str:
        return f"copy-sensitive-{self.generation}"


def test_entry_hash_commits_to_the_written_rendering(tmp_path: Path) -> None:
    # BL-094: record() must hash the same rendering it writes. Before the fix,
    # the hash covered str() of the live arg while the written line carried
    # str() of the asdict() deep copy, so a value whose str() is copy-sensitive
    # (a set, under some hash seeds) produced a line failing its own entry_hash
    # and an honest log verified as tampered.
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    record = logger.record(
        tool="collector",
        tier="T0",
        decision="allowed",
        args={"probe": _CopySensitive()},
        patterns_version=PATTERNS_VERSION,
    )
    logger.close()
    # The in-memory record is already the normalized, written form.
    assert record.args == {"probe": "copy-sensitive-0"}
    result = verify_chain(log)
    assert result.ok is True, result.reason
    assert result.count == 1


def test_concurrent_records_keep_an_unbroken_chain(tmp_path: Path) -> None:
    # BL-029: payload-build + write + chain-advance are serialised, so threaded
    # writers cannot interleave seq/prev_hash state.
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    per_thread = 50

    def write_many() -> None:
        for i in range(per_thread):
            logger.record(
                tool="collector",
                tier="T0",
                decision="allowed",
                args={"i": i},
                patterns_version=PATTERNS_VERSION,
            )

    threads = [threading.Thread(target=write_many) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    logger.close()
    result = verify_chain(log)
    assert result.ok is True, result.reason
    assert result.count == 4 * per_thread


def test_record_never_raises_on_hostile_str_or_circular_args(tmp_path: Path) -> None:
    # F-001: the logger must never raise (invariant 3) even on an arg value whose
    # __str__ raises, or a circular reference. Neither is reachable from JSON-RPC args
    # (native, acyclic), but the "never raises by construction" guarantee must hold for
    # any input, not only JSON-native ones.
    class Boom:
        def __str__(self) -> str:
            raise RuntimeError("hostile __str__")

    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    logger.record(
        tool="t",
        tier="T0",
        decision="allowed",
        args={"x": Boom()},
        patterns_version=PATTERNS_VERSION,
    )
    cyclic: dict[str, Any] = {}
    cyclic["self"] = cyclic
    logger.record(
        tool="t",
        tier="T0",
        decision="allowed",
        args={"c": cyclic},
        patterns_version=PATTERNS_VERSION,
    )
    logger.close()
    # Both records were written and the chain still verifies (the contained renderings
    # are deterministic, so each line hashes to its stored entry_hash).
    result = verify_chain(log)
    assert result.ok is True, result.reason
    assert result.count == 2
