"""Evidence checkpoints: periodic Merkle roots over the audit log (ADR-0008).

A checkpoint records the RFC 6962 Merkle root over the first ``tree_size`` audit
lines, stamps it (RFC 3161 interface; LocalStamper by default), and chains to the
previous checkpoint. ``verify_evidence`` is fail-closed: it re-verifies the
per-entry hash chain, recomputes each checkpoint's root from the log, checks the
checkpoint chain, requires every timestamp token to validate, and requires the
checkpoints to cover the full log (the last ``tree_size`` equals the line count and
sizes are non-decreasing) so a checkpoint cannot under-cover the log. Any break,
or any unreadable evidence line, returns ``ok=False`` (never raises).

Threat boundary: ``LocalStamper`` (the default) is self-contained, not qualified
external time, and its token is forgeable by anyone who can write the evidence
file. Tamper-evidence against an attacker who can rewrite both the audit log and
the evidence file therefore requires a non-forgeable stamper (a real RFC 3161 TSA)
and an out-of-band write-once store; without those, an attacker who truncates the
audit log to empty and writes a matching empty checkpoint cannot be detected here
(tracked as BL-050, an anchored high-water-mark). See LIMITATIONS and ADR-0008.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from praxis.audit.merkle import merkle_root_hex
from praxis.audit.rfc3161 import LocalStamper, Stamper
from praxis.clock import utc_now_iso
from praxis.execution.audit import verify_chain

GENESIS_CHECKPOINT = "0" * 64


@dataclass(frozen=True)
class MerkleCheckpoint:
    seq: int
    tree_size: int
    root_sha256: str
    ts: str
    token: dict[str, object]
    prev: str
    checkpoint_hash: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class EvidenceVerifyResult:
    ok: bool
    checkpoints: int
    reason: str | None


def _leaves(audit_path: Path) -> list[bytes]:
    return [
        line.encode("utf-8")
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _checkpoint_hash(payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _last_checkpoint(evidence_path: Path) -> tuple[str, int]:
    if not evidence_path.exists():
        return GENESIS_CHECKPOINT, 0
    last: dict[str, object] | None = None
    for line in evidence_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            last = json.loads(line)
    if last is None:
        return GENESIS_CHECKPOINT, 0
    return str(last["checkpoint_hash"]), int(str(last["seq"])) + 1


def make_checkpoint(
    audit_path: Path, evidence_path: Path, *, stamper: Stamper | None = None
) -> MerkleCheckpoint:
    active_stamper: Stamper = stamper if stamper is not None else LocalStamper()
    leaves = _leaves(audit_path)
    root = merkle_root_hex(leaves)
    prev, seq = _last_checkpoint(evidence_path)
    ts = utc_now_iso()
    token = active_stamper.stamp(root)
    payload: dict[str, object] = {
        "seq": seq,
        "tree_size": len(leaves),
        "root_sha256": root,
        "ts": ts,
        "token": token,
        "prev": prev,
    }
    checkpoint = MerkleCheckpoint(
        seq=seq,
        tree_size=len(leaves),
        root_sha256=root,
        ts=ts,
        token=token,
        prev=prev,
        checkpoint_hash=_checkpoint_hash(payload),
    )
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    with evidence_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(checkpoint.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
    return checkpoint


def verify_evidence(
    audit_path: Path, evidence_path: Path, *, stamper: Stamper | None = None
) -> EvidenceVerifyResult:
    active_stamper: Stamper = stamper if stamper is not None else LocalStamper()
    chain = verify_chain(audit_path)
    if not chain.ok:
        return EvidenceVerifyResult(False, 0, f"audit hash chain broken: {chain.reason}")
    leaves = _leaves(audit_path)
    if not evidence_path.exists():
        return EvidenceVerifyResult(True, 0, None)

    prev = GENESIS_CHECKPOINT
    expected_seq = 0
    count = 0
    last_tree_size = 0
    try:
        for line in evidence_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            cp = json.loads(line)
            if cp.get("prev") != prev:
                return EvidenceVerifyResult(False, count, "checkpoint chain broken")
            if cp.get("seq") != expected_seq:
                return EvidenceVerifyResult(False, count, "checkpoint seq discontinuity")
            payload = {k: cp[k] for k in ("seq", "tree_size", "root_sha256", "ts", "token", "prev")}
            if _checkpoint_hash(payload) != cp.get("checkpoint_hash"):
                return EvidenceVerifyResult(False, count, "checkpoint hash mismatch")
            tree_size = int(cp["tree_size"])
            # A checkpoint covers a non-decreasing prefix of the log and can never
            # claim more lines than exist; this defeats a forged under-covering
            # checkpoint (for example tree_size=0 over a non-empty log).
            if tree_size < last_tree_size or tree_size > len(leaves):
                return EvidenceVerifyResult(False, count, "checkpoint tree_size out of range")
            recomputed = merkle_root_hex(leaves[:tree_size])
            if recomputed != cp.get("root_sha256"):
                return EvidenceVerifyResult(False, count, "merkle root mismatch (tamper detected)")
            if not active_stamper.verify(str(cp["root_sha256"]), cp["token"]):
                return EvidenceVerifyResult(False, count, "timestamp token invalid (fail-closed)")
            prev = str(cp["checkpoint_hash"])
            expected_seq += 1
            count += 1
            last_tree_size = tree_size
    except Exception as exc:  # noqa: BLE001 - fail-closed: any unreadable evidence is a failure
        return EvidenceVerifyResult(
            False, count, f"evidence unreadable (fail-closed): {type(exc).__name__}"
        )
    if count > 0 and last_tree_size != len(leaves):
        return EvidenceVerifyResult(
            False, count, "checkpoints do not cover the full audit log (uncovered tail)"
        )
    return EvidenceVerifyResult(True, count, None)
