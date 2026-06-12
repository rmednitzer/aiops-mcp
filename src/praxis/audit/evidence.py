"""Evidence checkpoints: periodic Merkle roots over the audit log (ADR-0008).

A checkpoint records the RFC 6962 Merkle root over the first ``tree_size`` audit
lines, stamps it (RFC 3161 interface; LocalStamper by default), and chains to the
previous checkpoint. ``verify_evidence`` is fail-closed: it re-verifies the
per-entry hash chain, recomputes each checkpoint's root from the log, checks the
checkpoint chain, requires every timestamp token to validate, and requires the
checkpoints to cover the full log (the last ``tree_size`` equals the line count and
sizes are non-decreasing) so a checkpoint cannot under-cover the log. Any break,
or any unreadable evidence line, returns ``ok=False`` (never raises).

Runtime production (BL-076): ``EvidenceScheduler`` is wired as the AuditLogger's
post-record hook, checkpointing every N records and at orderly shutdown
(``finalize``), so the running server produces evidence instead of leaving it an
out-of-band library. ``write_anchor`` appends each checkpoint head to a separate
anchor file (BL-050): ``verify_evidence`` cross-checks the latest anchored head,
so an attacker who can rewrite the audit log AND the evidence file but not the
anchor cannot truncate history below the anchored high-water mark undetected.
The anchor's value rests on the operator placing it on a separate trust domain
(another filesystem, host, or WORM store).

Threat boundary: ``LocalStamper`` (the default) is self-contained, not qualified
external time, and its token is forgeable by anyone who can write the evidence
file. Tamper-evidence against an attacker who can rewrite the audit log, the
evidence file, and the anchor therefore still requires a non-forgeable stamper (a
real RFC 3161 TSA, tracked as BL-095) or an out-of-band write-once anchor store.
See LIMITATIONS and ADR-0008.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path

from praxis.audit.merkle import merkle_root_hex
from praxis.audit.rfc3161 import LocalStamper, Stamper
from praxis.clock import utc_now_iso
from praxis.execution.audit import AuditRecord, verify_chain

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
    audit_path: Path,
    evidence_path: Path,
    *,
    stamper: Stamper | None = None,
    anchor_path: Path | None = None,
) -> EvidenceVerifyResult:
    active_stamper: Stamper = stamper if stamper is not None else LocalStamper()
    chain = verify_chain(audit_path)
    if not chain.ok:
        return EvidenceVerifyResult(False, 0, f"audit hash chain broken: {chain.reason}")
    leaves = _leaves(audit_path)
    if not evidence_path.exists():
        if anchor_path is not None:
            failure = _anchor_failure(anchor_path, heads={})
            if failure is not None:
                return EvidenceVerifyResult(False, 0, failure)
        return EvidenceVerifyResult(True, 0, None)

    prev = GENESIS_CHECKPOINT
    expected_seq = 0
    count = 0
    last_tree_size = 0
    heads: dict[int, str] = {}  # checkpoint seq -> checkpoint_hash (for the anchor check)
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
            heads[expected_seq] = prev
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
    if anchor_path is not None:
        failure = _anchor_failure(anchor_path, heads=heads)
        if failure is not None:
            return EvidenceVerifyResult(False, count, failure)
    return EvidenceVerifyResult(True, count, None)


def write_anchor(anchor_path: Path, checkpoint: MerkleCheckpoint) -> bool:
    """Append the checkpoint head to the anchor file (BL-050). Never raises.

    The anchor is the high-water mark ``verify_evidence`` cross-checks; its value
    rests on living on a separate trust domain from the audit log and evidence
    file (another filesystem, host, or WORM store). Owner-only and append-only at
    the OS level, mirroring the audit sink (BL-064). Returns False when the write
    failed, so the caller can warn; anchoring lag then surfaces at the next
    verify instead of being silently absorbed.
    """
    line = json.dumps(
        {
            "seq": checkpoint.seq,
            "tree_size": checkpoint.tree_size,
            "root_sha256": checkpoint.root_sha256,
            "checkpoint_hash": checkpoint.checkpoint_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    try:
        anchor_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(anchor_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        return True
    except OSError:
        return False


def _anchor_failure(anchor_path: Path, *, heads: dict[int, str]) -> str | None:
    """The anchor cross-check: None when consistent, else the fail-closed reason.

    The latest anchored head must name a checkpoint that exists, hash-identical,
    in the (already verified) evidence chain. Evidence truncated or regrown below
    the anchored high-water mark therefore fails, which is exactly the attack the
    per-file checks cannot see (BL-050). An anchor file that is configured but
    missing while checkpoints exist is itself a finding, not a pass. An empty or
    absent anchor over zero checkpoints is genesis, and verifies.
    """
    try:
        if not anchor_path.exists():
            return "anchor file missing while checkpoints exist (fail-closed)" if heads else None
        lines = [ln for ln in anchor_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if not lines:
            return "anchor file empty while checkpoints exist (fail-closed)" if heads else None
        last = json.loads(lines[-1])
        seq = int(last["seq"])
        anchored_hash = str(last["checkpoint_hash"])
        present = heads.get(seq)
        if present is None:
            return "anchored checkpoint absent from evidence (truncated below high-water mark)"
        if present != anchored_hash:
            return "anchored checkpoint hash mismatch (evidence rewritten)"
        return None
    except Exception as exc:  # noqa: BLE001 - fail-closed: an unreadable anchor is a failure
        return f"anchor unreadable (fail-closed): {type(exc).__name__}"


class EvidenceScheduler:
    """Produce checkpoints (and anchor heads) as the audit log grows (BL-076, BL-050).

    Wired as the AuditLogger's post-record hook: every ``every`` records it runs
    ``make_checkpoint`` over the audit file, and ``finalize`` covers the tail at
    orderly shutdown so ``verify_evidence``'s full-coverage rule holds at rest.
    Every failure is contained to a stderr warning and a reset interval: evidence
    production must never block or break the audited path (the per-entry hash
    chain remains the primary record). One scheduler serves one process; calls
    are serialised under a lock, mirroring the audit writer (BL-029).
    """

    def __init__(
        self,
        audit_path: Path,
        evidence_path: Path,
        *,
        every: int = 64,
        anchor_path: Path | None = None,
        stamper: Stamper | None = None,
    ) -> None:
        self.audit_path = audit_path
        self.evidence_path = evidence_path
        self.every = every
        self.anchor_path = anchor_path
        self.stamper = stamper
        self._lock = threading.Lock()
        self._pending = 0

    def on_record(self, record: AuditRecord) -> None:
        """Count one written record; checkpoint when the interval fills."""
        if self.every <= 0:
            return
        with self._lock:
            self._pending += 1
            if self._pending >= self.every:
                self._checkpoint_locked()

    def finalize(self) -> None:
        """Checkpoint any uncovered tail (orderly shutdown). Never raises."""
        with self._lock:
            if self._pending > 0:
                self._checkpoint_locked()

    def _checkpoint_locked(self) -> None:
        # The interval resets on failure too, so a persistently failing sink
        # retries once per interval instead of on every record.
        self._pending = 0
        try:
            if not self.audit_path.exists():
                return  # the logger degraded to stderr: nothing to checkpoint
            checkpoint = make_checkpoint(self.audit_path, self.evidence_path, stamper=self.stamper)
            if self.anchor_path is not None and not write_anchor(self.anchor_path, checkpoint):
                with suppress(Exception):
                    print(
                        f"[praxis.evidence] anchor write failed ({self.anchor_path}); the "
                        "checkpoint is unanchored and verify will flag it (BL-050)",
                        file=sys.stderr,
                    )
        except Exception as exc:  # noqa: BLE001 - contained: never break the audited path
            with suppress(Exception):
                print(
                    f"[praxis.evidence] checkpoint failed ({exc!r}); will retry after the "
                    "next interval (the audit hash chain is unaffected)",
                    file=sys.stderr,
                )
