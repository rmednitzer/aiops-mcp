"""Session header: bind the running build's hash into the audit (ADR-0008).

Stamping the server-binary hash (a digest over the installed praxis source) and the
patterns version into the first audit record ties every later output hash to the
exact build that produced it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import praxis
from praxis.clock import utc_now_iso
from praxis.execution.audit import AuditLogger, AuditRecord
from praxis.execution.patterns import PATTERNS_VERSION


def server_binary_hash() -> str:
    """A stable SHA-256 over the installed praxis package source (path + content)."""
    pkg_dir = Path(praxis.__file__).resolve().parent
    digest = hashlib.sha256()
    for path in sorted(pkg_dir.rglob("*.py")):
        digest.update(path.relative_to(pkg_dir).as_posix().encode("utf-8"))
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


@dataclass(frozen=True)
class SessionHeader:
    praxis_version: str
    binary_sha256: str
    patterns_version: int
    started_at: str


def session_header() -> SessionHeader:
    return SessionHeader(
        praxis_version=praxis.__version__,
        binary_sha256=server_binary_hash(),
        patterns_version=PATTERNS_VERSION,
        started_at=utc_now_iso(),
    )


def bind_session(audit: AuditLogger, *, retention: Mapping[str, int] | None = None) -> AuditRecord:
    """Write the session header as the first audit record (provenance binding).

    With ``retention`` supplied (the configured audit/evidence retention tiers,
    ``Config.retention_args``, BL-035), the declared policy is bound into this first
    record, so the retention in force is part of the tamper-evident trail rather than
    documentation alone (NIS2 Art. 23, ISO 27001 A.8.15). The argument is additive:
    omitting it preserves the prior record shape.
    """
    header = session_header()
    args: dict[str, object] = {
        "praxis_version": header.praxis_version,
        "binary_sha256": header.binary_sha256,
        "started_at": header.started_at,
    }
    if retention is not None:
        # The session record is the provenance root: a retention key must never
        # shadow a provenance field (binary_sha256, praxis_version, started_at), so a
        # collision is refused rather than silently overwriting the binding. The real
        # caller passes only the two retention-day keys, so this cannot fire there; it
        # guards a future caller against corrupting the trail's root of trust.
        collisions = sorted(set(retention) & set(args))
        if collisions:
            raise ValueError(f"retention keys collide with provenance fields: {collisions}")
        args.update(retention)
    return audit.record(
        tool="praxis",
        tier="T0",
        decision="session",
        args=args,
        patterns_version=header.patterns_version,
    )
