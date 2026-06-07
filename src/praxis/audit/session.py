"""Session header: bind the running build's hash into the audit (ADR-0008).

Stamping the server-binary hash (a digest over the installed praxis source) and the
patterns version into the first audit record ties every later output hash to the
exact build that produced it.
"""

from __future__ import annotations

import hashlib
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


def bind_session(audit: AuditLogger) -> AuditRecord:
    """Write the session header as the first audit record (provenance binding)."""
    header = session_header()
    return audit.record(
        tool="praxis",
        tier="T0",
        decision="session",
        args={
            "praxis_version": header.praxis_version,
            "binary_sha256": header.binary_sha256,
            "started_at": header.started_at,
        },
        patterns_version=header.patterns_version,
    )
