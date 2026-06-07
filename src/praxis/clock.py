"""A single source of wall-clock time, in ISO 8601 UTC (CLAUDE.md: 24h UTC).

A leaf utility with no praxis dependencies, so any layer may import it without
creating an upward coupling.
"""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now_iso() -> str:
    """Current time as an ISO 8601 UTC string with microsecond precision (%f)."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
