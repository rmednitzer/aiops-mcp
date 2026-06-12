"""praxis CLI entry point: env -> config -> store -> context -> MCP server.

Defaults to stdio against the SQLite store with no external services. HTTP requires
the opt-in invariants and fails closed otherwise (ADR-0006).
"""

from __future__ import annotations

import sys

from praxis.config import CONFIG, TransportError
from praxis.server import serve


def main() -> None:
    try:
        serve(CONFIG)
    except TransportError as exc:
        raise SystemExit(f"praxis: refusing to start: {exc}") from exc
    except KeyboardInterrupt:  # pragma: no cover - interactive
        sys.exit(0)


if __name__ == "__main__":
    main()  # pragma: no cover - exercised as a process, not an import
