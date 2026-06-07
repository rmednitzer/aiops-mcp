"""Postgres backend parity. Skips cleanly when psycopg or a live PG is absent (BL-006)."""

from __future__ import annotations

import os

import pytest

pytest.importorskip("psycopg")

from praxis.model import OBSERVED, Fact  # noqa: E402
from praxis.store.postgres import PostgresStore  # noqa: E402

PG_DSN = os.environ.get("PRAXIS_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(
    not PG_DSN, reason="set PRAXIS_TEST_PG_DSN to run Postgres backend tests"
)


def _os_fact() -> Fact:
    return Fact(
        subject="host:pgtest",
        predicate="os_version",
        fact_type=OBSERVED,
        value={"version": "24.04"},
        t_valid="2026-06-07T00:00:00.000000Z",
        actor="collector",
    )


def test_postgres_roundtrip() -> None:
    assert PG_DSN is not None
    store = PostgresStore(PG_DSN)
    stored = store.put_fact(_os_fact())
    assert stored.fact_id is not None
    got = store.get_active("host:pgtest", "os_version", OBSERVED)
    assert got is not None
    assert got.value["version"] == "24.04"
    store.close()
