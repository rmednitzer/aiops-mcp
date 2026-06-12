# ADR-0018: Backlog remediation wave (2026-06-12): store parity, supply-chain pinning, coverage gate, deploy hardening

## Status

Accepted

## Date

2026-06-12

## Authors

praxis maintainers (implementation wave following the ADR-0017 audit pass)

## Context

ADR-0017 recorded a full read-only audit: no Critical/High/Medium findings, with
the actionable work filed as backlog rather than fixed in-pass, chiefly because
the audit environment could not verify a Postgres schema change. This wave runs in
an environment that can: a live PostgreSQL 16.13 (throwaway cluster on a Unix
socket) and helm 3.21 were available, so the deferred store change and the Helm
items could be implemented against real verification rather than shipped blind.

It follows the ADR-0013/ADR-0016 precedent: an implementation wave that remediates
a validated cluster of backlog items in the accompanying change, each with a
regression test or an equivalent rendered verification.

## Decision

1. Postgres storage-layer parity (BL-091, BL-028). The Postgres backend now
   computes ``seq`` inside the INSERT under new unique indexes
   (``facts_seq_unique``, ``edges_seq_unique``), exactly as the SQLite backend has
   since BL-068, so a cross-instance ``MAX(seq)+1`` race fails loudly with a
   ``UniqueViolation`` instead of silently corrupting fact ordering; the separate
   ``_next_seq`` read is removed. A statement-level ``BEFORE TRUNCATE`` trigger
   (row-level triggers do not fire for TRUNCATE) refuses table-wide truncation on
   both tables, and ``TRUNCATE`` is revoked from ``PUBLIC``. The trigger is the
   enforcing control: the table owner is not bound by the revoke, and the optional
   ``RESTRICTIVE`` RLS floor named in BL-028 is assessed as not load-bearing for
   the single-role v0 deployment (an owner who can drop policies can drop the
   trigger too; engine-level protection against the owner is out of scope, the
   same boundary the SQLite backend documents).

2. Hash-locked, bounded toolchain (BL-088). ``pyproject.toml`` bounds the dev
   extra (ruff <0.16, mypy <3, pytest <10, coverage <8), the postgres extra
   (psycopg <4), and the build backend (hatchling <2), so majors cannot land
   unreviewed. ``requirements-dev.txt`` (``uv pip compile --generate-hashes
   --universal``) is the exact CI install, consumed with ``pip --require-hashes``;
   Renovate maintains both. The fuzz workflow moves from Python 3.14 to 3.13 so
   the security surfaces are fuzzed on an interpreter the test matrix covers. The
   SBOM job installs the project into a dedicated venv and points ``cyclonedx-py``
   at that venv's interpreter, scoping the SBOM to the production dependency graph
   instead of the runner environment. The local ``uv sync`` lock (``uv.lock``) is
   gitignored: the supply-chain record is the hash-locked requirements file.

3. Coverage floor on the aggregate gate (BL-053). ``coverage`` joins the dev
   extra; measurement is source-based (every file under ``src/praxis`` counts,
   imported or not) with ``fail_under = 90`` against a measured 91 percent without
   the postgres extra. ``make coverage`` joins ``ci-success``. Source-based
   measurement surfaced the previously invisible ``__main__.py`` at zero, which
   gained tests for the fail-closed ``TransportError`` to ``SystemExit`` refusal
   and for serving the import-bound CONFIG.

4. Helm hardening and honesty (BL-051, BL-086, BL-093). The NetworkPolicy ingress
   admits only the peers named in ``networkPolicy.ingressFrom``; the empty default
   denies all ingress to the MCP port (fail closed), where previously any pod
   could reach it. The PostgreSQL DSN moves to a ``secretKeyRef``
   (``store.existingSecret``/``store.secretKey``), and a legacy inline ``storeDsn``
   value now fails the render with a migration message instead of landing the
   password in etcd and ``helm history``. ``NOTES.txt`` and a values comment state
   at install time that v0 refuses non-stdio transports, so the default chart
   CrashLoopBackOffs until HTTP serving lands (BL-012).

5. Audit self-consistency (BL-094, found during this wave by the new coverage
   gate re-running the suite under fresh hash seeds). ``AuditLogger.record``
   hashed the canonical form of the live payload while ``_write`` rendered the
   ``asdict()`` deep copy, and ``str()`` of a copy is not stable for every value
   (a deepcopied set may iterate in a different order; deterministic at
   ``PYTHONHASHSEED=24``), so a record with non-JSON-native args could fail its
   own ``entry_hash`` and an honest log verified as tampered (invariant 3, the
   BL-078 surface). ``record`` now normalizes the payload through one canonical
   JSON round-trip before hashing, so the hash and the written line derive from
   one rendering; the in-memory ``AuditRecord`` carries the same normalized args
   that land on disk. The regression test pins the mechanism with a
   deterministic copy-sensitive ``str()`` probe (fails on the old code every
   run, no seed required).

6. BL-028, BL-051, BL-053, BL-086, BL-088, BL-091, BL-093, and BL-094 are
   resolved by this wave. BL-027, BL-030..BL-033, BL-035, BL-036, BL-046,
   BL-050, BL-052, BL-060, BL-061, BL-076, BL-087, BL-089, and BL-092 remain
   open; the largest (BL-076, runtime audit anchoring) is unchanged by this
   wave.

## Consequences

Positive:

- Invariant 4 (append-only at the storage layer) now holds with the same strength
  on both backends, verified against a live PostgreSQL 16.13 rather than asserted:
  the suite's store tests pass with ``PRAXIS_TEST_PG_DSN`` set, including new live
  tests for seq uniqueness across two store instances, the duplicate-seq
  ``UniqueViolation``, and the TRUNCATE/DELETE refusals; static schema guards
  assert the same statements in environments without a database.
- The CI gate is reproducible by construction: the same hash-locked set installs
  and passes ``make ci-success`` on fresh 3.12.3 and 3.13.12 environments
  (verified in this wave), and the published SBOM describes the shipped graph.
- Coverage erosion now fails the aggregate gate instead of passing silently.
- The chart's two findable secrets paths (token, DSN) both use Secret references,
  and an unconfigured install is private by default at the network layer.

Negative:

- A chart upgrade with existing values must migrate: an inline ``storeDsn`` fails
  the render (deliberately, with instructions), and clients lose MCP-port access
  until ``networkPolicy.ingressFrom`` names them. Both are fail-closed migrations.
- Existing Postgres databases with duplicate ``seq`` values (possible only if the
  closed race ever fired) will fail the new unique index creation at connect; the
  operator must de-duplicate once. A clean database migrates transparently
  (verified: the index creation ran against the populated test database).
- Renovate lockfile updates to ``requirements-dev.txt`` add review traffic; that
  is the point.

Neutral:

- The fuzz workflow's interpreter follows the test matrix (3.13) rather than the
  newest CPython; the SBOM job stays on 3.14, where it only packages metadata.
- ``coverage`` runs the suite a second time inside ``ci-success`` (about 3 s).

## Alternatives considered and rejected

- A Postgres ``SEQUENCE``/identity column instead of the inline MAX(seq)+1 with a
  unique index. Rejected for parity: the two backends should fail the same way at
  the same boundary, and a sequence would diverge from the SQLite semantics
  (gap-free per-table ordering recoverable from the data alone).
- Exact-pinning the dev extra in ``pyproject.toml`` (``==`` everywhere). Rejected:
  the hash-locked requirements file already gives CI exactness; exact pins in the
  project metadata would force every local environment through lockstep upgrades
  for no additional supply-chain strength.
- Omitting ``store/postgres.py`` or ``__main__.py`` from coverage to raise the
  percentage. Rejected: source-based measurement with the honest denominator is
  the point of the gate; the floor (90) absorbs the optional-backend skips.
- Defaulting ``networkPolicy.ingressFrom`` to an allow-all selector for
  compatibility. Rejected: "never weaken a default"; the chart is not runnable in
  v0 anyway (BL-093), so the fail-closed default costs nothing today and is right
  later.

## Revisit triggers

- HTTP serving lands (BL-012): re-test the chart end to end, revisit BL-093's
  warning, and revisit the approval-registry and audit-writer single-process
  assumptions named in ADR-0016.
- A second writer process or replica becomes supported: the seq unique index
  turns races into visible errors, but a retry strategy (or advisory locking,
  BL-029's PG note) becomes necessary rather than optional.
- pip, uv, or Renovate change hash-locking semantics, or a dependency stops
  publishing wheels for a matrix interpreter (the universal lock assumes wheel
  coverage).
- A multi-role Postgres deployment arrives: revisit BL-028's RLS floor and
  per-role REVOKEs, which this wave assessed as out of scope for single-role v0.
