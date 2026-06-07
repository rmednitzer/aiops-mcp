# ADR-0002: Self-contained store strategy

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-07      |
| Authors | Roman Mednitzer |

## Context

`praxis` is the fleet's source of truth. It must persist a typed graph of
bitemporal facts (ADR-0003) and an append-only audit log (ADR-0008), be operable
on a single laptop with no external services, and scale to a production
deployment. The self-contained rule (ADR-0001) forbids a runtime dependency on
any external converged store.

Two competing pressures: the laptop case wants zero operational surface (one
file, no daemon), the production case wants a real engine with a graph extension
and vector search. A single hardcoded backend cannot serve both without either
over-provisioning the laptop or under-serving production.

## Decision

1. Define a narrow `StoreProtocol` (the L1 surface) that every backend honours:
   `put_fact`, `supersede_fact`, `get_active`, `history`, edges, and a
   capability probe. Service code depends only on the Protocol, never on a
   concrete backend.
2. Use an extension ladder. Optional capabilities (vector similarity, graph
   traversal, batch) are separate Protocols a backend advertises and implements
   only if it can honour them. A backend never fakes an unsupported capability.
3. Ship SQLite as the default backend: a single file, bitemporal fact tables, an
   append-only delete-blocking trigger, the active-fact unique constraint, and
   embeddings via `sqlite-vec` when present (degrading to no vector search when
   absent). No daemon, no network, works offline.
4. Ship a Postgres + Apache AGE + pgvector backend for production behind the same
   Protocol, as an optional extra. It is imported lazily; the package imports and
   type-checks with the driver absent.
5. Bitemporality and append-only are enforced at the storage layer (a trigger or
   equivalent), not only in application code, so a direct write cannot bypass the
   invariant.

## Consequences

Positive: the laptop and production cases share one code path; tests run against
SQLite with no services; the production engine is swappable without touching
service code; the append-only guarantee survives a buggy caller.

Negative: two backends to maintain; the Protocol is the lowest common
denominator, so backend-specific power is reached only through capability
Protocols.

Neutral: `sqlite-vec` and `psycopg` are optional extras, not core dependencies;
their absence degrades features, never breaks import.

## Alternatives considered and rejected

- A single Postgres-only backend. Rejected: forces a daemon onto the
  single-operator laptop case and breaks offline operation.
- An ORM over both engines. Rejected: the bitemporal and append-only invariants
  are expressed most safely in raw SQL with a delete-blocking trigger; an ORM
  obscures the trigger and the active-fact constraint.
- Depending on the estate's existing converged graph store. Rejected by ADR-0001
  (self-contained).

## Revisit triggers

- The fleet outgrows SQLite for the default deployment.
- A third backend is required (for example, an embedded graph engine).
- A capability needed by service code cannot be expressed in the L1 Protocol.
