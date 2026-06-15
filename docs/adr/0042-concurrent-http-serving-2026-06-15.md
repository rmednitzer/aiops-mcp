# ADR-0042: Concurrent HTTP serving over a thread-safe store (2026-06-15)

## Status

Accepted (resolves BL-110; the ADR-0041 concurrency revisit trigger)

## Date

2026-06-15

## Authors

praxis maintainers (BL-110)

## Context

ADR-0041 delivered the multi-client HTTP transport on a single-threaded stdlib
`HTTPServer`. That choice was deliberate and conservative: per-session isolation (the
security goal) was full, but requests were serialised, so a slow actuation on one client
blocked every other client. ADR-0041 recorded the single-threaded server as v1 and named
the follow-up: make the store thread-safe and switch to `ThreadingHTTPServer` (BL-110).

The reason serving was single-threaded was the store, not the transport. The default
`SqliteStore` held one `sqlite3` connection opened with `check_same_thread=True`, so a
handler thread other than the one that built the context could not touch it at all. Every
other shared component was already thread-safe or trivially safe: the audit hash chain
appends under its own lock (BL-029); the evidence scheduler holds its own lock and is
count-based, so out-of-order or concurrent `on_record` calls are correct; the session
manager, and each session's approval registry, are lock-guarded (ADR-0041); per-session
isolation keeps one client's taint latch or pending nonce off another. The remaining gaps
were the store connection and the per-session `BudgetTracker` counters.

## Decision

1. Serialise every store method on a per-instance re-entrant lock. A `synchronized`
   decorator in `store/base.py` wraps each connection-touching method of `SqliteStore`
   and `PostgresStore` with `with self._lock:` (an `RLock`, because a write method calls a
   read method on the same instance, e.g. `put_fact` -> `get_active`, on one thread). The
   SQLite connection is opened `check_same_thread=False` so a handler thread may use it;
   the lock makes the single shared connection safe, the documented-safe single-connection
   pattern. This is per-instance, so the BL-103 two-instance compare-and-set test still
   exercises real cross-connection concurrency (the `FOR UPDATE` and unique-`seq`
   guarantees are unchanged); the lock only serialises one instance shared across threads,
   which is the threaded-server case.

2. Make `BudgetTracker` thread-safe. The check-and-charge in `charge` (and the increment in
   `record_spend`) run under a `threading.Lock`, so two concurrent requests in the SAME
   session cannot read-modify-write the counters and let an extra action slip past the
   ceiling. Per-session budgets are otherwise isolated across sessions already (BL-104).

3. Switch the transport to `ThreadingHTTPServer` with `daemon_threads = True`. Each request
   runs on its own thread, so a slow actuation no longer blocks other clients. No other
   transport change: auth, the session lifecycle, the body cap, and the consent ceiling are
   as ADR-0041 left them.

The taint latch (`SessionTaint`) and the kill switch are intentionally left lock-free.
Both are monotonic and fail-safe: the taint latch only ever transitions unset -> set (a
concurrent double-mark is idempotent, and the worst case is over-tainting, which fails
closed), and the kill switch is a boolean plus an idempotent sentinel write whose
read-or-trip races resolve to "tripped" (also fail-safe). Adding locks there would buy no
correctness.

## Consequences

Positive: BL-110 is resolved. The HTTP server serves clients in parallel (for example
actuating several hosts at once), so one slow call no longer stalls the fleet, while every
bitemporal/append-only invariant holds: store mutations are serialised, the audit chain
and evidence stay single-writer-correct, and per-session isolation is unchanged. The store
lock is a single, auditable mechanism shared by both backends, with no new dependency.

Negative: store operations are serialised process-wide, so two requests never touch the
store literally simultaneously. This is acceptable: store operations are short, and the
work the threaded server actually parallelises (actuation subprocesses, network I/O, the
DRY_RUN to approve to execute round trip) runs outside any store method, so it overlaps
freely. A future workload that is store-read-bound could move to per-thread connections or
a WAL read pool; the `synchronized` seam localises that change.

Neutral: stdio is unchanged and remains the default. The lock is per store instance, so
behaviour is identical for the single-threaded stdio path (the lock is uncontended). The
SQLite `busy_timeout` and `BEGIN IMMEDIATE` cross-connection serialisation (BL-027, BL-068)
remain in force for the multi-instance/multi-process case and are complementary to the new
in-process lock.

## Alternatives considered and rejected

- A thread-safe wrapper/proxy around any `StoreProtocol` backend, locking in one place.
  Rejected: a universal proxy that exposes the vector and compare-and-set methods would
  make a backend that lacks them appear to have them, violating the store contract's stated
  rule that a backend never fakes an unsupported capability (`store/base.py`); per-backend
  locking keeps each backend's true capability surface and `isinstance` checks honest.
- Per-thread store connections via `threading.local` (true read concurrency, no lock).
  Rejected for v1: a `:memory:` database is per-connection, so each thread would get a
  separate empty database, breaking the in-memory default used widely in tests and by the
  ephemeral server; connection lifecycle across the thread pool adds complexity. The single
  connection plus lock is correct for both `:memory:` and file stores. Per-thread or pooled
  connections remain the escalation path if read throughput demands it.
- A non-reentrant `Lock` on the store. Rejected: `put_fact` calls `get_active` on the same
  instance, which would self-deadlock; `RLock` re-enters on the owning thread.
- Holding the audit lock across the evidence `on_record` hook to serialise checkpoints.
  Rejected as unnecessary: the evidence scheduler already holds its own lock and counts
  records, so concurrent or out-of-order hook calls are already correct.

## Revisit triggers

- A store-read-bound workload wants real read parallelism: move to per-thread connections
  or a WAL reader pool behind the `synchronized` seam (SQLite), or a connection pool
  (Postgres).
- A deployment wants bounded concurrency or backpressure: cap the worker threads (a pool)
  rather than `ThreadingHTTPServer`'s unbounded thread-per-request.
- Per-distinct-client tokens land (the ADR-0006 multi-operator revisit): concurrent
  distinct operators make the per-session budget and consent ceiling load-bearing across
  real principals, not just one operator's sessions.
