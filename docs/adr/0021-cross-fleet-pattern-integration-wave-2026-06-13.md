# ADR-0021: Cross-fleet pattern integration wave (2026-06-13)

## Status

Accepted

## Date

2026-06-13

## Authors

praxis maintainers (pattern-integration wave following ADR-0020)

## Context

A survey of proven operational patterns from the broader fleet-tooling domain
(infrastructure provisioning, configuration management, operator runbooks, shell
and SSH actuation, and an agent runtime) was run against praxis to find additions
worth adopting. praxis had already absorbed most generic hardening idioms (finite
or non-negative numeric validation at construction, per-link failure containment in
the routing-chain dispatcher, provider-token redaction shapes, the append-only
hash-chained audit with degrade-to-stderr, process-group subprocess kill, an env
allowlist, chain resume on restart), so the genuinely missing, high-value additions
clustered in four areas. They are integrated here natively, with no import from or
runtime coupling to any external tooling (ADR-0001, ADR-0014): praxis reimplements
the idea, it does not depend on the source.

The wave deliberately implements the four self-contained, well-scoped additions and
records the larger or decision-bearing findings as tracked backlog items rather than
rushing them into a security-sensitive change.

## Decision

1. Machine-checkable compliance catalog (BL-031, closing the open item; advances the
   module-back-citation part of BL-036). The prose compliance map
   (`docs/governance/compliance-map.md`) and the STPA security constraints
   (`docs/stpa/07-security-constraints.md`) are projected into
   `docs/governance/compliance-controls.json`, a pydantic-validated catalog keyed by
   the existing SEC-1..SEC-10 ids plus one governance control (`CTL-001`,
   supply-chain and secure development). The model
   (`src/praxis/governance/catalog.py`) is the single source of truth for a generated
   JSON Schema (`docs/schema/compliance-controls.schema.json`, under the existing
   `make schema` drift guard), mirroring the SKILL.md frontmatter pattern (ADR-0014).
   `src/praxis/governance/validate.py` runs eleven bidirectional cross-reference
   rules: id format; the SEC controls are exactly the STPA constraints; every cited
   module exists and (for a SEC control's `src/praxis` modules) carries the matching
   `SEC-N` back-citation token; every `SEC-N` token in the source tree names a
   catalog control; invariants are in 1..9; every regulatory framework is known and
   every in-scope framework is cited; every listed proving test `path::function`
   exists and an implemented control names at least one (partial/planned exempt); the
   prose map cites no undefined control; and a partial/planned control carries a
   tracking BL id while an implemented one does not. `scripts/validate_compliance.py`
   wires it into `make validate-compliance` and the `ci-success` aggregate, and the
   suite re-runs it (`tests/governance/`) so `make check` catches drift too.

2. Redaction hardening (BL-097). `execution/redaction.py` gains a PyPI upload-token
   shape (anchored on the fixed `AgEIcHlwaS5vcmc` macaroon prefix), runs the npm and
   GitLab token bodies UNBOUNDED from their length floor so a longer-than-minimum
   token collapses whole instead of leaving a tail in the audit log, and adds a
   context-gated compact MySQL password redaction (`mysql -p<secret>`) that fires only
   when a MySQL-family client is present in the same string, so `-p`-as-port for
   unrelated tools (`ssh -p22`, `nmap -p1-1000`) is not over-scrubbed. Strengthens
   SEC-9 (invariant 3); no classification change, so `PATTERNS_VERSION` is unchanged.

3. Talos partition-scoped reset (BL-098). `actuation/talosctl.py` gains an additive
   `system_labels` structured param mapping to `talosctl reset
   --system-labels-to-wipe` (allowlisted to `EPHEMERAL`/`STATE`, case-normalised).
   Wiping only `EPHEMERAL` preserves the `STATE` partition (node identity and
   secrets), so the node rejoins the cluster rather than needing a full
   re-provision. It is mutually exclusive with the disk-scoped `--wipe-mode`
   (supplying both is refused: fail closed on an ambiguous reset scope). The
   documented `wipe_mode` default (`system-disk`, BL-025) is left unchanged: this is
   a strictly additive capability. The partition reset keeps its T3 authority because
   the `reset` verb already floors at T3 in the classifier (a test pins this), so no
   `patterns.py` change is needed (SEC-5, invariant 6).

4. Content-hash compare-and-set for supersede (BL-027, closing the open item). A new
   `VersionedStore` Protocol (`store/base.py`) sits beside `VectorStore` on the
   extension ladder, advertised via `Capability.COMPARE_AND_SET`. `Fact.content_hash`
   is a stable SHA-256 over the asserted content (key, value, write provenance), not
   the store-assigned lifecycle stamps, so the version a caller reads off
   `get_active` survives the store round-trip and is identical on both backends.
   `put_fact_if(fact, expected_version=...)` makes the read-compare-write atomic and
   version-gated: SQLite takes the write lock up front with `BEGIN IMMEDIATE` (plus a
   `busy_timeout` so a second instance serialises rather than failing fast), Postgres
   locks the active row with `SELECT ... FOR UPDATE`; a mismatch raises
   `VersionConflict` and writes nothing. This forecloses a lost update where an
   operator approves replacing the fact they read but a different value lands in
   between (SEC-6, invariant 4). A concurrency test proves exactly one of two racing
   writers wins; the rest run in the shared backend-parity suite.

5. The larger or decision-bearing findings are tracked, not rushed (mirrors how
   ADR-0011 recorded a validated backlog rather than implementing all at once):
   a CIS-Talos desired-state baseline as drift data (large; needs a fact-predicate
   schema decision, filed for a dedicated ADR), a multi-sink audit fan-out with
   per-sink failure containment (latent until a second audit sink is wired, e.g. the
   Postgres path), an audit `request_id`/`client_id` correlation field (lower value
   for a stdio-default single-operator server), and a client-side-only
   (`--server=false`) talosctl pre-flight health probe (a behavioural change to a
   HARD safety precondition, raised for an operator decision rather than changed
   unilaterally). See `docs/backlog.md`.

## Consequences

Positive:

- The compliance map stops being prose a reviewer must trust and becomes a CI gate:
  a stale module path, a control that no longer back-cites its constraint, an
  uncovered framework, a missing proving test, or a map row referencing an undefined
  control all break the build. The compliance map's own stated principle ("a control
  without a test is a visible gap") is now machine-enforced.
- The redaction additions close real audit-log leak paths (a long npm token tail, a
  bare PyPI token, the most common MySQL password form) without over-scrubbing.
- Operators gain a STATE-preserving Talos reset (the safer, more common reset) as a
  first-class, audited, T3-gated option, without changing the documented default.
- The store gains a lost-update guard that matches the human-gated convergence
  promise: an approval bound to a read cannot silently apply to a value that changed
  underneath it. The two backends are held to one behaviour by the parity suite.

Negative:

- The catalog is a new artifact to maintain: adding a SEC constraint or moving an
  enforcement file now also means updating the catalog, or CI fails. That coupling is
  the point (it is the drift guard), but it is real maintenance.
- `put_fact_if` adds a third fact-write path beside `put_fact` and `supersede`;
  callers that want lost-update safety must read the version and pass it. The plain
  `put_fact` (last-writer-wins under the unique-index race) is unchanged, so this is
  opt-in, not a default tightening.
- The SQLite `busy_timeout` makes a contended write wait up to 5 s rather than fail
  fast; for the single-operator stdio default there is normally one connection, so no
  contention, but a multi-instance deployment now blocks instead of erroring.

Neutral:

- No change to the execution pipeline, the approval gate, the transport guard, or
  `PATTERNS_VERSION`. The redaction change is additive pattern coverage; the talos
  change is an additive param; the CAS change is an additive Protocol and method.
- The catalog keys on SEC-N rather than inventing a parallel control namespace, so
  the existing STPA traceability stays the single spine and the catalog is a
  projection of it, not a competitor.

## Alternatives considered and rejected

- Model the compliance catalog in YAML. Rejected: praxis has no YAML dependency and
  hand-rolls its only frontmatter parser (BL-057) to avoid the parser attack surface;
  JSON plus a pydantic model is the in-repo idiom (ADR-0014) and needs no new
  dependency.
- Invent a `CTL-NNN` namespace for every control. Rejected: the SEC constraints are
  already the tested, STPA-derived control set; keying the catalog on them keeps one
  spine. A single `CTL-001` is used only for the supply-chain/secure-development
  control that has no single SEC home.
- Change the talosctl reset default to the STATE-preserving scope. Rejected here: the
  `system-disk` default is a documented BL-025 decision, and reversing a destructive
  default is an operator decision that belongs in its own ADR, not a side effect of
  adding an option. The safer scope is now available; the default question is a
  revisit trigger.
- Implement compare-and-set as a new MCP tool. Rejected: it is a store primitive, not
  a new control action; it routes through no new tool surface and so needs no new UCA
  row. The fact-writing tools that already have UCA coverage can adopt it internally.
- Add an audit `request_id`/`client_id` field in this wave. Rejected for now: the
  value is correlation across concurrent clients, which the stdio-default
  single-operator server does not have; filed rather than built.

## Revisit triggers

- A second audit sink is wired (the Postgres audit path, a syslog target): introduce
  the multi-sink fan-out with per-sink failure containment, `BaseException` still
  propagating, before the second sink can mask the first.
- The drift engine needs a machine-readable CIS-Talos desired-state baseline: open a
  dedicated ADR for the fact-predicate schema, then transcribe the baseline as
  `KNOWN_GOOD` data.
- An operator decides the default Talos reset scope should preserve `STATE`: supersede
  the BL-025 default in a new ADR and flip `_DEFAULT_WIPE_MODE` with its test.
- The HTTP transport (BL-012) lands and the server serves multiple clients: add the
  audit `request_id`/`client_id` correlation field (additive to the audit record).
- A new SEC constraint or a moved enforcement file: update
  `docs/governance/compliance-controls.json` in the same change (the validator will
  flag the omission).
