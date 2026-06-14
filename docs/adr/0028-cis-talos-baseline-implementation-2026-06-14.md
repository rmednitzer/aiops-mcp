# ADR-0028: CIS-Talos drift baseline implementation (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (ratifies ADR-0024; implements BL-099, from ADR-0021)

## Context

ADR-0024 fixed the CIS fact-predicate schema and was recorded Proposed, to be
ratified before BL-099 was implemented (the backlog item required the schema decision
first). The maintainer ratified ADR-0024; this wave adopts it as the schema of record
and implements the baseline, the suppression policy, and the observing collector.

## Decision

1. Ratify ADR-0024 as the schema of record, unchanged: subject `host:<name>` /
   `cluster:<name>`, predicate `cis:<benchmark>:<control_id>`, the comparable-`value`
   versus documentation-`reason` split, CIS-aware severity through the engine's
   `severity_for` hook, and the explicit `TALOS_SATISFIED` / `CIS_SUPPRESSED` sets.

2. Implement the baseline in `src/praxis/drift/cis.py`: a `CisControl` record, one
   `normalize_value` applied identically on both sides (booleans lowercased, scalars
   trimmed, lists/comma-strings sorted), the vetted `CIS_BASELINE` across the kubelet,
   API-server, controller-manager, scheduler, and cluster control families, plus
   `cis_severity`, `cis_baseline_facts`, `cis_drift`, and `seed_cis_baseline`. The
   engine (`diff`, `default_severity`) and the store are untouched.

3. Suppression model: `CIS_SUPPRESSED` is a named waiver of a baseline control (the
   waived control is in the baseline and is dropped from the active set), while
   `TALOS_SATISFIED` documents controls Talos guarantees structurally that are not in
   the checkable baseline at all. Both are excluded at materialization, so neither the
   CIS diff nor the generic `drift_scan` alerts on them. Excluding at materialization
   (rather than filtering findings afterwards) also keeps the generic scan's
   `flag_unexpected` path from re-surfacing a waived control as `UNEXPECTED`.

4. The observing collector (`src/praxis/collectors/cis.py`) is a pure parser of
   captured CIS evidence (an out-of-process T0 read) into `OBSERVED` facts under the
   same schema. It emits only controls in the active baseline, so observed is a subset
   of desired and the generic scan never manufactures a CIS `UNEXPECTED`; a baselined
   control with no evidence still surfaces as `MISSING`.

5. Wire CIS through the existing audited surface with no new tool and no new UCA: the
   collector plugs into `ingest_observation` (already audited, marked untrusted, and
   UCA-covered, BL-085), and `drift_scan` passes `cis_severity` (a tool-level severity
   choice, the engine stays generic per ADR-0024 decision 5) so a seeded baseline plus
   ingested evidence reports CIS drift at `CRITICAL` through the existing read-only
   tool. Seeding the baseline is a library helper (`seed_cis_baseline`), an operator
   blessing like the other known-good seeds (BL-016), not an actuator.

6. Baseline scope: an initial, vetted, must-equal-Y control set, benchmark-namespaced
   so a CIS Kubernetes Benchmark numeric revision (`k8s-1.x`) or further controls
   extend it additively. Accuracy was favoured over breadth: the `talos` namespace
   uses stable, descriptive control ids with the CIS Kubernetes reference carried in
   `reason`, so an error-prone numeric id is never committed as a key (ADR-0024
   decision 3 blesses both id forms).

## Consequences

Positive: CIS drift drops into the existing engine, store, and tools with no engine
change; findings attach to the real host/cluster vertices and join the same bitemporal
history as other facts; the `value`/`reason` split keeps the equality diff reliable;
severity and suppression are explicit and reviewable; there is no new actuation or UCA
surface. The whole pipeline is unit-tested here without a live cluster, because the
collector is a pure parser and the diff is pure.

Negative: the baseline content is an initial set, not the full benchmark; growing it
(and adding a `k8s-1.x` numeric namespace) is tracked follow-up. A normalization
mismatch between real evidence and the baseline would show as a spurious `CHANGED`
until reconciled, so the first live collector bring-up must be validated against a
known-compliant node (the risk ADR-0024 named).

Neutral: `drift_scan` now ranks any `cis:` predicate `CRITICAL`; non-CIS predicates
are unchanged because `cis_severity` delegates to `default_severity`. The collector
couples to the active baseline keys by design (to keep observed a subset of desired),
so evidence for an unknown or waived control is dropped rather than recorded.

## Alternatives considered and rejected

- A dedicated `cis_drift_scan` MCP tool. Rejected: it would duplicate `drift_scan` and
  add tool and STPA surface; making `drift_scan` CIS-aware via severity reuses the
  audited read path. `cis_drift` stays a library entry point for direct use and tests.
- Transcribing the full CIS Kubernetes Benchmark by numeric id from memory. Rejected
  as error-prone for a security baseline; the `talos` descriptive-id namespace with
  CIS references in `reason` is accurate and extensible.
- Post-diff finding suppression. Rejected: it leaves the generic scan's
  `flag_unexpected` path re-surfacing waived controls as `UNEXPECTED`; excluding at
  materialization is consistent across both the CIS and the generic entry points.
- Seeding the baseline via an MCP tool. Rejected: blessing a desired baseline is an
  operator action with no actuation; a library helper avoids a new state-writing tool
  and the UCA it would carry.

## Revisit triggers

- A new CIS Kubernetes Benchmark revision (add a `k8s-1.x` benchmark namespace and a
  baseline migration).
- The first live collector bring-up (validate normalization against a known-compliant
  node; reconcile any mismatch into the `value` schema).
- The baseline grows enough to warrant splitting the data out of `drift/cis.py`.
- A need to rank CIS Level 2 controls below Level 1 (the level side table ADR-0024
  decision 5 anticipated).
