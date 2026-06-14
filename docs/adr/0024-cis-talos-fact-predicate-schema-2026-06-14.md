# ADR-0024: CIS-Talos drift baseline: the fact-predicate schema (2026-06-14)

## Status

Proposed

## Date

2026-06-14

## Authors

praxis maintainers (prerequisite decision for BL-099, requested before implementation)

## Context

BL-099 wants the CIS Kubernetes Benchmark, with the Talos-defaults mapping,
transcribed into `KNOWN_GOOD` facts so the drift engine can report a cluster's
configuration drift from a hardened baseline. The backlog item is explicit that a
fact-predicate schema decision must land first: how a CIS control is named as a
`(subject, predicate, fact_type)` key, what its `value` looks like, how severity is
assigned, and how false positives (controls Talos satisfies structurally, or that an
environment legitimately waives) are suppressed. This ADR records that decision so
the baseline data and the observing collector agree on one schema. It does not
implement the baseline; it is the prerequisite the item names.

The constraints come from the existing model, which this ADR deliberately does not
change:

- `Fact` is keyed by `(subject, predicate, fact_type)`; `value` is a dict
  (`src/praxis/model/facts.py`, ADR-0003).
- `drift.engine.diff(observed, desired, *, flag_unexpected, severity_for)` indexes
  both sides by `(subject, predicate)` and, per desired key, emits `MISSING` when
  observed is absent and `CHANGED` when `have.value != want.value`. Severity is a
  pluggable `severity_for(predicate, kind)` hook (`src/praxis/drift/engine.py`).
- `known_good_from_store` already returns `list_active(fact_type=KNOWN_GOOD)`
  (`src/praxis/drift/sources.py`).
- Drift is read-only (T0); convergence stays human-gated (SEC-6). A drift-data
  source adds no actuation and so no new UCA (the same status as the tofu and
  ansible sources).

The crux is that `diff` compares whole `value` dicts for equality. Any descriptive
metadata placed in `value` that the collector cannot reproduce byte-for-byte would
manufacture a spurious `CHANGED` finding on every control. The schema therefore has
to separate the comparable setting from its documentation.

## Decision

1. Reuse `fact_type=KNOWN_GOOD` for the CIS desired baseline and `OBSERVED` for the
   collected state. No new fact type: a CIS baseline is exactly an operator-blessed
   known-good snapshot, which is what `KNOWN_GOOD` already means, and reuse keeps the
   generic `diff` working unchanged.

2. Subject is the real fleet asset, not a synthetic CIS namespace:
   - `host:<name>` for node-scoped controls (kubelet flags, sysctls, file
     permissions, and the control-plane static-pod component flags, which on Talos
     run per control-plane node). This matches the existing osquery/AIDE collectors,
     so CIS drift attaches to the same vertex as the rest of a host's facts.
   - `cluster:<name>` for genuine cluster singletons (for example an admission
     configuration). Keeping the subject the asset means a finding points at what an
     operator must act on.

3. Predicate is `cis:<benchmark>:<control_id>`, for example
   `cis:k8s-1.9:1.2.1` or `cis:talos:kubelet-anonymous-auth`. The `<benchmark>`
   segment versions the source (a CIS Kubernetes Benchmark revision, or `talos` for
   a Talos-specific control), so a benchmark bump is a new predicate namespace rather
   than a silent redefinition. The control id is the stable key, unique per subject,
   and machine-joinable back to the published benchmark. The `cis:` prefix is the
   severity hook's signal (decision 5).

4. `value` carries only the normalized, collector-reproducible setting; all
   documentation lives in `reason`:
   - `value` is `{"value": <normalized>}` (or a small dict of normalized fields for a
     multi-part control). Normalization is defined once and applied identically on
     both sides: cast scalars to strings, lowercase booleans (`"true"`/`"false"`),
     sort list-valued settings, and trim whitespace, so a compliant node compares
     equal and only a real difference yields `CHANGED`.
   - `reason` holds a JSON string with the CIS id, title, level (1 or 2),
     scored/not-scored, rationale, and remediation. `diff` ignores `reason`, so this
     metadata enriches audit and triage without ever causing a false `CHANGED`. A
     finding still carries the asset (subject), the control (predicate), and the
     observed/desired values; the triage step reads the baseline fact's `reason` for
     the human context.
   - A control the collector cannot evaluate is simply an absent `OBSERVED` fact, so
     `diff` reports it `MISSING`: an unevaluable hardening control is surfaced, not
     silently passed (the same posture as the ansible UNREACHABLE escalation).

5. Severity uses the existing `severity_for` hook, not an engine change. A
   `cis_severity(predicate, kind)` function treats any `cis:`-prefixed predicate as
   security-relevant and ranks its drift `CRITICAL`, consistent with the existing
   `_SECURITY_PREDICATES` posture (`src/praxis/drift/engine.py`); a later refinement may read
   the CIS level from a side table to rank Level 2 controls `WARNING`. Because `diff`
   already accepts `severity_for`, the CIS drift entry point passes `cis_severity`
   and the engine itself is untouched.

6. False positives are an explicit, documented, reviewable suppression set, never a
   blanket ignore:
   - `CIS_SUPPRESSED`: a set of `<benchmark>:<control_id>` keys the CIS drift entry
     point filters out (or downgrades to `INFO` with a `suppressed` reason), each
     paired with a one-line rationale, so a suppression is auditable and can be
     re-reviewed when the benchmark or the platform changes.
   - `TALOS_SATISFIED`: controls Talos enforces structurally and immutably, where
     there is nothing a node could drift to. These are documented as
     platform-guaranteed and excluded from the per-node diff rather than checked,
     so the baseline does not spend a check on what cannot change. Controls Talos
     sets by a default that an operator could still change are kept in the baseline
     with the Talos-hardened value as the desired state.

7. The observing collector (talosctl/API reads, sysctl reads) is read-only and is
   implementation, not part of this decision; it must emit `OBSERVED` facts under the
   same `(subject, predicate, value)` schema fixed here.

## Consequences

Positive: the baseline drops into the existing engine with no change to `Fact`,
`diff`, or the store; CIS findings attach to the real host/cluster vertices and join
the same bitemporal history as other facts; the `value`/`reason` split makes the
equality diff reliable while keeping full CIS documentation in the trail; severity
and suppression are explicit and reviewable.

Negative: keying on the control id means a benchmark revision that renumbers controls
needs a new `<benchmark>` namespace and a baseline migration; the `value`/`reason`
split puts the burden of identical normalization on both the baseline and the
collector, so a normalization mismatch would show as spurious `CHANGED` until
reconciled (the first collector bring-up must be validated against a known-compliant
node).

Neutral: this is a schema and policy decision; the baseline data, the suppression
contents, the Talos-satisfied set, and the collector are the implementing work that
BL-099 still tracks. The decision is recorded Proposed for ratification before that
work begins, per the backlog item.

## Alternatives considered and rejected

- A new `fact_type="cis"`. Rejected: a CIS baseline is an operator-blessed desired
  snapshot, exactly `KNOWN_GOOD`; a parallel type would fork the generic diff for no
  gain.
- A synthetic subject namespace (`cis:kube-apiserver` as the subject). Rejected: it
  detaches the finding from the asset an operator must remediate and from that host's
  other facts; the control belongs in the predicate, the asset in the subject.
- Carry the full CIS metadata in `value`. Rejected: `diff` compares whole `value`
  dicts, so unreproducible metadata would emit a `CHANGED` on every control; metadata
  belongs in `reason`, which the diff ignores.
- A blanket "ignore Talos-irrelevant controls" flag. Rejected: suppression must be a
  named set with per-control rationale so it is auditable and re-reviewable, not a
  silent mask over real drift.
- Bake CIS severity into the engine. Rejected: the engine already exposes
  `severity_for`; a CIS-specific function keeps the engine generic.

## Revisit triggers

- A new CIS Kubernetes Benchmark revision (handled by a new `<benchmark>` predicate
  namespace plus a baseline migration).
- Talos changes a default or a structural guarantee the `TALOS_SATISFIED` set
  relied on.
- The collector bring-up reveals a normalization mismatch that the `value` schema or
  the normalization rules must absorb.
- A need to rank CIS Level 2 controls below Level 1, which would add the level side
  table referenced in decision 5.

## Ratification note (2026-06-14)

Ratified and implemented by ADR-0028 (BL-099). This decision is the CIS schema of
record; the Decision above is unchanged. ADR-0028 records the implementing work: the
baseline data, the suppression and Talos-satisfied policy, the read-only observing
collector, and the CIS-aware severity wired into the existing drift scan.
