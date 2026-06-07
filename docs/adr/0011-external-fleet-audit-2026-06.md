# ADR-0011: External fleet-repository audit (2026-06) and validated hardening backlog

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-07      |
| Authors | Roman Mednitzer |

## Context

`praxis` is self-contained (ADR-0001): zero runtime dependency on, and no imports
from, any other repository. It does not follow that praxis cannot learn from the
sibling repositories that share its operator, its EU-sovereign posture, and its
security concerns. Nine sibling repositories were audited for transferable
patterns, with auditing, security, and capability prioritised:

- `relay-shell` (shell/SSH MCP server; the execution trust boundary),
- `isms-mcp` (read-only MCP overlay; server surface, path boundary, classification),
- `agents` (harness and memory backends; the multi-audit ADR cadence),
- `core-graph` (bitemporal four-timestamp model; evidence integrity; engine-level RLS),
- `ai-stack` (governed Helm chart; supply-chain parity; governance-as-code),
- `infra` and `runbooks` (Talos no-SSH paradigm; destructive-op guards),
- `automation` and `isms` (compliance-controls mapping; append-only evidence).

The audit confirmed that several controls are already correct in praxis and must
not be re-done (the RFC 6962 Merkle construction in `audit/merkle.py`, the
active-fact partial unique index in `store/sqlite.py`, single-target T3 in
`execution/runner.py`, the DRY_RUN preview in `actuation/base.py`, the
fail-closed transport guard in `config.py`, and `readOnlyRootFilesystem: true`,
which is stricter than the ai-stack helper default and is kept). Two agent
claims about praxis were checked and found incorrect: praxis already has a
forward-linked, restart-resuming audit hash chain, and its bitemporal
supersession does not suffer the overlap-constraint trap.

The remaining findings are recorded here as a backlog wave. Per the standalone
constraint every item is a pattern to re-implement, never a dependency to add.

## Decision

1. Adopt periodic external-fleet audit as a recurring practice, recorded as an
   ADR per wave (the cadence observed in the `agents` repository, ADR 0007 to
   0023, where each audit generalises an invariant class to a new boundary). This
   ADR is the first such wave.
2. Each finding is validated against a trusted source before acceptance, not only
   against the sibling repository that surfaced it. The validation verdict is
   recorded in the table below. Validation materially changed four findings:
   BL-019 was downgraded (no current injection bypass exists), BL-022 and BL-023
   were reframed (Talos already verifies the snapshot hash; a pre-upgrade health
   check is best practice, not a Talos requirement), and BL-024 was strengthened
   (the first OWASP defence is to not let the caller supply the path at all, so a
   runbook registry by id is preferred over a path allow-list).
3. The validated findings are accepted as backlog items BL-017 to BL-036, each
   mapped to a security constraint (`docs/stpa/07-security-constraints.md`) or an
   invariant, and each citing this ADR as its source. Accepting an item schedules
   the work; it does not weaken any current default.

### Validated findings

Trusted sources: OpenSSH `ssh_config(5)` (man.openbsd.org); the Python
`subprocess` documentation; the PostgreSQL 17 documentation (`CREATE TRIGGER`,
`ddl-rowsecurity`, `ddl-priv`, advisory locks); the Talos / `talosctl`
documentation; the OWASP OS Command Injection, Path Traversal, and Logging
guidance (the trusted references named in `relay-shell` and the praxis security
posture); IEEE 754 for floating-point comparison semantics.

| BL | Finding | Constraint | Source | Trusted-source verdict |
|----|---------|-----------|--------|------------------------|
| 017 | Read and ingest tools (`query_facts`, `fact_history`, `ingest_observation`, `drift_scan`) return without an audit record; only `run_action` flows through `run()`. | SEC-2, SEC-9, INV 1 | relay-shell | OWASP Logging: log access to sensitive data and access-control failures. Confirmed. |
| 018 | Trifecta denials raise `TrifectaViolation` (in `context.py` and `tools/actuate.py`) with no audit record, unlike the runner `denied()` path. | SEC-2, SEC-4 | agents (BL-202) | OWASP Logging: authorization failures must always be logged. Confirmed. |
| 019 | The classify and deny probe sees only the command string, not the tool name (and would not see stdin or env if those were ever passed through). | SEC-1, SEC-3 | relay-shell | OWASP Command Injection: array-argument execution (no shell) is the primary defence and praxis already does it; the full argv is already classified. Downgraded to an enhancement (tool-scoped deny rules) plus a forward note. |
| 020 | The SSH adapter emits a bare `ssh target action` with no host-key policy, risking MITM and interactive hangs. | SEC-5, SEC-8 | relay-shell | OpenSSH `ssh_config(5)`: `StrictHostKeyChecking accept-new` adds new keys but refuses changed keys; `BatchMode=yes` disables prompts and fails fast. Confirmed. |
| 021 | `run_subprocess` has no `start_new_session` and no `killpg` on timeout, orphaning descendants (acute for ansible and tofu partial state). | SEC-6, SEC-8 | relay-shell | Python `subprocess`: `run()` timeout kills the direct child only; `start_new_session=True` calls `setsid()`, enabling `os.killpg`. Confirmed. |
| 022 | The talosctl etcd-restore path must preserve snapshot integrity verification. | SEC-6, SEC-4 | runbooks | Talos: `bootstrap --recover-from` hash-verifies the snapshot by default (skippable only with `--recover-skip-hash-check`). Reframed: never pass the skip flag; an optional praxis-side sidecar verify is defence in depth. |
| 023 | A pre-flight cluster health check before a talosctl upgrade. | SEC-6 | runbooks | Talos: not mandated by the upgrade API; it is SRE best practice. Reframed as a recommended HARD precondition, not a requirement. |
| 024 | The runbook adapter runs `bash <caller-supplied-path>` with no path boundary. | SEC-4 | isms-mcp | OWASP Path Traversal: prefer not letting the caller supply the path (use an index of known-good items); otherwise normalise and constrain within a base directory. Strengthened: prefer a runbook registry keyed by id over a path allow-list. |
| 025 | The talosctl reset scope should not inherit the most destructive default. | SEC-6, INV 9 | runbooks | Talos: `talosctl reset --wipe-mode` defaults to `ALL` (wipes system and user disks). Confirmed: require an explicit scope and treat `ALL` as a T3-confirmed choice. |
| 026 | Numeric fields parsed from collected host data are not checked for NaN or infinity before use. | SEC-10, SEC-4 | agents, isms-mcp | IEEE 754: NaN comparisons are always false, so a NaN can silently disable a `<= 0` or ordering check. Confirmed: parse with a finite-or-default helper at every collector site. |
| 027 | The store exposes only `StoreProtocol` and `VectorStore`; no additive extension ladder and no content-hash compare-and-set to harden the one-active-fact supersede. | SEC-10 | agents | Optimistic concurrency control is standard; the additive-stability rule keeps it non-breaking. Accepted as additive. |
| 028 | The Postgres backend enforces append-only by trigger only. | SEC-10 | core-graph | PostgreSQL 17: `TRUNCATE` is not subject to row security and is a separately revocable privilege; a `TRUNCATE` trigger is statement-level; owners and superusers bypass RLS unless `FORCE`d; `RESTRICTIVE` policies combine with `AND`. Confirmed: add `REVOKE` plus a `BEFORE TRUNCATE` trigger; an optional `RESTRICTIVE` RLS classification floor raises the bar against non-superuser paths. |
| 029 | The audit hash chain is not write-serialised under concurrent writers. | SEC-2, SEC-9 | core-graph | PostgreSQL `pg_advisory_xact_lock` serialises chain appends. Confirmed. Low now (stdio is serial), load-bearing once the HTTP or Postgres audit path is concurrent. |
| 030 | Collected snapshots are not integrity-bound into the Merkle checkpoint (the chain covers what is written, not what was read from the host). | SEC-9, SEC-10 | isms | Chain-of-custody practice; consistent with the RFC 6962 checkpoint already in `audit/evidence.py`. Accepted: stamp a `raw_snapshot_hash`. |
| 031 | `compliance-map.md` is prose only, with no machine check that each control maps to an enforcing file and a test, and each declared framework has at least one article-level citation. | governance | automation, isms | GRC-as-code practice (the automation bidirectional validator and the isms validator suite). Accepted. |
| 032 | There are no chart-rendering assertions; a regression flipping `automountServiceAccountToken` or dropping `readOnlyRootFilesystem` passes `make check` and fails only at deploy. | SEC-7, INV 9 | ai-stack | helm-unittest is the standard chart-assertion tool. Accepted. |
| 033 | The airgap `zarf.yaml` carries a placeholder digest, there is no SBOM, and no values-to-SBOM-to-zarf parity check, yet the compliance map cites an SBOM as the CRA enforcement. | supply chain | ai-stack | CycloneDX is the SBOM standard; CRA Annex I expects supply-chain traceability; a placeholder digest fails airgap pull. Accepted. |
| 034 | `parse_ansible_check` maps every changed task to WARNING, missing FAILED (ERROR), unreachable (CRITICAL), and ok (known-good). | SEC-3, SEC-6 | automation | Conservative round-up (SEC-3) and trustworthy DRY_RUN before approval (SEC-6) require severity fidelity. Accepted. |
| 035 | The audit and evidence chain has no documented retention policy. | governance | automation | NIS2 Art. 23 and ISO/IEC 27001 A.8.15 expect defined log retention. Accepted: documented tiers bound in config. |
| 036 | Governance hygiene: back-citation headers in enforcing modules, agent hard-rules (no fabrication, no bypass) in `CLAUDE.md`, a `values-prod.yaml` overlay and version-bump checklist, a namespace default-deny NetworkPolicy, regulatory-deadline data (NISG 2026 in force 2026-10-01), and an empty-string-is-not-loopback test. | governance | automation, isms, ai-stack, core-graph | Practice-level, each traceable to a sibling-repo control. Accepted as a consolidated low-priority item. |

## Consequences

Positive: the hardening backlog is derived from a cross-fleet audit and each item
is validated against an authoritative source, so the work is defensible and
traceable (finding to constraint to source). The audit-as-ADR cadence becomes a
repeatable maintenance method.

Negative: the backlog grows by twenty items; some (BL-027 to BL-030, BL-031 to
BL-033) are medium effort and touch the store, the Postgres backend, and the
deploy and governance surfaces.

Neutral: this ADR records findings and their validation; the enforcement is the
code and tests delivered under each backlog item. No current default changes on
acceptance.

## Alternatives considered and rejected

- Take a runtime dependency on a sibling repository (for example reuse
  relay-shell as the actuator). Rejected: ADR-0001 makes praxis self-contained;
  the value here is the patterns, not the code.
- Accept the sibling-repo recommendations as-is without independent validation.
  Rejected: validation corrected four findings (BL-019, BL-022, BL-023, BL-024),
  which would otherwise have produced wrong or wasted work.
- Record the findings only in the backlog without an ADR. Rejected: the backlog
  format requires a source ADR, and the validation evidence needs a durable home.

## Revisit triggers

- A new sibling repository enters the operator's fleet, or a material change
  lands in an audited one.
- The HTTP transport or a concurrent Postgres audit path is implemented (raises
  BL-029 from low to load-bearing).
- A trusted source contradicts a recorded verdict (correct by an appended audit
  note here and a new finding, never by rewriting an accepted row).
