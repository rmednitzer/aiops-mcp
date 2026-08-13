## Description

<!-- What does this PR change, and why? -->

## Type of change

- [ ] Bug fix
- [ ] New capability (tool, skill, collector, store backend)
- [ ] Refactor
- [ ] Documentation, ADR, or STPA item
- [ ] CI, packaging, or tooling

## Governance traceability

<!--
Governance is load-bearing here. Link what applies; write "none" where it does
not. Decisions are ADRs, work items are BL-NNN in docs/backlog.md, and safety
or security requirements come from docs/stpa/.
-->

- Backlog item(s):
- ADR(s):
- STPA Unsafe Control Action / security constraint:

## The nine invariants

- [ ] This change does not weaken any of the nine invariants
- [ ] If it changes one, the change is recorded in a new ADR that supersedes the old decision, and the proving test was updated alongside it

<!--
For reference:
 1. Single audited execution path; no tool bypasses it.
 2. Tiered authority T0-T3 (classify rounds up; sudo/doas/pkexec at least T2;
    modes gate tiers; deny is global).
 3. Audit stores output_sha256 and output_len, never bodies; append-only hash
    chain; params redacted; logger never raises.
 4. State facts are bitemporal and append-only; supersede, never delete.
 5. host_type gates actuation; never SSH a Talos host.
 6. DRY_RUN, then human approval, then execute; T3 needs a typed token and one
    target at a time.
 7. stdio by default; HTTP needs token, non-loopback opt-in, and the SSRF
    egress filter; no token passthrough.
 8. Lethal-trifecta containment; treat all collected data as untrusted.
 9. Least privilege; scoped revocable credentials; kill switch.
-->

## Checklist

- [ ] `make check` is green (ruff, mypy strict, pytest)
- [ ] `make schema` and `make eval` run where relevant
- [ ] Behavior changes carry a test; one invariant change means at least one test change
- [ ] `CHANGELOG.md` and the affected `docs/` are updated
- [ ] A changed decision is a new ADR, not an edit to an existing one
- [ ] No default was weakened to make something pass
- [ ] Prose follows the documentation style (no em dashes, no double hyphens as punctuation; SI units, ISO 8601 dates, 24h UTC)

## Blast radius and rollback

<!--
Which components and which contracts does this touch, and how is it rolled
back? Required for anything touching the execution path, the audit record, the
store, or the transport.
-->
