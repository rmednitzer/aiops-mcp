# ADR-0012: Internal deep audit (2026-06) and remediation wave

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-07      |
| Authors | Roman Mednitzer |

## Context

A deep internal audit read every source file, ran the gates, and added a dynamic
adversarial harness that executed the real code against hostile inputs (the
harness lived outside the repo; nothing was modified during the audit). Six
parallel static reviews (execution, store, actuation, MCP surface, audit/skills,
docs/deploy/CI) were cross-checked, and every Critical and High claim was either
reproduced by execution or verified against the exact source.

The audit confirmed the architecture and the SQLite store are sound (append-only
triggers block DELETE, value-mutation, actor-mutation, and a second active row;
the hash chain detects edit, reorder, and head-truncation; the Merkle tree is RFC
6962 correct). It also found that several load-bearing security properties do not
hold as claimed. The most serious, all reproduced:

- The tamper-evidence layer is forgeable and not fail-closed: a checkpoint with
  `tree_size=0` (plus a forgeable `LocalStamper` token over `sha256(b"")`)
  verifies as `ok=True` on a non-empty log, and malformed evidence raises instead
  of returning a negative result.
- The production Postgres append-only trigger omits the identity columns the
  SQLite trigger guards, so `fact_type` or `predicate` is mutable on an active
  row, and both backends allow a `t_invalid` only mutation that supersedes a fact
  without an actor or reason.
- Tier and deny classification holes: `chmod -R 777 /` classifies T0 and is not
  denied, and writes under `/etc/` via `cp`/`tee`/`ln`/`truncate` classify T0.
- The SSRF egress filter has numeric and trailing-dot bypasses and treats every
  DNS name as allowed, and its entry point has no callers.
- Redaction misses space-separated credential flags (`--password VALUE`) and URL
  or DSN embedded credentials, and the stdio server returns exception text to the
  client without redaction.
- The consent registry specified in ADR-0006 Decision 4 and presented as a
  control in `SECURITY.md` was never built (zero references in code).

## Decision

1. Adopt the internal deep audit (static fan-out plus dynamic adversarial harness
   plus per-claim verification) as a recurring practice alongside the external
   audit cadence (ADR-0011). This ADR is the first internal wave.
2. Accept the findings as backlog items BL-037 to BL-061, each mapped to a
   security constraint or invariant and citing this ADR.
3. Remediate the reproduced P0 set and the reproduced P1 set in the change that
   accompanies this ADR (BL-037 to BL-045 resolved); the remainder stay open and
   tracked. Confirmed-correct controls are not reopened.
4. Correct the documentation that over-stated delivered guarantees. ADR-0006 is
   immutable, so its consent gap is recorded as an appended audit note there, not
   a rewrite.

### Findings

Verification: R = reproduced by executing the code, V = verified against the
exact source, S = static review (credible, not independently executed).

| BL | Finding | Constraint | Sev | Verify | Status |
|----|---------|-----------|-----|--------|--------|
| 037 | `verify_evidence` accepts a `tree_size=0` checkpoint on a non-empty log and raises on malformed evidence (not fail-closed); `LocalStamper` tokens are forgeable | SEC-9, INV 3 | Critical | R | resolved |
| 038 | Postgres append-only trigger omits `predicate`/`fact_type`/`fact_id`/`reason` (and edge identity columns); docstring claims exact SQLite parity | SEC-10, INV 4 | Critical | V | resolved |
| 039 | Both backends allow a `t_invalid` or `superseded_actor` only mutation on an active row, superseding without actor or reason | SEC-10, INV 4 | High | V | resolved |
| 040 | Deny and tier holes: `chmod -R 777 /` is T0 and undenied; `/etc/` writes via `cp`/`tee`/`ln`/`truncate` are T0 | SEC-1, SEC-3, INV 2 | High | R | resolved |
| 041 | Redaction misses `--password VALUE` style flags and URL/DSN credentials; the stdio server error path does not redact | SEC-9, INV 3 | High | R | resolved |
| 042 | SSRF filter bypasses (decimal/hex/octal/trailing-dot IP) and allows all DNS names; `assert_egress_allowed` fail-open on non-IP host | SEC-7, INV 7 | High | R | resolved |
| 043 | OpenTofu DRY_RUN is `plan -refresh-only` but apply is `apply -auto-approve`: preview scope does not match execute scope | SEC-6, INV 6 | High | V | resolved |
| 044 | `_bounded_error` can raise (broken `__str__`), so `run()` can raise with no audit record | SEC-2, INV 1 | Med | V | resolved |
| 045 | Docs over-state delivered controls: consent registry (ADR-0006/`SECURITY.md`), invariant 1 universality, STPA `_ssrf.py` path and read-tool audit claim | governance | High | V | resolved |
| 046 | SSRF: resolve hostnames and check every resolved IP (rebinding-aware) and wire the filter into the egress path | SEC-7 | High | R | open |
| 047 | talosctl T3 single-target is checked on `host.name`, not the actual `host.nodes` list, so a T3 reset can wipe multiple nodes | SEC-6 | High | V | open |
| 048 | talosctl `action.split()` appends attacker-influenced flags (`--insecure`, `--talosconfig`); use a verb allowlist | SEC-8 | Med | V | open |
| 049 | `CredentialBroker` is never wired into the actuation path; scoped-credential enforcement is latent | INV 9 | High | V | open |
| 050 | Audit hash chain tail-truncation is undetectable; needs an anchored high-water-mark | SEC-9 | Med | R | open |
| 051 | Helm NetworkPolicy ingress has no `from:` selector; any pod can reach the MCP port | SEC-7 | High | V | open |
| 052 | `ci-success` gates only `check`; CodeQL/fuzz/sbom/dependency-review rely on out-of-band branch protection | governance | High | V | open |
| 053 | No coverage tooling or gate (`pytest-cov`, `cov-fail-under`) | governance | Med | V | open |
| 054 | `_cosine` returns NaN on NaN/Inf input; `seq` is not unique and the `MAX(seq)+1` read races | SEC-10 | Med | R/S | open |
| 055 | Audit degrade path reopens the file after `_degrade`, overriding the stderr sink and leaking the handle | SEC-8 | Med | S | open |
| 056 | stdio server: unbounded line read (DoS); JSON-RPC notification and batch edge cases | SEC-7 | Med | R/S | open |
| 057 | Manifest parser: `---extra` accepted as fence, no size cap, indented-key injection, duplicate-key last-wins | INV 8 | Med | R | open |
| 058 | Collectors: AIDE empty output reads as clean (false negative); no size caps; non-finite numeric parse (with BL-026) | INV 8 | Med | S | open |
| 059 | Drift: `UNEXPECTED` security-predicate findings are not escalated; multi-host Ansible output makes one invalid subject | SEC-6 | Med | S | open |
| 060 | Deploy and config: Helm health probes, systemd drop-in duplication, unpinned `cyclonedx-bom`, whitespace `HTTP_HOST`, compliance-map path citations | governance | Med | S | open |
| 061 | Test and fuzz gaps: Postgres parity suite, evidence tamper matrix, host_type refusal per adapter, SSRF bypass tests, fuzz of manifest/merkle/evidence | governance | Med | V | open |

BL-017 (read and ingest tools not audited) and BL-018 (trifecta denials not
audited) were already open and are confirmed by this audit; they are not
duplicated here.

## Consequences

Positive: the highest-severity, reproduced security gaps are fixed with tests in
the accompanying change; the rest are tracked with a verification level so the
backlog reflects evidence, not conjecture. The internal-audit method is now
repeatable.

Negative: the backlog grows by twenty-five items; several open items (BL-046,
BL-049, BL-051, BL-052) are architectural and will need their own changes.

Neutral: this ADR records findings and acceptance; enforcement is the code and
tests under each item.

## Alternatives considered and rejected

- Fix everything in one change. Rejected: the architectural items (credential
  wiring, hostname-resolving SSRF, CI gating) are larger than the surgical
  security fixes and merit separate, reviewable changes.
- Trust the static reviews without reproduction. Rejected: dynamic reproduction
  confirmed the P0 set and corrected severities, which is the basis for fixing
  them with confidence.

## Revisit triggers

- The HTTP transport or a concurrent Postgres audit path is implemented (raises
  BL-050 and BL-046 in urgency).
- An open item here is found exploitable in a wired path before it is scheduled.
- A later audit contradicts a recorded verdict (append an audit note, never
  rewrite a resolved row).
