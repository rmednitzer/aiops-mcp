# ADR-0036: Required security gates folded into the ci-success aggregate

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-14      |
| Authors | Roman Mednitzer |

## Context

BL-052 (filed in ADR-0012): CodeQL and dependency-review ran as standalone workflows
whose enforcement depended on the branch ruleset listing them as required checks. In
practice the ruleset required only `ci-success`, so the `ci.yml` comment claiming the
security workflows were "required via branch protection" was untrue -- a PR could merge
with a failing CodeQL or dependency-review run. The requirement lived in mutable,
external branch-protection configuration rather than in the repository.

## Decision

CodeQL and dependency-review are folded into the required `ci-success` aggregate as
reusable-workflow calls, so the single required check transitively requires them in-repo:

1. `codeql.yml` and `dependency-review.yml` gain `on: workflow_call` and drop their
   standalone `push`/`pull_request` triggers (CodeQL keeps its weekly `schedule`).
2. `ci.yml` invokes both as jobs (`uses: ./.github/workflows/...`), granting CodeQL the
   `security-events: write` permission it needs; dependency-review runs only on
   `pull_request` (it diffs the PR).
3. `ci-success` `needs` them and uses `if: always()` with an explicit per-gate result
   check, so it runs even when a gate is legitimately skipped (dependency-review on
   push) yet fails on any failed or cancelled gate.

`fuzz` (scheduled, expensive) and `sbom` (push/release publish, ADR-0035) deliberately
stay out of the per-PR gate; they are not pull-request checks.

## Consequences

Positive: the security gates are enforced by the repository's own CI graph, not by
external branch-protection config that can drift or be misconfigured; the false
"required via branch protection" claim is corrected; the ruleset still needs only the
one `ci-success` check.

Negative / accepted: CodeQL now runs via the `ci.yml` call on every push and PR (plus
the weekly standalone scan); the reusable-workflow indirection is slightly less obvious
than a standalone workflow.

Neutral: no change to what CodeQL or dependency-review actually check.

## Revisit triggers

- A third pull-request-time security check is added: route it through the same aggregate.
- GitHub adds native cross-workflow required-check composition, making the
  reusable-workflow indirection unnecessary.
