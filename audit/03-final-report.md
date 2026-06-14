# Audit phase 8: final report

Date: 2026-06-14
Repository: `rmednitzer/aiops-mcp` (product `praxis`)
Audited HEAD: `b2d17ce` (`209f61a` plus the concurrently-landed #69 and #71)
Prior pass: 2026-06-12, HEAD `dc69596` (ADR-0017)

## Executive summary

This is the second full, phased, read-only audit of `praxis`, run on 2026-06-14.
It examined HEAD `209f61a`; during the governance write-back #69 (ADR-0037, BL-100
multi-sink audit fan-out) and #71 (ADR-0038, BL-101 request/client correlation)
merged to `main`, so the pass was rebased onto the merged tree `b2d17ce`, the gate
suite re-run there, and both deltas reviewed. The result is a clean bill of health:
no Critical, High, Medium, or Low findings; every CI and governance gate green; no
known dependency vulnerabilities; 200000 fuzz iterations with no violations; and —
new this pass — an executed adversarial battery in which all five load-bearing
controls held under attack inputs.

Every finding from the 2026-06-12 pass (Q-01..Q-05 / BL-091, BL-092, BL-093, and
the BL-088 items) is now closed, each with a resolving ADR or backlog id recorded
in `audit/02`. The first pass's top-5 residual risks (BL-076, BL-095, BL-046,
BL-091, the BL-012 guard surface) are all resolved, as are the two items still open
at audit time — BL-100 (#69) and BL-101 (#71) — closed during this write-back. The
backlog stands at 103 of 103 prior items resolved; this pass adds BL-104, the sole
open item.

This pass's net contribution is fresh, command-backed evidence (including the
adversarial battery and a review of the #69 and #71 deltas), the refreshed `audit/`
baseline, and one Info/latent, forward-looking backlog item (BL-104). No code was
changed: the single finding is latent on a transport that is not implemented, and
shipping speculative concurrency code against an absent code path would violate the
project's "no behavior change without a test" rule.

## Baseline vs exit metrics

No fixes were applied, so the baseline is also the exit state.

| Metric | 2026-06-14 (merged tree `b2d17ce`) | 2026-06-12 (ADR-0017) |
|---|---|---|
| Tests | 372 passed, 23 skipped (live-Postgres) | 226 passed, 1 skipped |
| Lint (ruff) | 0 violations | 0 violations |
| Format (ruff) | clean | clean |
| Types (mypy strict) | 0 errors, 121 files | 0 errors, 107 files |
| Schema drift | none | none |
| Eval gate | P@1 1.000, MRR 1.000, n=8 | P@1 1.000, MRR 1.000, n=8 |
| Compliance gate | consistent | (added later) |
| Helm unittest | 34 passed (4 suites) | (added later) |
| Coverage | 92 percent (gated, BL-053) | 94 percent (ad hoc) |
| Dependency vulns | 0 (pip-audit) | 0 (pip-audit) |
| Fuzz | 200000 iters, 0 violations | 200000 iters, 0 violations |
| Adversarial battery | 5/5 controls held | (not run) |
| Secrets (tree) | 0 real | 0 real |

Vulnerability counts this pass: Critical 0, High 0, Medium 0, Low 0, Info 1 (F-01 /
BL-104, latent) plus one no-action false-positive note (N-01, bandit B608).

## Commits in this audit pass

Each is one concern; evidence and the governance write-back are separated.

1. `docs(audit): second full-pass audit refresh (2026-06-14)` — the refreshed
   `audit/00..03` evidence files, the ADR-0039 governance record, the ADR index
   entry, BL-104, and the CHANGELOG entry.

## Residual risk statement

- BL-104 (Info, latent): the single process-wide `ExecutionContext` (one
  `SessionTaint`, one `ApprovalRegistry` with a non-atomic validate/consume) is
  correct and safe on the stdio transport (single process, single-threaded, one
  operator). It becomes load-bearing only if/when the multi-client HTTP transport
  serves concurrent clients on one context; tracked for that work. Not reachable
  today (non-stdio binds are refused, fail-closed). #71's per-request correlation
  scope is adjacent groundwork but does not isolate the taint latch or the nonce.
- Tamper-evidence is defence-in-depth: the SHA-256 hash chain plus RFC 6962 Merkle
  evidence, anchorable to a high-water-mark file, stampable by a real RFC 3161 TSA
  (`tsa` extra, fail-closed selection) instead of the keyless `LocalStamper`, and
  now also fannable to a best-effort secondary sink (`SyslogAuditSink`, #69) with
  per-sink failure containment that leaves the authoritative file write untouched.
  OS append-only storage on the trail files remains the documented baseline control
  (SECURITY.md, ADR-0019/0029).
- HTTP serving is unimplemented and fails closed; the Helm/zarf artifacts encode a
  forward production posture and are not runnable as shipped (documented at install
  time, BL-093). No exposure.
- Supply chain: one runtime dependency, vuln-free today; the dev set and the
  container base are digest/hash-pinned; the deploy image digest is an all-zero
  placeholder the operator replaces at first release (fail-closed).

Overall: the design's load-bearing controls — single audited path, deny-first
tiered authority, human-binding minted approvals, storage-layer append-only with
CAS on both backends, fail-closed SSRF and transport guards, in-path trifecta
containment, broad pre-audit redaction, PSA-restricted deploy — are present in
code, tested, and verified present and effective this pass (the adversarial battery
exercised them directly). Residual risk is concentrated in the one deferred,
openly-tracked item (BL-104), not reachable on the shipped surface.

## Top backlog items (by leverage)

1. BL-012 HTTP serving (resolved for the guard/config surface; live serving is the
   remaining transport work) — the trigger that activates BL-104.
2. BL-104 (M, open, new) — per-session execution-context isolation and an atomic
   approval consume, to land with the multi-client transport (building on #71's
   per-request correlation scope).

## Method note and deviations

- Tooling available this pass: `uv run`-driven gates, `pip-audit`, `bandit`, the
  in-repo fuzzer, an executed adversarial probe, and a manual SAST/secret re-read.
  semgrep/gitleaks/trufflehog were not used; the adversarial battery and bandit
  substitute for rule-based SAST.
- The pass was rebased onto `origin/main` after #69 and #71 landed; the gate suite
  was re-run on the merged tree and both deltas reviewed, so the evidence matches
  what ships.
- Governance deliverables follow the repo's established scheme: `docs/adr/NNNN-*.md`
  (ADR-0039), `docs/backlog.md` with stable `BL-NNN` ids (BL-104), and the `audit/`
  evidence set refreshed in place (the living regression reference, ADR-0017
  Decision 1; git preserves the 2026-06-12 text). No parallel backlog or ADR tree
  is created.
- No stop condition was triggered: the suite runs, no secret appears exploited, no
  fix required a major bump or data migration, and no repo content conflicted with
  the audit.
