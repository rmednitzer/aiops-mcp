---
name: drift-triage
description: Triage configuration drift findings: prioritize by severity, explain observed versus desired, and propose a human-gated convergence.
kind: tool
---

# Drift triage

Tool skill. Walks the drift findings produced by `drift_scan`: prioritizes by
severity (security predicates escalate to critical), explains the observed versus
desired delta for each finding, and proposes a convergence plan. Convergence is
never automatic: a proposal must pass DRY_RUN, then human approval, then execute
through the audited path (SEC-6).
