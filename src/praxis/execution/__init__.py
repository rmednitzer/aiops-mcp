"""The single audited, tier-aware execution path.

Fuses classification (`patterns`), the deny-first policy gate (`policy`),
redaction, the append-only hash-chained audit log (`audit`), contracts and budgets
(`contract`), and the one fused entry point (`runner.run`). See ADR-0004 and
ADR-0005, and the SEC constraints in `docs/stpa/07-security-constraints.md`.
"""

from __future__ import annotations

from praxis.execution.audit import AuditLogger, AuditRecord, VerifyResult, verify_chain
from praxis.execution.contract import (
    Approval,
    ApprovalError,
    ApprovalRegistry,
    BudgetError,
    BudgetTracker,
    Contract,
    Predicate,
    RetryPolicy,
    Severity,
    Violation,
)
from praxis.execution.patterns import PATTERNS_VERSION, Tier
from praxis.execution.policy import Decision, Mode, Policy, classify
from praxis.execution.redaction import redact, redact_args
from praxis.execution.runner import (
    ExecutionContext,
    ExecutionRequest,
    ExecutionResult,
    KillSwitch,
    run,
)

__all__ = [
    "PATTERNS_VERSION",
    "Approval",
    "ApprovalError",
    "ApprovalRegistry",
    "AuditLogger",
    "AuditRecord",
    "BudgetError",
    "BudgetTracker",
    "Contract",
    "Decision",
    "ExecutionContext",
    "ExecutionRequest",
    "ExecutionResult",
    "KillSwitch",
    "Mode",
    "Policy",
    "Predicate",
    "RetryPolicy",
    "Severity",
    "Tier",
    "Violation",
    "VerifyResult",
    "classify",
    "redact",
    "redact_args",
    "run",
    "verify_chain",
]
