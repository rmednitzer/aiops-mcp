# Runbook: operate praxis

The day-to-day operator loop. praxis defaults to stdio against SQLite with no
external services.

## Start

```
uv venv --python 3.12 .venv && uv pip install --python .venv -e .
PRAXIS_MODE=guarded PRAXIS_AUDIT_PATH=/var/lib/praxis/audit.jsonl \
  .venv/bin/python -m praxis
```

Modes (ADR-0004): `readonly` (T0 only), `guarded` (T0-T2; T3 refused), `open`
(all tiers, each behind its gate). Start in `guarded`; raise to `open` only for a
deliberate T3 with a typed token.

## Observe (read, T0)

- `ingest_observation` parses captured telemetry (osquery/aide/probe/talos) into
  observed facts. Note: this arms the trifecta gate for the session (SEC-4).
- `query_facts` / `fact_history` read the bitemporal model.
- `drift_scan` diffs observed facts against the known-good baseline.

## Actuate (DRY_RUN, then approve, then execute)

1. Call `run_action` with `dry_run: true` to preview. A dry run needs no approval;
   its response carries the `action_id` and the exact `approval_token` to use next.
2. Review the preview, then re-issue with `dry_run: false` and that `approval_token`.
   For T2 the token is `APPROVE-<action_id>`; for T3 it is `CONFIRM-<target>` and
   exactly one target is allowed.
3. Each call writes one audit record (allow, deny, or error). Output bodies are
   never logged, only their SHA-256 and length.

Trifecta note (SEC-4): once a session has ingested untrusted content (any
`ingest_observation` or feed), even a sub-T2 act requires a validated, single-use
`approval_token`; a bare token string is rejected. The dry-run response surfaces
the token to use.

## Stop everything

Trip the kill switch (in-process `ExecutionContext.kill_switch.trip()`), or set
the mode to `readonly` and restart. The kill switch clears only by explicit
operator action.

## Networked (HTTP) deployment

HTTP is opt-in and fails closed: it needs `PRAXIS_HTTP_TOKEN` and, for any
non-loopback bind, `PRAXIS_HTTP_ALLOW_ANY=yes-i-understand-the-risk`, plus the
SSRF egress filter. See `deploy/` and ADR-0006. HTTP serving is staged; use stdio
for v0.
