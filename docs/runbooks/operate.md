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
deliberate T3 with a minted approval token and exactly one target.

## Observe (read, T0)

- `ingest_observation` parses captured telemetry (osquery/aide/probe/talos) into
  observed facts. It runs through the audited path (one audit record carrying the
  raw payload's SHA-256 and length, never the body) and arms the trifecta latch
  for the session (SEC-4, ADR-0016).
- `query_facts` / `fact_history` read the bitemporal model, audited per call. A
  read that returns observed facts also arms the trifecta latch: collected data
  read back is as untrusted as live collection.
- `drift_scan` diffs observed facts against the known-good baseline, audited.

## Actuate (DRY_RUN, then approve, then execute)

1. Call `run_action` with `dry_run: true` to preview. A dry run needs no approval.
   Its response carries the `action_id`; for a gated action the server mints a
   single-use approval token and prints it on ITS OWN console (stderr), out-of-band
   from the MCP channel (BL-072, ADR-0016). The token never appears in the tool
   response, so an autonomous caller cannot read and replay it.
2. Read the token from the server console, review the preview, then re-issue with
   `dry_run: false` and that token as `approval_token`. The token is single-use,
   expires after `PRAXIS_APPROVAL_TTL_SECONDS` (default 600), and is bound to the
   exact action, target, tier, and patterns version; for T3 exactly one target is
   allowed. A restart invalidates pending tokens: re-run the dry run.
3. Each call writes one audit record (allow, deny, or error). Output bodies are
   never logged, only their SHA-256 and length.

Trifecta note (SEC-4): once a session has taken in untrusted content (an ingest,
or a read returning observed facts), ANY T1+ real run requires a minted approval,
enforced inside the audited path itself. Free-form shell via ssh floors at T2
regardless (BL-073), so it always meets the gate.

Configuration this flow needs: `PRAXIS_PLAYBOOK_ROOT` and `PRAXIS_RUNBOOK_ROOT`
confine ansible and runbook actions; both adapters refuse outright until their
root is set (fail closed, BL-024/BL-081). Optional budget ceilings
(`PRAXIS_MAX_ACTIONS`, `PRAXIS_MAX_WALL_SECONDS`) deny, audited, once exhausted.

## Stop everything

Call the `emergency_stop` tool (T0, audited, never gated): it trips the kill
switch immediately and, with `PRAXIS_KILL_SWITCH_PATH` set, writes a sentinel file
so the stop survives a restart. An operator can also engage the stop out-of-band
by creating the sentinel file (`touch`), with no tool call at all. Restoring
service is deliberately out-of-band: remove the sentinel file and restart (or call
`kill_switch.reset()` in-process). Setting `PRAXIS_MODE=readonly` and restarting
remains a coarser fallback. The credential broker's `kill_all` also trips the
shared switch (BL-049, BL-075).

## Audit sinks and stamping

The append-only file at `PRAXIS_AUDIT_PATH` is the authoritative, tamper-evident sink.
Two opt-in additions are available, both off by default:

- `PRAXIS_AUDIT_SYSLOG_ADDRESS` forwards each (already-redacted) audit line to syslog for
  SIEM/journald visibility: a Unix socket path (e.g. `/dev/log`) or `host:port` for a
  remote UDP collector. It is best-effort and fanned out after the authoritative file
  write, so a down or oversized syslog endpoint never affects the file, the hash chain,
  or `verify_audit.py` (BL-100, ADR-0037). The destination is operator-trusted
  configuration; unlike the model-influenced egress paths it is not run through the SSRF
  filter, so a local SIEM on an RFC1918/Tailscale address works as intended.
- `PRAXIS_TSA_URL` plus `PRAXIS_TSA_CERT` (the TSA signing certificate, PEM) plus the
  `tsa` extra switch evidence checkpoints to a non-forgeable RFC 3161 timestamp authority
  instead of the keyless `LocalStamper` (BL-095, ADR-0030). Selection fails closed at
  startup if the URL is set without the certificate. Leave both unset to keep the
  `LocalStamper`, with OS append-only storage (`chattr +a`/WORM) as the required control.

Audit records carry optional `request_id`/`client_id` correlation fields (set per request
by the transport; BL-101, ADR-0038) so concurrent calls can be tied to their entries.

## Retention and archival

The audit and evidence retention tiers are declared in config:
`PRAXIS_AUDIT_RETENTION_DAYS` and `PRAXIS_EVIDENCE_RETENTION_DAYS` (default 365;
`0` is indefinite; the anchor follows the evidence tier). They are recorded in the
first session audit record for traceability (NIS2 Art. 23, ISO 27001 A.8.15).

praxis never deletes from the trail (it is append-only). Enforce a tier by archiving
whole files older than it, then rotating to a fresh `PRAXIS_AUDIT_PATH`: stop the
server, move `audit.jsonl` with its `.evidence.jsonl` and anchor sidecars to your
archive (WORM or a write-once bucket), and restart so a new chain begins with a fresh
session header. Do not `truncate` or `copytruncate` a live file: that breaks the hash
chain, the Merkle coverage, and the `O_APPEND` owner-only sink. Keep the three files
together so a retained window stays independently verifiable with
`scripts/verify_audit.py`.

## Networked (HTTP) deployment

HTTP is opt-in and fails closed: it needs `PRAXIS_HTTP_TOKEN` and, for any
non-loopback bind, `PRAXIS_HTTP_ALLOW_ANY=yes-i-understand-the-risk`, plus the
SSRF egress filter. See `deploy/` and ADR-0006. HTTP serving is staged; use stdio
for v0.
