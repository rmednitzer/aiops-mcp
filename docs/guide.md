# How to use praxis: a complete guide

This guide shows how to run the `praxis` MCP server, connect a client, and use every
one of its functions safely. It is task-oriented; for the design rationale see
[Architecture](architecture.md), and for the day-to-day operator loop see the
[operate runbook](runbooks/operate.md).

`praxis` exposes six MCP tools over JSON-RPC 2.0: three read-only tools (`query_facts`,
`fact_history`, `drift_scan`), one observation-ingest tool (`ingest_observation`) that
writes facts to the model (it changes no host), one tier-gated actuator (`run_action`),
and one control tool (`emergency_stop`). Everything you do goes through one audited
execution path.

## 1. The mental model (read this first)

Five ideas govern every call.

- **Tiers T0 to T3.** Every action is classified by impact. T0 is read/observe. T1 is
  low impact. T2 is state-changing (needs human approval). T3 is irreversible (needs a
  typed approval token AND exactly one target). Classification rounds up conservatively,
  and a global deny list refuses dangerous commands in every mode.
- **Modes gate tiers.** The server runs in one of three modes (set by `PRAXIS_MODE`):
  `readonly` (T0 only), `guarded` (T0 to T2; T3 refused), or `open` (all tiers, each
  behind its own gate). Start in `guarded`.
- **DRY_RUN, then approve, then execute.** A state-changing `run_action` is previewed
  with `dry_run: true`. For a gated action the server mints a single-use, time-bound
  approval token and prints it on its OWN console (stderr), never in the tool response.
  You read that token and re-issue the call with `dry_run: false` and the token.
- **The trifecta latch.** Once a session has taken in untrusted content (an
  `ingest_observation`, or any read that returns observed facts), every later T1+ real
  run requires a minted approval, even if it would not otherwise be gated. This contains
  the "lethal trifecta" (sensitive data plus untrusted content plus actuation).
- **Everything is audited.** Every call writes exactly one record (allow, deny, or error)
  to an append-only, hash-chained log. Output bodies are never logged, only their SHA-256
  and length.

## 2. Run the server

`praxis` is self-contained: the default is a SQLite store over stdio with no external
services.

```bash
uv sync --extra dev                 # install (add --extra postgres for the PG backend)
PRAXIS_MODE=guarded \
PRAXIS_AUDIT_PATH=/var/lib/praxis/audit.jsonl \
  python -m praxis                  # serve over stdio (JSON-RPC 2.0)
```

The process speaks newline-delimited JSON-RPC on stdin/stdout. It refuses to start on an
unsafe HTTP bind (fail closed). For a networked deployment see [section 8](#8-http-transport).

## 3. The MCP protocol surface

Three JSON-RPC methods are served. A message with no `id` is a notification: it is never
dispatched and gets no response.

### initialize

Always call this first.

```json
{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
```

Response:

```json
{"jsonrpc": "2.0", "id": 1, "result": {
  "protocolVersion": "2025-11-25",
  "capabilities": {"tools": {}},
  "serverInfo": {"name": "praxis", "version": "0.0.0"}
}}
```

Over HTTP, `initialize` also mints a session and may carry a `consentCeiling` (see
[section 8](#8-http-transport)).

### tools/list

Discover the tools, their JSON Schemas, and their annotations.

```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
```

Each entry carries an `inputSchema` (generated from the tool's validated model) and
`annotations` with `readOnlyHint` and `destructiveHint`, so a client can reason about a
call before making it. Annotations are descriptive; the executor is the enforcement.

### tools/call

Invoke a tool by name with an `arguments` object.

```json
{"jsonrpc": "2.0", "id": 3, "method": "tools/call",
 "params": {"name": "query_facts", "arguments": {"subject": "host:axiom"}}}
```

The result is MCP content: a single text block whose `text` is the tool's JSON output,
plus `isError`.

```json
{"jsonrpc": "2.0", "id": 3, "result": {
  "content": [{"type": "text", "text": "{\"count\": 1, \"facts\": [ ... ]}"}],
  "isError": false
}}
```

Arguments are strictly validated against the tool's schema: an unknown field, a missing
required field, or a wrong type is rejected at the boundary (no coercion) with
`isError: true` and a bounded message. The examples below show only the `arguments`
object for brevity.

## 4. Reading and ingesting fleet state

The first three tools are read-only (`readOnlyHint: true`). `ingest_observation` is not a
read: it writes observed facts to the model (`readOnlyHint: false`), though it touches no
host. All four run through the audited path.

### query_facts (T0, read-only)

List the active facts in the fleet model.

| Argument | Type | Required | Meaning |
|---|---|---|---|
| `subject` | string | no | Filter to one subject, e.g. `host:axiom`. |
| `fact_type` | string | no | Filter to `observed`, `desired`, `drift`, or `known_good`. |

```json
{"name": "query_facts", "arguments": {"subject": "host:axiom", "fact_type": "observed"}}
```

Returns `{"count": N, "facts": [{"subject", "predicate", "fact_type", "value"}, ...]}`.
Returning observed facts arms the trifecta latch for the session (collected data read
back is treated as untrusted).

### fact_history (T0, read-only)

The full bitemporal history for a subject, oldest first.

| Argument | Type | Required | Meaning |
|---|---|---|---|
| `subject` | string | yes | The subject to trace, e.g. `host:axiom`. |
| `predicate` | string | no | Restrict to one predicate, e.g. `os_version`. |

```json
{"name": "fact_history", "arguments": {"subject": "host:axiom", "predicate": "os_version"}}
```

Returns `{"count": N, "history": [{"predicate", "value", "t_recorded", "active"}, ...]}`.

### drift_scan (T0, read-only)

Diff observed facts against the known-good baseline.

| Argument | Type | Required | Meaning |
|---|---|---|---|
| `subject` | string | no | Restrict the scan to one subject. |

```json
{"name": "drift_scan", "arguments": {"subject": "host:axiom"}}
```

Returns `{"count": N, "findings": [{"subject", "predicate", "kind", "severity"}, ...]}`.
Drift on a CIS control (`cis:` predicate) is ranked CRITICAL; other predicates use the
engine default.

### ingest_observation (writes facts, not destructive)

Parse captured host telemetry into observed facts and record them. This is how state
enters the model. It does not touch any host; it writes append-only facts and marks the
session untrusted (arming the trifecta latch).

| Argument | Type | Required | Meaning |
|---|---|---|---|
| `collector` | enum | yes | One of `osquery`, `aide`, `probe`, `talos`, `cis`. |
| `subject` | string | yes | The subject the telemetry describes, e.g. `host:axiom`. |
| `raw` | string | yes | The raw tool output you captured. Bounded at 4,194,304 characters (4 * 1024 * 1024); the cap is on characters, not bytes, so non-ASCII input may exceed 4 MiB on the wire. |
| `predicate` | string | no | The predicate to record under (defaults to the collector name; ignored by `cis`, which reads each control's benchmark from the payload). |

```json
{"name": "ingest_observation", "arguments": {
  "collector": "probe", "subject": "host:axiom", "predicate": "os_release",
  "raw": "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\""
}}
```

Returns `{"ingested": N, "subject", "collector"}`. The raw body is never written to the
audit log; only its SHA-256 and length are recorded.

You capture the `raw` payload yourself with a T0 read on the host (for example
`cat /etc/os-release`, an `osquery` query, an `aide --check`, or `talosctl`), then hand it
to `ingest_observation`. `praxis` parses telemetry; it does not collect it for you.

## 5. The actuator: run_action

`run_action` is the one destructive surface. It wraps a real tool per host type and routes
through the audited path: the host_type gate, the tier classification, the approval flow,
the trifecta gate, and the optional credential-scope gate.

| Argument | Type | Required | Meaning |
|---|---|---|---|
| `adapter` | enum | yes | `ssh`, `ansible`, `opentofu`, `runbook`, or `talosctl`. |
| `host` | string | yes | The target host name. Where it is passed to a wrapped CLI (the `ssh` target, which is `ssh_alias` or `host`, and the `ansible` `--limit` host), the effective target must begin with an alphanumeric (option-injection guard); adapters that do not put it in argv (`runbook`, `opentofu`) do not apply that check. |
| `host_type` | enum | yes | `ubuntu`, `talos`, `windows`, or `cloud`. Must match the adapter (you cannot SSH a Talos host). |
| `action` | string | yes | The command, playbook path, runbook id, or talosctl verb. |
| `dry_run` | bool | no (default `true`) | Preview vs execute. |
| `approval_token` | string | no | The minted token, required for a gated real run. |
| `ssh_alias` | string | no | The SSH config alias for the `ssh` adapter. |
| `nodes` | string[] | no | Talos node addresses. |
| `endpoints` | string[] | no | Talos endpoint addresses. |
| `wipe_mode` | enum | no | `talosctl reset` scope: `system-disk` (safe default if omitted), `user-disks`, or `all` (T3). Never implicit. |
| `health_client_side_only` | bool | no (default `false`) | Narrow the talosctl pre-upgrade health gate to client-side checks. The gate still runs and still HARD-gates. |
| `tofu_chdir` | string | no | OpenTofu `-chdir` workspace, confined to `PRAXIS_TOFU_ROOT`; refused if no root is configured. |

Adapters with a native safe preview (`ansible --check`, `tofu plan`) run it under
`dry_run`; the others (`ssh`, `talosctl`, `runbook`) return a non-executing preview
string. The response is:

```json
{"ok": true, "tier": "T2", "error": null,
 "output_sha256": "...", "output_len": 1234, "output": "<truncated preview>",
 "action_id": "<id on a dry run>",
 "approval": "<note, only on a gated dry run>"}
```

The output body in the response is a truncated preview; the audit stores only the hash and
length. Free-form shell via `ssh` floors at T2 (so it always meets the approval gate),
because a denylist cannot be complete against arbitrary commands.

## 6. End-to-end workflows

### Observe the fleet

1. Capture telemetry on the host with a T0 read (your own SSH/osquery/talosctl call).
2. `ingest_observation` to parse it into facts.
3. `query_facts` to read the model, or `drift_scan` to compare against known-good.

```json
{"name": "ingest_observation", "arguments": {"collector": "osquery", "subject": "host:axiom", "raw": "<osquery JSON>"}}
{"name": "drift_scan", "arguments": {"subject": "host:axiom"}}
```

### Actuate (DRY_RUN, approve, execute)

1. **Preview.** Call with `dry_run: true`. A dry run needs no approval; its response
   carries `action_id`. For a gated action the server prints a single-use token on its
   own console (stderr), out-of-band.

   ```json
   {"name": "run_action", "arguments": {
     "adapter": "ssh", "host": "axiom", "host_type": "ubuntu",
     "ssh_alias": "axiom", "action": "systemctl restart nginx", "dry_run": true}}
   ```

2. **Read the token** from the server console (it never appears in the tool response).

3. **Execute.** Re-issue with `dry_run: false` and the token as `approval_token`. The
   token is single-use, expires after `PRAXIS_APPROVAL_TTL_SECONDS` (default 600 s), and
   is bound to the exact action, target, tier, and patterns version.

   ```json
   {"name": "run_action", "arguments": {
     "adapter": "ssh", "host": "axiom", "host_type": "ubuntu", "ssh_alias": "axiom",
     "action": "systemctl restart nginx", "dry_run": false, "approval_token": "<token>"}}
   ```

A restart invalidates pending tokens: re-run the dry run. For a T3 action (for example a
`talosctl reset` with `wipe_mode: all`) the server allows exactly one target; supply a
single host and run in `open` mode.

### Stop everything

`emergency_stop` (T0, audited, never gated) trips the kill switch immediately; every
subsequent execution is refused at the first step of the audited path.

| Argument | Type | Required | Meaning |
|---|---|---|---|
| `reason` | string | yes | Why execution is halted (1 to 500 chars); recorded in the audit. |

```json
{"name": "emergency_stop", "arguments": {"reason": "suspected compromise on axiom"}}
```

With `PRAXIS_KILL_SWITCH_PATH` set the trip is durable across a restart. Restoring service
is deliberately out-of-band: remove the sentinel file and restart (or reset the in-process
switch). An operator can also engage the stop with no tool call by creating the sentinel
file (`touch`).

## 7. Reading the outcomes and common refusals

Every `tools/call` returns `isError` plus a text body. A refusal is not a crash; it is an
audited decision with a bounded reason. The ones you will meet:

- `approval required at T2+: run with dry_run=True, then approve` - preview first, then
  supply the token.
- `untrusted content ingested this session; actuation requires an approval` - the trifecta
  latch is armed; the action needs a minted approval even at T1.
- `T3 is irreversible: supply exactly one target` - reduce to a single host.
- `... does not actuate host_type=...` - the adapter does not match the host type (SEC-5).
- `kill switch engaged; execution disabled` - the emergency stop is tripped.
- `budget exceeded: ...` - a per-session ceiling is exhausted (see `PRAXIS_MAX_ACTIONS`).
- `no <kind> root configured` - set `PRAXIS_PLAYBOOK_ROOT` / `RUNBOOK_ROOT` / `TOFU_ROOT`.

## 8. HTTP transport

HTTP is opt-in and fails closed. It requires `PRAXIS_HTTP_TOKEN` and, for any non-loopback
bind, `PRAXIS_HTTP_ALLOW_ANY=yes-i-understand-the-risk`, plus the SSRF egress filter on
server-initiated requests.

```bash
PRAXIS_TRANSPORT=http PRAXIS_HTTP_TOKEN=$(openssl rand -hex 32) \
PRAXIS_HTTP_HOST=127.0.0.1 PRAXIS_MODE=guarded \
  python -m praxis
```

- **Auth.** Every request carries `Authorization: Bearer <token>`; a missing or wrong
  token is `401`. The token is never forwarded upstream.
- **Sessions.** `initialize` returns an `Mcp-Session-Id` header; every later request must
  send `Mcp-Session-Id: <id>` or it is `404`. Each session is isolated (its own trifecta
  latch, approval nonces, budget, and consent ceiling); every action across all sessions
  still lands in the one audit chain, tagged with the request and session ids.
- **Consent ceiling.** A session may pin a per-client tier ceiling at `initialize` with a
  `consentCeiling` param (`T0` to `T3`); an action above it is refused. Absent, the session
  is gated by `PRAXIS_MODE`; a malformed value fails closed to `T0`.
- **Concurrency.** The server is threaded, so a slow actuation on one client does not block
  others. There is no SSE stream; the transport is JSON-RPC over POST.

```bash
# initialize (capture the session id), then call a tool with it
curl -sD- -H "Authorization: Bearer $PRAXIS_HTTP_TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"consentCeiling":"T2"}}' \
  http://127.0.0.1:8765/

curl -s -H "Authorization: Bearer $PRAXIS_HTTP_TOKEN" -H "Mcp-Session-Id: <id>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_facts","arguments":{}}}' \
  http://127.0.0.1:8765/
```

Approval over HTTP is unchanged: the minted nonce is surfaced on the server console, never
in the HTTP response, so the operator reads it out-of-band.

## 9. Configuration reference

All configuration is `PRAXIS_`-prefixed and bound once at import. Defaults are safe.

| Variable | Default | Purpose |
|---|---|---|
| `PRAXIS_TRANSPORT` | `stdio` | `stdio` or `http`. |
| `PRAXIS_MODE` | `guarded` | `readonly`, `guarded`, or `open`. |
| `PRAXIS_STORE_DSN` | SQLite (memory/file) | `postgresql://...` for the Postgres backend, a path, or `sqlite:///path`. |
| `PRAXIS_AUDIT_PATH` | stderr | The append-only audit file. Set it for a durable, tamper-evident trail and runtime evidence. |
| `PRAXIS_HTTP_TOKEN` | unset | Required bearer token for HTTP. |
| `PRAXIS_HTTP_HOST` / `PRAXIS_HTTP_PORT` | `127.0.0.1` / `8765` | HTTP bind. |
| `PRAXIS_HTTP_ALLOW_ANY` | unset | `yes-i-understand-the-risk` to allow a non-loopback bind. |
| `PRAXIS_ALLOW_RESTRICTED` | `true` on stdio, `false` on HTTP | Whether `query_facts`/`fact_history` return facts classified `restricted`. Default-denied over HTTP; set `true` to include them. |
| `PRAXIS_APPROVAL_TTL_SECONDS` | `600` | Approval nonce lifetime. |
| `PRAXIS_MAX_ACTIONS` / `PRAXIS_MAX_WALL_SECONDS` | unset | Per-session budget ceilings. |
| `PRAXIS_KILL_SWITCH_PATH` | unset | Durable kill-switch sentinel file. |
| `PRAXIS_PLAYBOOK_ROOT` / `PRAXIS_RUNBOOK_ROOT` / `PRAXIS_TOFU_ROOT` | unset | Confinement roots for ansible / runbook / opentofu actuation (fail closed when unset). |
| `PRAXIS_EVIDENCE_PATH` / `PRAXIS_EVIDENCE_EVERY` / `PRAXIS_ANCHOR_PATH` | derived / `64` / unset | Runtime Merkle checkpoints and the anchored high-water mark. |
| `PRAXIS_AUDIT_SYSLOG_ADDRESS` | unset | Best-effort secondary syslog sink for SIEM/journald. |
| `PRAXIS_TSA_URL` / `PRAXIS_TSA_CERT` | unset | RFC 3161 timestamp authority for non-forgeable evidence (needs the `tsa` extra). |
| `PRAXIS_AUDIT_RETENTION_DAYS` / `PRAXIS_EVIDENCE_RETENTION_DAYS` | `365` | Declared retention tiers (`0` is indefinite). |

## 10. Verifying the audit trail

With `PRAXIS_AUDIT_PATH` set, the trail is an append-only hash chain plus Merkle
checkpoints. Verify a retained window end to end with the bundled script:

```bash
python scripts/verify_audit.py /var/lib/praxis/audit.jsonl
```

Keep the `audit.jsonl`, its `.evidence.jsonl`, and any anchor sidecar together so a
verifier can replay the window. With the default `LocalStamper`, operating-system
append-only storage (`chattr +a` or WORM) on those files is the required tamper-evidence
control; an RFC 3161 TSA stamper removes that requirement.

## Where to go next

- [Operate runbook](runbooks/operate.md): the condensed day-to-day loop.
- [Self-audit runbook](runbooks/self-audit.md): verifying the server against its own model.
- [Architecture](architecture.md) and [Decisions (ADRs)](adr/README.md): why it works this
  way.
- [Security model](https://github.com/rmednitzer/aiops-mcp/blob/main/SECURITY.md) and
  [Safety and security (STPA)](stpa/README.md): the controls and the hazards they trace to.
