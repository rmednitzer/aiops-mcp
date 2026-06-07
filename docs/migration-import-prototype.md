# Migration note: importing the prototype into the praxis model (BL-016)

The predecessor was a hand-run MCP gateway whose knowledge lived in flat markdown
and whose "known-good" was an operator's memory and ad-hoc baselines. This note
describes how to bring that material into the praxis model without weakening any
invariant. praxis remains self-contained: the import is a one-time data load, not a
runtime dependency on the prototype.

## What maps to what

| Prototype artifact | praxis target | How |
|--------------------|---------------|-----|
| `CONTEXT-<host>.md`, `fleet-inventory.md` (host knowledge) | host-knowledge skills under `skills/<name>/SKILL.md` | One bundle per topic; write a precise, router-targetable `description` (ADR-0010). Keep prose in the body. |
| The host list and routing | `config/inventory.yaml` | Fill the schema in `config/inventory.example.yaml`; set `host_type` (it gates actuation, SEC-5) and routing (ssh alias, talosctl endpoints/nodes). |
| Per-host known-good baselines | `KNOWN_GOOD` facts in the store | For each baseline value, write a `Fact(subject="host:<name>", predicate=<...>, fact_type=KNOWN_GOOD, value=...)` via `store.put_fact`. The drift engine diffs observed against these (`drift.diff`). |
| Operator procedures / runbooks | tool skills under `skills/` and entries in `runbooks/` (the companion repo) | Knowledge becomes a tool skill; the actual script stays a runbook invoked through the `runbook` adapter. |

## Procedure

1. Inventory first. Translate the host list into `config/inventory.yaml`. Get
   `host_type` right for every host; a mis-typed Talos host as `ubuntu` would let
   the SSH adapter be selected (SEC-5 refuses it, but the data should be correct).
2. Host knowledge. For each prototype context document, create a host-knowledge
   `SKILL.md` with a specific description. Run `make eval` and add golden queries
   so routing stays measured (ADR-0010).
3. Known-good baselines. For each host and predicate (os_version, ssh_config,
   file_integrity, service states, listening ports), record a `KNOWN_GOOD` fact.
   Treat the baseline as operator-blessed: it is the desired state the drift engine
   compares against. Bitemporality means a later correction supersedes with an actor
   and a reason, never an in-place edit (SEC-10).
4. Verify. Ingest a current observation (the `ingest_observation` tool or a
   collector), then run `drift_scan`. The findings are the gap between the imported
   baseline and reality; triage them with the `drift-triage` skill.

## What not to import

- No secrets, tokens, or private keys. Credentials are injected out of band and
  scoped through the `CredentialBroker` (invariant 9); they never enter the store
  or a skill bundle.
- No executable prototype code as a skill `contract.py`. Untrusted bundles load
  inert (`allow_contract=False`, ADR-0010).
