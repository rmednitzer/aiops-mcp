# Backlog

Stable `BL-NNN` ids. Ids are never renumbered and resolved items are never
deleted (status moves to `resolved`). Each item cites its source ADR. Sizes:
XS, S, M, L.

| ID | Item | Size | Status | Source ADR |
|----|------|------|--------|-----------|
| BL-001 | Add full Apache-2.0 LICENSE text and NOTICE | XS | resolved | 0001 |
| BL-002 | Write ADR-0002..0010 and complete `pyproject.toml` + `Makefile` | S | resolved | 0002 |
| BL-003 | Complete STPA artifacts 01..07 (losses, hazards, constraints, control structure, UCAs, loss scenarios, security constraints) | M | resolved | 0009 |
| BL-004 | Execution core: patterns/policy/redaction/audit/contract/runner (vendored + fused), with invariant tests | L | resolved | 0004, 0005 |
| BL-005 | StoreProtocol + ladder; SQLite default backend (bitemporal, append-only trigger, active-fact constraint, sqlite-vec) | L | resolved | 0002, 0003 |
| BL-006 | Postgres+AGE+pgvector production backend behind the same Protocol | M | resolved | 0002, 0003 |
| BL-007 | Fact model + host_type; osquery and AIDE collectors (read-only) | M | resolved | 0007 |
| BL-008 | Drift engine: desired-state sources (tofu plan, ansible check, known-good) + findings | L | resolved | 0007 |
| BL-009 | Actuation adapters (ssh/opentofu/ansible/runbook/talosctl/redfish/cloud) with DRY_RUN -> approve -> execute | L | resolved | 0004, 0005 |
| BL-010 | Skills engine: manifest, registry, routing-chain dispatcher; eval gate + schema guard | M | resolved | 0010 |
| BL-011 | Tamper-evident audit + evidence: supervisor writer, Merkle, RFC 3161, optional Rekor | M | resolved | 0008 |
| BL-012 | MCP server surface: config, transport guards (stdio/http, SSRF egress, consent), tools with annotations | L | resolved | 0006 |
| BL-013 | CI workflows (codeql, sbom, dependency-review, fuzz; pinned SHAs; least-privilege) + ci-success aggregate | M | resolved | 0001 |
| BL-014 | Hardened deploy: Helm chart, systemd units, optional zarf | M | resolved | 0006 |
| BL-015 | Compliance map: complete EU AI Act / NIS2 / CRA / GDPR / ISO 27001 mapping to controls | S | resolved | 0009 |
| BL-016 | Migration note: import prototype host-knowledge and known-good baselines into the model | S | resolved | 0007 |
| BL-017 | Audit read and ingest tools through the single path (`query_facts`, `fact_history`, `ingest_observation`, `drift_scan` currently bypass `run()`) | S | resolved | 0011, 0016 |
| BL-018 | Write an audit record for trifecta denials before raising `TrifectaViolation` (context + actuate) | S | resolved | 0011, 0013 |
| BL-019 | Include the tool name in the classify/deny probe; document that any future stdin/env passthrough must be classified | S | resolved | 0011, 0016 |
| BL-020 | SSH adapter host-key policy (`StrictHostKeyChecking accept-new`/`yes`, `BatchMode=yes`, `UserKnownHostsFile`) | S | resolved | 0011, 0013 |
| BL-021 | `run_subprocess` process-group isolation (`start_new_session=True` plus `killpg` on timeout) | S | resolved | 0011, 0013 |
| BL-022 | Keep Talos snapshot hash verification on etcd-restore (never pass `--recover-skip-hash-check`; optional sidecar verify) | S | resolved | 0011, 0016 |
| BL-023 | Pre-flight `talosctl health` HARD precondition before talosctl upgrade | S | resolved | 0011, 0016 |
| BL-024 | Runbook actuation by registry id (preferred) or a canonicalised, base-dir-contained path | M | resolved | 0011, 0016 |
| BL-025 | Safe-default destructive scope for talosctl reset (no implicit `--wipe-mode ALL`; `ALL` is T3-confirmed) | S | resolved | 0011, 0016 |
| BL-026 | Finite-or-default numeric parsing of collected host data at every collector site | S | resolved | 0011, 0016 |
| BL-027 | Additive store extension Protocols plus content-hash compare-and-set for supersede | M | open | 0011 |
| BL-028 | Postgres backend engine-level append-only (`REVOKE` plus `BEFORE TRUNCATE` trigger; optional `RESTRICTIVE` RLS floor) | M | open | 0011 |
| BL-029 | Serialise audit hash-chain appends for concurrent writers (process lock now; `pg_advisory_xact_lock` for the PG path) | S | resolved | 0011, 0016 |
| BL-030 | Stamp `raw_snapshot_hash` of each collected snapshot into the Merkle checkpoint | M | open | 0011 |
| BL-031 | Machine-checkable compliance map (bidirectional code/control/article validator plus framework coverage) in CI | M | open | 0011 |
| BL-032 | helm-unittest chart assertions for the praxis chart, gated in CI | M | open | 0011 |
| BL-033 | Supply-chain parity: real zarf digest, CycloneDX SBOM, values/sbom/zarf CI parity, governance-as-code labels | M | open | 0011 |
| BL-034 | Multi-severity `parse_ansible_check` (FAILED to ERROR, unreachable to CRITICAL, ok to known-good) | S | resolved | 0011, 0013 |
| BL-035 | Documented audit/evidence retention tiers bound in config (NIS2 Art. 23, ISO 27001 A.8.15) | S | open | 0011 |
| BL-036 | Governance hygiene bundle (module back-citation headers, agent hard-rules, values-prod overlay plus version-bump checklist, namespace default-deny NetworkPolicy, regulatory-deadline data, empty-string-not-loopback test) | M | open | 0011 |
| BL-037 | `verify_evidence` fail-closed (return, never raise) and require checkpoints to cover the full log; document `LocalStamper` forgeability | M | resolved | 0012 |
| BL-038 | Postgres append-only trigger: guard all identity columns, split per-table (facts vs edges), correct the parity docstring | M | resolved | 0012 |
| BL-039 | Store triggers: block any `t_invalid`/`t_superseded`/`superseded_actor` mutation that leaves a row active (supersede-without-actor bypass) | S | resolved | 0012 |
| BL-040 | Patterns: fix the `chmod`/`chown -R /` deny and the `/etc/` write tier (`\b`-before-`/` defect); bump `PATTERNS_VERSION` | S | resolved | 0012 |
| BL-041 | Redaction: cover space-separated credential flags and URL/DSN credentials; redact the stdio server error path | S | resolved | 0012 |
| BL-042 | SSRF: normalise decimal/hex/octal/trailing-dot IP forms; `assert_egress_allowed` fail-closed on a non-IP host | S | resolved | 0012 |
| BL-043 | OpenTofu DRY_RUN uses a full `tofu plan` so the preview scope matches the apply scope | XS | resolved | 0012 |
| BL-044 | `_bounded_error` never raises, so `run()` always writes exactly one audit record | XS | resolved | 0012 |
| BL-045 | Docs honesty: ADR-0006 consent audit note; qualify `SECURITY.md`/`LIMITATIONS.md`; fix STPA `_ssrf.py` path and read-tool audit claim | S | resolved | 0012 |
| BL-046 | SSRF: resolve hostnames and check every resolved IP (rebinding-aware); wire the filter into the egress path | M | open | 0012 |
| BL-047 | talosctl: enforce the T3 single-target rule on `host.nodes`, not only `host.name` | S | resolved | 0012, 0013 |
| BL-048 | talosctl: replace `action.split()` with a verb allowlist; pass structured params | S | resolved | 0012, 0013 |
| BL-049 | Wire `CredentialBroker` into the actuation path (scoped, revocable enforcement) | M | resolved | 0012, 0016 |
| BL-050 | Audit hash chain: anchored high-water-mark to detect tail truncation | M | open | 0012 |
| BL-051 | Helm NetworkPolicy: restrict ingress with a `from:` selector | S | open | 0012 |
| BL-052 | CI: make CodeQL/fuzz/sbom/dependency-review required gates, not branch-protection-external | S | open | 0012 |
| BL-053 | Add coverage tooling and a `cov-fail-under` gate | S | open | 0012 |
| BL-054 | Store: `_cosine` finite-input guard; `seq` uniqueness or identity column to remove the `MAX(seq)+1` race | S | resolved | 0012, 0013 |
| BL-055 | Audit logger: do not reopen the file after `_degrade`; close the sink on degraded close | S | resolved | 0012, 0013 |
| BL-056 | stdio server: bound the per-line read; correct JSON-RPC notification and batch handling | S | resolved | 0012, 0016 |
| BL-057 | Manifest parser: exact `---` fence, size cap, reject indented keys, reject duplicate keys | S | resolved | 0012, 0013 |
| BL-058 | Collectors: AIDE empty output is not clean; per-collector size caps; finite numeric parse (with BL-026) | S | resolved | 0012, 0013 |
| BL-059 | Drift: escalate `UNEXPECTED` security-predicate findings; split multi-host Ansible subjects | S | resolved | 0012, 0013 |
| BL-060 | Deploy and config: Helm health probes, systemd drop-in dedupe, pin `cyclonedx-bom`, strip whitespace `HTTP_HOST`, normalise compliance-map path citations | M | open | 0012 |
| BL-061 | Test and fuzz wave: Postgres parity suite, evidence tamper matrix, host_type refusal per adapter, SSRF bypass tests, fuzz manifest/merkle/evidence | M | open | 0012 |
| BL-062 | Route read tools (`query_facts`, `fact_history`, collector/skill reads) through the audited path, or formally document the deliberate exclusion; reconcile with invariant 1 wording | S | resolved | 0012, 0016 |
| BL-063 | Actuation subprocess hardening: scrub env (`GIT_TERMINAL_PROMPT=0`, `DEBIAN_FRONTEND=noninteractive`, neutralise `*_ASKPASS`) and detach stdin (`DEVNULL`) so a wrapped tool cannot read the MCP stdio stream or hang on a prompt | S | resolved | 0013 |
| BL-064 | Audit log opened `O_APPEND` and owner-only (`0o600`, plus chmod of a pre-existing file) so redacted parameters are not world/group readable | XS | resolved | 0013 |
| BL-065 | Redaction: add provider token shapes (`github_pat_`, `glpat-`, `npm_`, `AIza`, `ya29.`, Stripe, OpenAI scoped) and make `Authorization` value-complete (no SigV4 signature leak) | S | resolved | 0013 |
| BL-066 | Self-containment: remove the out-of-tree prototype reference from `context.py` (no sibling repo named in code or docs) | XS | resolved | 0013 |
| BL-067 | Config: strip whitespace from `PRAXIS_HTTP_HOST` so a `"127.0.0.1\n"` value is recognised as loopback; empty defaults to loopback (residual of BL-060) | XS | resolved | 0013 |
| BL-068 | Store: add a `seq` identity/uniqueness so the `MAX(seq)+1` read cannot race across two store instances on one file (residual of BL-054) | S | resolved | 0013, 0016 |
| BL-069 | Clarify the self-contained rule (no coupling to sibling fleet repos, not anti-PyPI); record ADR-0014 and an appended audit note on ADR-0001; correct the over-absolute "implements everything itself" wording across the docs | S | resolved | 0014 |
| BL-070 | Adopt pydantic at the external-input boundary (MCP tool arguments, config, SKILL.md frontmatter) as the single source of truth for the JSON Schema and the parse/validate step; keep the execution core dependency-free | M | resolved | 0014 |
| BL-071 | SBOM CI repair: correct the `cyclonedx-py environment` output flag (`--outfile` to `--output-file`; the job had failed on every push to main since it was added), pin `cyclonedx-bom==7.3.0` so a future unpinned major bump cannot change the CLI surface, and align the SBOM runner to Python 3.12 (the `requires-python` floor and the ci.yml matrix), so the supply-chain job is reproducible and off a bleeding-edge interpreter (closes the `cyclonedx-bom` pin in BL-060; residual of BL-033) | S | resolved | 0014 |
| BL-072 | Approval gate human-binding: replace the deterministic `expected_token` (and its echo in the `DRY_RUN` body) with a server-issued, single-use, TTL-bound nonce surfaced out-of-band, so an autonomous caller cannot self-approve T2/T3 | L | resolved | 0015, 0016 |
| BL-073 | Floor free-form shell/runbook/exec actuation at T2 (`SSHAdapter.base_tier` T1 to T2); keep the denylist upgrade-only; add the missing destructive patterns (`find -delete`, `iptables -F`, `nft flush ruleset`, `kubectl drain`/`cordon`, mass `DELETE`/`UPDATE`, Windows `Remove-Item -Recurse`/`Format-Volume`/`Stop-Computer`) and bump `PATTERNS_VERSION` | M | resolved | 0015, 0016 |
| BL-074 | Wire `BudgetTracker` into `ExecutionContext`/`run()` so a per-session action, cost, and wall-time ceiling is enforced on the audited path | M | resolved | 0015, 0016 |
| BL-075 | Give the kill switch an operator actuator (an MCP kill/restore tool plus a signal or file sentinel) and a durable trip record, so SEC-8 emergency stop is engageable at runtime, not only via the unwired broker | S | resolved | 0015, 0016 |
| BL-076 | Wire runtime audit anchoring: invoke periodic `make_checkpoint` from the server (or a supervised sidecar), implement a non-forgeable stamper (real RFC 3161 or a transparency-log anchor), and make operating-system append-only (`chattr +a`/WORM) a required, documented deploy control until then | L | open | 0015 |
| BL-077 | Bound `redact_args` recursion depth and size inside the audited path and move it under the runner's failure containment, so a deeply nested args payload audits-and-denies instead of raising out of `run()` unaudited | S | resolved | 0015, 0016 |
| BL-078 | `execution/audit.py::_canonical`: add `default=str` (as `action_id` already does) so `AuditLogger.record` can never raise on a non-JSON-native arg value (logger-never-raises by construction) | XS | resolved | 0015, 0016 |
| BL-079 | Open the SQLite store file (and WAL/SHM sidecars) `0o600` so restricted facts are not group/world readable (mirror BL-064 for the audit log) | XS | resolved | 0015, 0016 |
| BL-080 | Scope the actuation subprocess environment to an allowlist (PATH, LANG, `SSH_AUTH_SOCK`, `TALOSCONFIG`, the prompt-suppression knobs) instead of copying the full server environment, so unrelated secrets do not reach wrapped tools and their plugins | S | resolved | 0015, 0016 |
| BL-081 | Ansible adapter input validation: apply the `_SAFE_TARGET` host check to `host.name` before `--limit`, and confine the playbook `action` to a configured base directory (extends BL-024 from runbook to ansible) | S | resolved | 0015, 0016 |
| BL-082 | talosctl: reject post-verb tokens beginning with `-` (take structured resource args), and validate each `nodes`/`endpoints` value as an IP or RFC 1123 host, closing the `--talosconfig` flag-injection residual of BL-047/BL-048 | S | resolved | 0015, 0016 |
| BL-083 | Move trifecta containment into the single audited path keyed off `request.untrusted`/context (not only the `run_action` handler); arm the latch on any read of attacker-influenced facts, not just live collection; remove or wire the dead `ExecutionRequest.untrusted` field | M | resolved | 0015, 0016 |
| BL-084 | Validate and consume the approval before `guard_actuation` for all tiers, so the trifecta audit cannot record a T2+ call as gated on token presence while the executor later denies it on token validity | S | resolved | 0015, 0016 |
| BL-085 | Route `ingest_observation` through `run()` (or document the deliberate exclusion) and add its UCA row, so the one untrusted-driven state-writing tool is audited and STPA-covered (sharpens BL-017/BL-062) | S | resolved | 0015, 0016 |
| BL-086 | Helm: move `storeDsn` to a `secretKeyRef` (existingSecret), mirroring the http-token pattern, and block an inline plaintext DSN in the Deployment env | S | open | 0015 |
| BL-087 | Deploy hardening: add systemd `PrivateUsers`/`ProcSubset=pid`/`RemoveIPC`/`IPAddressDeny`/`SocketBindDeny`, de-duplicate the base unit vs drop-in, scope the Helm NetworkPolicy DNS egress and add RFC1918/IMDS `except` to egress CIDRs, and set a sandbox `runtimeClassName` default | M | open | 0015 |
| BL-088 | Supply-chain: pin the fuzz interpreter to a stable Python, bound `ruff`/`mypy`/`pytest`/`psycopg[binary]`/`hatchling` versions, add a hash-locked dev requirements file for CI installs, and scope the SBOM to the production dependency graph | S | open | 0015 |
| BL-089 | STPA traceability: add SEC "Prevents" coverage for UCA-4..7, UCA-10, UCA-12/13, UCA-23; mark `act_cloud`/`act_redfish` rows planned; add a `set_mode` escalation test | S | open | 0015 |
| BL-090 | Annotate the aspirational compliance-map rows (NIS2 Art. 21 broker BL-049; CRA Annex I NetworkPolicy ingress BL-051 and digest-pin BL-033) with their tracking item; append audit notes to ADR-0004/0005/0008 per ADR-0015 Decision 6 | S | resolved | 0015, 0016 |
| BL-091 | Postgres `seq` race residual: the SQLite backend computes `seq` inside the INSERT under `facts_seq_unique`/`edges_seq_unique` (BL-068), but `store/postgres.py` still reads `_next_seq` as a separate `SELECT MAX(seq)+1` with no unique index on `seq`, so the `MAX(seq)+1` race BL-054 claimed closed is unmitigated on the Postgres path (reachable once `replicaCount`>1). Add `CREATE UNIQUE INDEX IF NOT EXISTS {facts,edges}_seq_unique` to `_SCHEMA` and a parity test in the Postgres suite. Schema change: proposal, not executed in the audit pass. | S | open | 0017 |
| BL-092 | Supply-chain reviewability: no `Dockerfile`/`Containerfile` exists, yet `deploy/helm/praxis/values.yaml` and `deploy/zarf.yaml` reference a digest-pinned `ghcr.io/rmednitzer/praxis` image, so the deployed container cannot be built or inspected from the repo (at odds with the ADR-0001 digest-pin posture; adjacent BL-033). Add a minimal non-root, pinned-base (distroless) Dockerfile that runs `python -m praxis`, or document the external build. | S | open | 0017 |
| BL-093 | Deploy doc clarity: the Helm chart defaults `transport: http`, but the server refuses any non-stdio transport with `NotImplementedError` (server.py), so `helm install` with defaults yields CrashLoopBackOff until HTTP serving lands (BL-012). `deploy/README.md` already names stdio as the working path; add a `values.yaml` comment and a chart `NOTES.txt` warning so the staged-not-runnable state is visible at install time. | XS | open | 0017 |
