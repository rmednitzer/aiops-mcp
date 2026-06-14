# Deep audit 2026-06-14: baseline and method

Date: 2026-06-14
Scope: full in-depth audit, validation, and adversarial-testing pass over `praxis`
at the post-ADR-0038 baseline (backlog fully resolved). Follows the 2026-06-12 pass
(ADR-0017, `audit/00-inventory.md`..`03-final-report.md`); this directory holds the
2026-06-14 pass so the prior record is preserved.

Method: five parallel read-only domain audits (execution core and invariants;
transport/SSRF/redaction/audit-integrity; store/actuation/collectors/drift;
documentation drift; STPA and governance traceability), plus hands-on runtime
adversarial probing recorded below. Findings are in `01-findings.md`; disposition is
in `02-report.md`. Every result cites a command run or a `file:line` read this session.

## Baseline at audit start

| Gate | Tool | Result |
|---|---|---|
| Lint (incl. `S`/bandit rules) | ruff | All checks passed (`src tests scripts`) |
| Format | ruff format | clean |
| Type safety | mypy strict | Success, no issues, 64 source files |
| Tests | pytest | 394 collected; `make ci-success` green |
| Coverage | coverage | 92% total, above the floor |
| Schema drift | `make schema` (in ci-success) | green |
| Eval gate | `make eval` (in ci-success) | green |
| Fuzz | `scripts/fuzz.py 20000` | `20000 iterations (+ manifest/merkle/evidence stages), no violations` |
| Dependency surface | pyproject | one runtime dep (`pydantic>=2,<3`); CI runs dependency-review and a hash-locked dev lock |
| Secret sweep | grep over tree | clean (only test fixtures: the canonical `AKIAIOSFODNN7EXAMPLE` in `scripts/fuzz.py`; a library constant) |
| Working tree | git | clean at audit start |

`pip-audit` is not available in this session (it was in the 2026-06-12 pass, which
reported no known vulnerabilities); the runtime surface is one bounded package and CI
enforces dependency-review plus a hash-locked `requirements-dev.txt`.

## Runtime adversarial probe matrix

Direct calls against the security-critical functions with hostile inputs. PASS = the
control held; the two deviations are tracked in `01-findings.md`.

### Redaction (`execution/redaction.py`) - PASS
Redacted every probed secret format: AWS AKIA, GitHub `ghp_`, OpenAI `sk-`, JWT,
PEM private key, `scheme://user:pw@host` DSN, `Authorization:` header, MySQL compact
`-p<pw>`, Slack `xoxb-`, GitLab `glpat-`. Secret-keyed values redacted regardless of
shape (int, list, nested dict). Hostile inputs did not crash `redact_args` (object
with a raising `__str__`, `bytes`, `set`, depth-50 nesting). Plain values preserved.
Note (F-002): an unkeyed high-entropy value in no known format is not redacted (the
redactor is pattern + secret-key based, by design).

### SSRF egress (`_ssrf.py`) - PASS
Blocked: `169.254.169.254`, `127.0.0.1`, `0.0.0.0`, RFC1918 (`10/172.16/192.168`),
`::1`, link-local `fe80::`, ULA `fc00::`/`fd00::`, IPv4-mapped `::ffff:127.0.0.1` and
`::ffff:169.254.169.254`, 6to4 `2002:a9fe:a9fe::`, and decimal/octal/hex IP encodings.
`8.8.8.8` allowed. Bare names denied by the strict gate; `metadata.google.internal`
denied by the strict gate and (when resolved) blocked as `169.254.169.254`. A mixed
A-record set (`[8.8.8.8, 10.0.0.5]`) is blocked because every resolved IP is checked
(rebinding pin). `is_blocked_address(name)` returning False for a bare name is an
IP-level helper, by design - not a gap (the egress gate handles names).

### Tier classification (`execution/policy.py`, `patterns.py`) - PASS
`sudo`/`doas` -> T3 (reboot), `pkexec` -> T2; compound `echo hi; sudo reboot` -> T3;
env-prefixed `FOO=bar sudo x` -> T2; absolute `/usr/bin/sudo x` -> T2; base tier
preserved (rounds up, never down).

### Audit logger (`execution/audit.py`) - PASS except F-001
No output body written (only `output_sha256`/`output_len`). `record` did not raise on
`set`/`bytes` args. F-001: `record` RAISED on an arg value whose `__str__` raises, and
on a circular reference (`_canonical` `default=str` is uncontained). Not reachable from
JSON-RPC args (native, acyclic) or via `redact_args` (depth-capped), but it breaks the
invariant-3 "logger never raises" claim for a direct internal call. Tracked F-001.

### Transport guard (`config.py`) - PASS
`validate_transport` fails closed on HTTP-without-token, non-loopback-without-opt-in,
and unknown transport.

### Store (`store/`) - PASS
No `delete` method on the store; facts are append-only by construction (engine-level
enforcement reviewed separately in `01-findings.md`).
