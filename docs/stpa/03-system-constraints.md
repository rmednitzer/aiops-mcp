# 03 System-level constraints

System-level constraints are the conditions the system must enforce to keep
hazards (`02-hazards.md`) from occurring. They are refined into concrete,
mechanism-mapped security constraints in `07-security-constraints.md`.

| ID | Constraint | Prevents |
|----|-----------|----------|
| SC-1 | Every state-changing tool call MUST produce an immutable audit record, and the record MUST be committed before the effect is acknowledged. | H-2 |
| SC-2 | Every action at T2 or above MUST require an explicit human confirmation; T3 MUST additionally require a typed token and operate on exactly one target. | H-1 |
| SC-3 | Tier classification MUST be conservative: on ambiguity it rounds up, and any privilege-escalation cue (sudo, doas, pkexec) is at least T2. | H-3 |
| SC-4 | A single session MUST NOT simultaneously hold sensitive data, attacker-influenced content, and an actuation capability without a human gate between phases. | H-4 |
| SC-5 | Actuation MUST branch on host_type and MUST NOT open SSH to a Talos host. | H-5 |
| SC-6 | Convergence MUST be DRY_RUN, then human approval, then execute; a drift finding MUST NOT auto-trigger a fix, and a fix MUST validate its target. | H-6 |
| SC-7 | The control surface MUST default to a non-network transport; any network bind MUST require authentication AND an explicit non-loopback opt-in AND an SSRF egress filter; tokens MUST NOT be passed through to upstreams. | H-7 |
| SC-8 | Credentials MUST be least-privilege, scoped per role, independently revocable, never logged; a kill switch MUST stop all execution immediately. | H-8 |
| SC-9 | The audit log MUST store only an output hash and length, never bodies or secrets; parameters MUST be redacted. | H-9 |
| SC-10 | State facts MUST be append-only; deletion MUST be blocked at the storage layer; corrections MUST supersede with an actor and a reason. | H-10 |

Each constraint is the parent of one or more entries in
`07-security-constraints.md`, which name the enforcing code, policy, or gate.
