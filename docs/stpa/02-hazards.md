# 02 Hazards

A hazard is a system state that, combined with worst-case environment conditions,
leads to a loss. Each maps to one or more losses (`01-losses.md`).

| ID | Hazard | Leads to |
|----|--------|----------|
| H-1 | A state-changing tool is invoked without validating operator intent (no HITL gate at T2 or above). | L-1, L-2 |
| H-2 | An action executes before, or without, an immutable audit record being written. | L-3 |
| H-3 | Tier classification under-rates an action (an irreversible action treated as reversible). | L-1, L-2 |
| H-4 | Attacker-influenced content (collected host data, command output, a feed) is allowed to authorize or shape actuation in the same session as sensitive data and an actuation capability (the lethal trifecta). | L-1, L-2, L-4 |
| H-5 | Actuation targets the wrong host type (for example an SSH path attempted against an immutable Talos node). | L-2 |
| H-6 | A reconciliation applies a change derived from a stale or wrong desired-state, or against a misidentified target. | L-2, L-5 |
| H-7 | The MCP surface is reachable without authentication, on a routable bind, or can be used to pivot into the private network (SSRF). | L-6, L-4 |
| H-8 | A credential is over-scoped, non-revocable, or logged, or the kill switch does not stop execution. | L-1, L-4 |
| H-9 | Output bodies, secrets, or unbounded attacker content are written into the audit log. | L-4, L-3 |
| H-10 | A fact is mutated or deleted in place, so history (and therefore the as-of truth) is lost. | L-3, L-5 |

## Hazard-to-loss matrix

| | L-1 | L-2 | L-3 | L-4 | L-5 | L-6 |
|-|-----|-----|-----|-----|-----|-----|
| H-1 | x | x | | | | |
| H-2 | | | x | | | |
| H-3 | x | x | | | | |
| H-4 | x | x | | x | | |
| H-5 | | x | | | | |
| H-6 | | x | | | x | |
| H-7 | | | | x | | x |
| H-8 | x | | | x | | |
| H-9 | | | x | x | | |
| H-10 | | | x | | x | |
