# 04 Control structure

The system is a hierarchical control loop. Control actions flow down from the
operator through the MCP server to the fleet; feedback flows back up. Trust
boundaries are crossed at each arrow into an untrusted zone.

## Diagram

```
            +-------------------------------------------------+
            |                  Operator (human)               |
            |   issues commands; approves T2/T3; sets mode    |
            +-------------------------------------------------+
                      |  control: command, approval, typed token
                      |  feedback: result summary, drift findings, audit
                      v
   == trust boundary: model-driven plane (attacker-influenced) ===========
                      |
            +-------------------------------------------------+
            |                MCP server (praxis)              |
            |  transport guard (stdio default / HTTP opt-in)  |
            |  per-client consent registry                    |
            +-------------------------------------------------+
                      |  every read or act call
                      v
            +-------------------------------------------------+
            |        Single audited execution path            |
            |  classify -> policy (deny-first) -> redact ->   |
            |  contract -> execute -> format -> truncate ->   |
            |  audit record                                   |
            +-------------------------------------------------+
              |               |                |            |
              v               v                v            v
        +-----------+   +-----------+   +-------------+  +-----------+
        | Store     |   | Drift     |   | Skills      |  | Actuation |
        | (facts,   |   | engine    |   | registry +  |  | adapters  |
        | bitemporal|   | observe/  |   | dispatcher  |  | (per      |
        | audit log)|   | diff      |   |             |  | host_type)|
        +-----------+   +-----------+   +-------------+  +-----------+
                                                              |
                      == trust boundary: managed fleet =======|=========
                                                              v
        +---------------------------------------------------------------+
        |  Fleet hosts                                                   |
        |  ubuntu (ssh/ansible/runbook)  talos (talosctl, NO ssh)        |
        |  windows (winrm/ssh)           cloud/OOB (API/redfish)         |
        +---------------------------------------------------------------+
                      |  feedback: collected telemetry (UNTRUSTED)
                      ^--------------------------------------------------
```

## Controllers and controlled processes

| Controller | Controls | Control actions | Feedback received |
|-----------|----------|-----------------|-------------------|
| Operator | MCP server | issue command, approve T2/T3, supply typed token, set mode, trip kill switch | result summaries, drift findings, audit verification |
| MCP server | execution path | forward classified call with consent + annotations | tier, decision, audited outcome |
| Execution path | store, drift, skills, actuation | put/supersede fact, run observe/diff, dispatch skill, invoke adapter | success/failure, output hash + length |
| Actuation adapter | fleet host | DRY_RUN, execute (per host_type) | exit status, captured output (untrusted) |
| Drift engine | store | write drift findings as facts | diff result |

## Trust boundaries

1. Operator -> MCP server: the operator is trusted; the channel and the content
   returned to the operator are not (a returned summary may quote untrusted host
   output).
2. MCP server -> execution path: internal, but the request payload originates in
   the model-driven plane and is treated as data.
3. Execution path -> fleet: the actuation arrow is the highest-consequence
   boundary; host_type selects the legal adapter.
4. Fleet -> execution path (feedback): collected telemetry and command output are
   attacker-influenced and untrusted (the lethal-trifecta source).

## Feedback adequacy (an STPA concern)

Stale or missing feedback is itself a hazard (H-6, L-5). The drift engine's
observe step and the bitemporal store exist so the controller's picture of the
controlled process is fresh and as-of queryable, not assumed.
