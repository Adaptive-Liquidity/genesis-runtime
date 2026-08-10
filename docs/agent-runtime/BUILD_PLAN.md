# R0-R18 Build Plan

## Stage control

Only R0 and R1 are active. The required control point is: complete their evidence, validate, and stop before R2. A later stage is a target, not an implemented feature or inherited security claim.

| Stage | Target | Status in this workspace |
| --- | --- | --- |
| R0 | Architecture and core types | Active: contract/type evidence |
| R1 | Single-agent secure vertical slice | Active: fixed one-agent/one-tool evidence |
| R2 | Full authority lifecycle and delegation | Not active |
| R3 | Durable MissionStore | Not active |
| R4 | Real model integration and typed protocol | Not active |
| R5 | Dynamic Agent Synthesis | Not active |
| R6 | Multi-agent runtime | Not active |
| R7 | Canonical actions and transactions | Not active |
| R8 | Staged effects | Not active |
| R9 | IFC and memory | Not active |
| R10 | Circuit breaker and emergency stop | Not active |
| R11 | Evidence and proof system | Not active |
| R12 | Product and MCP surface | Not active |
| R13 | Behavioral verification | Not active |
| R14 | TLA+ model checking | Not active |
| R15 | Adversarial evaluation | Not active |
| R16 | Repair | Not active |
| R17 | Self-modification | Not active |
| R18 | Constrained decoding | Not active |

## R0 acceptance evidence

R0 is limited to the protocol's architecture and data-model foundation. Its test evidence should cover:

- single-source model/tool requests in `AgentSpec`;
- typed identifiers and strict serialization;
- deterministic, domain-separated canonical digests;
- semantic-context identity that excludes metadata-only `context_version`;
- bound tool-manifest identity;
- immutable lease/action certificates separated from mutable records;
- distinct authorization and physical-effect state; and
- a closed, size-bounded typed output protocol.

Passing unit tests support these concrete implementations. They do not establish durable behavior or system-wide invariants.

## R1 acceptance evidence

R1 remains a deliberately fixed vertical slice:

1. Resolve one agent's requested model, instruction profile, and registered fixture tool into trusted semantic context.
2. Accept scripted model bytes only through the typed `ProtocolGate`.
3. Apply plan, mission, authority, capability, manifest, and semantic-context checks in the trusted host.
4. Issue a scoped token only at the execution boundary.
5. Execute the fixture WASM only through the Nexus dependency pinned at `c4343883cc4bd1f1262f2f878ed81f8015cedd0e`.
6. Record and check in-memory event completeness for the exercised path.
7. Exercise rejection branches before Nexus for malformed output, unknown/disallowed tools, excess/forbidden authority, manifest mismatch, and semantic drift.
8. Confirm the tested model-facing trace contains neither issued tokens nor WASM bytes.

The validation command is:

```powershell
cargo test --workspace --all-targets
```

The checkpoint report must record the exact Nexus revision, test command, result, and any untested or blocked surface. If the command does not pass, R0/R1 are not validated.

## Stop gate before R2

Do not start R2 merely because R0/R1 types anticipate later state. Before activating R2, review the R0/R1 evidence for contradictions and explicitly approve the next stage.

At this stop gate, the project still makes no durability, crash-recovery, exactly-once, full delegation/revocation, IFC/MAC, multi-agent/coalition, formal-verification, or production-readiness claim.
