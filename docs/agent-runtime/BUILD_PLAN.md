# R0-R18 Build Plan

## Stage control

R0-R2 are active. The required control point is: complete their evidence, validate, and stop before R3. A later stage is a target, not an implemented feature or inherited security claim.

| Stage | Target | Status in this workspace |
| --- | --- | --- |
| R0 | Architecture and core types | Implemented/tested: contract/type evidence |
| R1 | Single-agent secure vertical slice | Implemented/tested: fixed one-agent/one-tool evidence |
| R2 | Full authority lifecycle and delegation | Implemented/tested: in-memory identity, chain, lifecycle, and live revalidation evidence |
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

Future R5 design note: Dynamic Genesis specialist synthesis will require an explicit policy for mission-approved per-agent model/runtime specialization while preserving authority non-amplification. That policy and implementation are not part of R2.

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

The checkpoint report must record the exact Nexus revision, test command, result, and any untested or blocked surface. If the command does not pass, R0-R2 are not validated.

## R2 acceptance evidence

R2 adds a deliberately in-memory authority layer:

1. Bind signed agent identities to issuer identity and key identifiers without exposing signing material through serialization or debug output.
2. Bind every immutable lease certificate to its subject, issuer, exact parent or renewal predecessor, mission, organization version, policy epoch, semantic context, and full capability manifest.
3. Validate transitive capability and tool attenuation across the entire live chain; reject `Capability::All`.
4. Bound authority and identity chains to the trusted kernel maximum, independently of future mission spawn topology.
5. Maintain generation-checked in-memory pause, resume, expiry, cascading revocation, and immutable same-context renewal records. Renewal cannot reauthorize semantic-context drift.
6. Revalidate every observed generation, chain signature, semantic context, and atomic registry manifest snapshot immediately before issuing Nexus tokens and consuming authorization.
7. Keep final validation, synchronous token issuance, and single-use consumption under one authority guard as the authorization commit section: a prior revocation rejects, while a later revocation governs future calls and does not cancel an already-started Nexus execution.
8. Use a fresh Nexus hypervisor per execution so its bearer-token state is not retained after the call. Snapshot identifiers from one call are consequently not reusable in another.

## Stop gate before R3

Do not infer persistence from the R2 in-memory authority ledger or event stream. R3 requires separate approval and must add crash-safe storage and recovery evidence.

At this stop gate, the project still makes no durability, crash-recovery, exactly-once, distributed revocation, IFC/MAC, multi-agent/coalition, formal-verification, or production-readiness claim.
