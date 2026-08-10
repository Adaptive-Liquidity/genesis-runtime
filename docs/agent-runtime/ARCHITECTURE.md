# Genesis Runtime Architecture

## Scope and status

This document describes the standalone `genesis-runtime` workspace at R0/R1. It distinguishes implemented/tested fixture behavior from the broader AEON design targets. R2-R18 are roadmap stages, not active architecture claims.

The normative baseline is [AEON Protocol v1.4](AEON_PROTOCOL_V1_4.md). That file is preserved byte-for-byte from the supplied final official source. This document is explanatory and does not amend it.

## Trust boundary

The model-facing strategy side is untrusted. It may propose an `AgentSpec` and emit a closed typed protocol message. It does not receive a Nexus capability token, WASM bytes, mutable lease state, or authority-ledger mutation access.

The host-side runtime is trusted for the R1 fixture. It resolves semantic context, validates typed output, applies mission and authority checks, binds the selected tool to its registered manifest digest, and passes approved execution to Nexus.

Nexus is the sole execution kernel. The workspace dependency is pinned to Git revision `c4343883cc4bd1f1262f2f878ed81f8015cedd0e` from `https://github.com/adaptiveliquidity/Nexus.git`, with default features disabled. AEON owns orchestration and governance checks; Nexus owns capability-enforced WASM execution. There is no AEON-native fallback executor in the R1 design.

## R1 request path

```text
MissionEnvelope + AgentSpec
          |
          v
trusted ContextResolver
          |
          v
scripted model response (untrusted bytes)
          |
          v
ProtocolGate -> PlanGate -> ActionGate / AuthorityKernel
          |                       |
          | rejection             | approved binding
          v                       v
   in-memory event         Nexus execution port
        evidence                   |
                                   v
                       pinned Nexus WASM kernel
                                   |
                                   v
                           execution result
```

Malformed output is rejected by `ProtocolGate` before ActionGate or Nexus. A well-formed proposal still must satisfy mission tool bounds, requested/granted capability bounds, the prohibition on `Capability::All`, current semantic-context identity, and the registered tool-manifest binding before execution.

## Data ownership

| Data | Owner in the design | R0/R1 status |
| --- | --- | --- |
| `AgentSpec` | Untrusted proposal | Typed request; no lifecycle or credentials |
| `SemanticContext` | Trusted resolver | Canonical digest excludes metadata-only `context_version` |
| `AuthorityLeaseCertificate` | Trusted authority path | Immutable signed payload type; R1 does not implement the full lifecycle |
| `LeaseRecord` | Trusted mutable state | Separate type; in-memory only |
| `CapabilityManifest` / `BoundTool` | Trusted registry/authority path | Canonical binding exercised for the fixed tool |
| `CanonicalAction` / `ActionRef` | Trusted canonicalizer | Typed/canonical contract evidence at R0 |
| `AuthorizationRecord` | Trusted authorization path | In-memory R1 consumption state only |
| `EffectRecord` | Future transaction/reconciliation path | Typed state model only; no external exactly-once claim |
| `MissionEvent` | Evidence plane | In-memory completeness checks for exercised paths only |

## Evidence boundary

R0 tests establish properties of the represented types and canonicalization functions for test inputs. R1 tests execute one scripted agent and a fixture WASM tool through the real pinned Nexus dependency, plus fixed rejection branches.

This is not evidence of durable state, crash recovery, tamper evidence, external-effect reconciliation, concurrency safety, generalized policy completeness, delegation chains, multi-agent isolation, or coalition behavior. Those surfaces require later roadmap stages and separate evidence.

## Roadmap boundary

R0 supplies architecture/types and R1 supplies the single-agent vertical slice. R2 begins the full authority lifecycle; R3 begins durable storage. No later-stage feature should be inferred from a type that anticipates it. See [BUILD_PLAN.md](BUILD_PLAN.md) for the R0-R18 stage boundary.
