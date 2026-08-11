# Genesis Runtime Architecture

## Scope and status

This document describes the standalone `genesis-runtime` workspace at R0-R2. It distinguishes implemented/tested fixture behavior from the broader AEON design targets. R3-R18 are roadmap stages, not active architecture claims.

The normative baseline is [AEON Protocol v1.4](AEON_PROTOCOL_V1_4.md). That file is preserved byte-for-byte from the supplied final official source. This document is explanatory and does not amend it.

## Trust boundary

The model-facing strategy side is untrusted. It may propose an `AgentSpec` and emit a closed typed protocol message. It does not receive a Nexus capability token, WASM bytes, mutable lease state, or authority-ledger mutation access.

The host-side runtime is trusted for the exercised fixture. It resolves semantic context, validates typed output, owns in-memory key custody and authority state, verifies the complete live lease/identity chain and full capability manifest, and passes approved execution to Nexus.

Nexus is the sole execution kernel. The workspace dependency is pinned to Git revision `c4343883cc4bd1f1262f2f878ed81f8015cedd0e` from `https://github.com/adaptiveliquidity/Nexus.git`, with default features disabled. AEON owns orchestration and governance checks; Nexus owns capability-enforced WASM execution. There is no AEON-native fallback executor.

## R2 request path

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
          |                signed chain + full manifest
          | rejection               |
          v                         v
   in-memory event       guarded final validation +
        evidence         per-call token issuance +
                         authorization consumption
                                    |
                                    v
                       pinned Nexus async execution
                                    |
                                    v
                            execution result
```

Malformed output is rejected by `ProtocolGate` before ActionGate or Nexus. A well-formed proposal must satisfy mission bounds, bounded transitive lease attenuation, identity and lease signatures, live generations, the prohibition on `Capability::All`, current semantic-context identity, and an atomic full-manifest registry snapshot. These bindings are checked again while the authority read guard is held through per-call hypervisor creation, token issuance, and authorization consumption. The guard is released before asynchronous WASM execution.

R2 counts the root as authority-chain depth one and enforces a trusted kernel maximum on both lease and identity walks. This is a validation resource-safety bound, not a mission agent-spawn or topology feature. Renewal preserves the prior certificate's exact semantic-context digest; it cannot serve as a semantic-context reauthorization path.

## Data ownership

| Data | Owner in the design | R0-R2 status |
| --- | --- | --- |
| `AgentSpec` | Untrusted proposal | Typed request; signing credentials remain host-side |
| `SemanticContext` | Trusted resolver | Canonical digest excludes metadata-only `context_version` |
| `AgentIdentityCertificate` / `KeyCustody` | Trusted authority path | Signed identity; in-memory custody with redacted debug output |
| `AuthorityLeaseCertificate` | Trusted authority path | Immutable signed parent/renewal and policy binding |
| `LeaseRecord` | Trusted mutable state | Generation-checked lifecycle; in-memory only |
| `CapabilityManifest` / `BoundTool` | Trusted registry/authority path | Full atomic binding and subset attenuation exercised |
| `CanonicalAction` / `ActionRef` | Trusted canonicalizer | Typed/canonical contract evidence at R0 |
| `AuthorizationRecord` | Trusted authorization path | In-memory R1 consumption state only |
| `EffectRecord` | Future transaction/reconciliation path | Typed state model only; no external exactly-once claim |
| `MissionEvent` | Evidence plane | In-memory completeness checks for exercised paths only |

## Evidence boundary

R0 tests establish properties of the represented types and canonicalization functions for test inputs. R1 tests execute one scripted agent and a fixture WASM tool through the real pinned Nexus dependency, plus fixed rejection branches. R2 tests exercise in-memory signed identity/lease chains, bounded attenuation, lifecycle transitions, full-manifest drift, same-context renewal, evidence-access failures, and deterministic pre-commit race schedules.

This is not evidence of durable state, crash recovery, tamper evidence, external-effect reconciliation, generalized policy completeness, multi-agent scheduling/isolation, or coalition behavior. Revocation is linearized at the final authorization-consumption step and does not interrupt a Nexus call already past that point. Those broader surfaces require later roadmap stages and separate evidence.

## Roadmap boundary

R0 supplies architecture/types, R1 supplies the single-agent vertical slice, and R2 supplies the in-memory authority lifecycle. R3 begins durable storage. No later-stage feature should be inferred from a type that anticipates it. See [BUILD_PLAN.md](BUILD_PLAN.md) for the R0-R18 stage boundary.
