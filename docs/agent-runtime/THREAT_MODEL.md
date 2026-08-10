# R0/R1 Threat Model

## Scope

This threat model covers the standalone R0/R1 `genesis-runtime`: one mission, one scripted agent, one successful fixture tool path, host-side gates, the pinned Nexus execution kernel, and in-memory evidence. It records target threats beyond R1 so their absence is visible, but it does not claim controls that belong to R2-R18.

## Assets

- Mission tool and capability bounds.
- Trusted semantic-context identity.
- Tool implementation identity and registry root.
- Lease/certificate identity and mutable authorization state.
- Nexus capability tokens and WASM modules.
- The ordering and completeness of in-process mission events.

## Trust assumptions

- Model output, proposed roles/objectives, tool arguments, and requested authority are untrusted.
- The host runtime, its registries, canonicalization code, policy inputs, and process memory are trusted for the R1 fixture.
- Nexus revision `c4343883cc4bd1f1262f2f878ed81f8015cedd0e` is the sole kernel trusted to enforce the issued capability token during WASM execution.
- Cargo/Git dependency retrieval, the Rust toolchain, operating system, and build host are supply-chain assumptions outside the R1 test model.
- The in-memory event store is lost on process loss and is not a tamper-evident witness.

## Threats and present handling

| ID | Threat target from the baseline | R0/R1 handling | Residual exposure |
| --- | --- | --- | --- |
| T1 | Escape from mission bounds | Reject tool/capability requests outside fixed mission allowlists | Policy completeness and broader resource namespaces are unverified |
| T2 | Identity/delegation authority expansion | Typed agent/lease identity and a direct, non-delegating R1 path | No parent/child chain validation, attenuation, or coalition analysis |
| T3 | Bypass of complete mediation | Closed protocol and ActionGate/AuthorityKernel precede the only Nexus execution port | Future adapters and paths must independently preserve mediation |
| T4 | Unspecified in supplied v1.4 baseline | No control claimed under this identifier | Authoritative definition is required |
| T5 | Unspecified in supplied v1.4 baseline | No control claimed under this identifier | Authoritative definition is required |
| T6 | Lease/identity/revocation failure | Immutable certificate data is separated from mutable lease state | Revocation, expiry, renewal, persistence, and races are R2+ work |
| T7 | Information-flow/MAC violation | Model-facing token/WASM exclusion is checked in the fixed trace | Full labels, IFC propagation, memory policy, and covert channels are not addressed |
| T8 | Tool implementation substitution | Expected and current tool-manifest digests must match for the R1 fixture | Registry compromise, lifecycle-wide reauthorization, and broad tool sets are not covered |
| T9 | Stale organization or policy authority | Version/epoch fields bind context; tested policy-epoch drift is rejected through T11 | No distributed freshness, revocation propagation, or durable epoch history |
| T10 | Unspecified in supplied v1.4 baseline | No control claimed under this identifier | Authoritative definition is required |
| T11 | Semantic drift across continuation | Exact canonical digest equality; metadata-only version changes do not alter identity | No v2 compatibility/revalidation receipts or long-running continuation evidence |

## Cross-cutting abuse cases

### Malformed or smuggled model output

The closed protocol rejects malformed JSON, unknown variants, missing fields, unknown fields, and oversized output before ActionGate. Remaining risks include parser/library defects, denial of service within accepted size limits, and future schema changes.

### Capability escalation

The fixed R1 path rejects `Capability::All` and capabilities outside mission authority. This does not establish that every future Nexus capability or path mapping is least privilege.

### Secret or executable-material disclosure

The tested model trace excludes issued Nexus tokens and WASM bytes. Process compromise, logs added outside the tested trace, debugging facilities, crash dumps, and future integrations remain outside this evidence.

### Replay, crash, and uncertain external effects

R1 state is in memory. There is no durable replay ledger, atomic crash recovery, exactly-once guarantee, or external-effect reconciliation. A type representing `UnknownOutcome` is a design boundary, not an implementation of recovery. Non-idempotent uncertain effects must not be assumed safe to retry.

### Multi-agent collusion

R1 has one agent and therefore supplies no evidence about delegation graphs, scheduler isolation, collusion, or coalition authority. Those claims are explicitly out of scope.

## Required follow-on work

R2 must add and test the full authority lifecycle before delegation or revocation claims. R3 must add durable, crash-safe evidence before durability claims. R7-R9 must address action transactions, effects, IFC, and memory. R14 may add a scoped TLA+ model-check result, while implementation conformance remains separately tested. See [BUILD_PLAN.md](BUILD_PLAN.md).
