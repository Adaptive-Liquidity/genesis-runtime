# R0-R2 Threat Model

## Scope

This threat model covers the standalone R0–R2 `genesis-runtime`: one mission, one scripted executing agent, in-memory delegated identity/lease chains, one successful fixture tool path, host-side gates, the pinned Nexus execution kernel, and in-memory evidence. It records later target threats so their absence is visible, but it does not claim controls that belong to R3–R13.

## Assets

- Mission tool and capability bounds.
- Trusted semantic-context identity.
- Tool implementation identity and registry root.
- Lease/certificate identity and mutable authorization state.
- Agent signing keys, issuer bindings, and lease generations.
- Nexus capability tokens and WASM modules.
- The ordering and completeness of in-process mission and authority events.

## Trust assumptions

- Model output, proposed roles/objectives, tool arguments, and requested authority are untrusted.
- The host runtime, its in-memory key custody/authority ledger, registries, canonicalization code, policy inputs, and process memory are trusted for the fixture.
- Nexus revision `c4343883cc4bd1f1262f2f878ed81f8015cedd0e` is the sole kernel trusted to enforce the issued capability token during WASM execution.
- Cargo/Git dependency retrieval, the Rust toolchain, operating system, and build host are supply-chain assumptions outside the test model.
- The in-memory event store is lost on process loss and is not a tamper-evident witness.

## Threats and present handling

| ID | Threat target from the baseline | R0-R2 handling | Residual exposure |
| --- | --- | --- | --- |
| T1 | Escape from mission bounds | Reject tool/capability requests outside fixed mission allowlists | Policy completeness and broader resource namespaces are unverified |
| T2 | Identity/delegation authority expansion | Verify signed issuer/subject identity, exact signed parents, generations, expiry, and bounded transitive capability/tool attenuation | In-memory trust anchor; no coalition analysis or distributed identity federation |
| T3 | Bypass of complete mediation | Closed protocol and ActionGate/AuthorityKernel precede the only Nexus execution port | Future adapters and paths must independently preserve mediation |
| T4 | Unspecified in supplied v1.4 baseline | No control claimed under this identifier | Authoritative definition is required |
| T5 | Unspecified in supplied v1.4 baseline | No control claimed under this identifier | Authoritative definition is required |
| T6 | Lease/identity/revocation failure | Separate immutable certificates and mutable records; generation-checked pause/resume/expiry/cascading revocation/renewal; final live pre-token check | No persistence/distributed propagation; an in-flight call past commit is not cancelled |
| T7 | Information-flow/MAC violation | Model-facing token/WASM exclusion is checked in the fixed trace | Full labels, IFC propagation, memory policy, and covert channels are not addressed |
| T8 | Tool implementation substitution | Atomic registry snapshot binds model, tools, permissions, runtime configuration, and registry root at gate and commit | Registry compromise and cross-process consistency are not covered |
| T9 | Stale organization or policy authority | Signed version/epoch bindings are rechecked across the full live chain | No distributed freshness or durable epoch history |
| T10 | Unspecified in supplied v1.4 baseline | No control claimed under this identifier | Authoritative definition is required |
| T11 | Semantic drift across continuation | Exact canonical digest equality; metadata-only version changes do not alter identity; renewal cannot rebind changed context | No v2 compatibility/revalidation receipts or long-running continuation evidence |

## Cross-cutting abuse cases

### Malformed or smuggled model output

The closed protocol rejects malformed JSON, unknown variants, missing fields, unknown fields, and oversized output before ActionGate. Remaining risks include parser/library defects, denial of service within accepted size limits, and future schema changes.

### Capability escalation

The runtime rejects `Capability::All`, capabilities outside mission authority, and transitive delegation expansion. This does not establish that every future Nexus capability or path mapping is least privilege.

### Key compromise and certificate forgery

Signing keys remain behind an in-memory custody interface and are omitted from serialization and debug output. Lease and identity signatures bind exact issuer key identifiers. Host-process or memory compromise can still steal keys or rewrite the in-memory trust state; hardware/external custody and rotation are not implemented.

### Revocation race and bearer-token lifetime

Final full-chain/generation/manifest/context validation, synchronous token issuance, and authorization consumption share one authority guard as the R2 commit section. A revocation before that section rejects execution. A revocation after it controls future calls but does not cancel the already-started call. The guard is not held across asynchronous WASM execution. Each execution uses a fresh Nexus hypervisor, so token state is dropped after the call and snapshot identifiers cannot be reused across calls.

The final registry snapshot freezes the selected registered implementation for that call, and the semantic-context digest is sampled inside the protected commit section. Mutations before those final samples reject; mutations after their linearization points apply to future calls while the captured call may complete. Deterministic race tests exercise both revoke-first and commit-first schedules.

### Authority-chain resource exhaustion

Cycle detection alone does not bound valid acyclic chains. R2 therefore rejects lease and identity chains beyond the trusted kernel maximum. The bound limits validation work and does not implement mission topology, scheduling, or Genesis synthesis.

### Secret or executable-material disclosure

The tested model trace excludes issued Nexus tokens and WASM bytes. Process compromise, logs added outside the tested trace, debugging facilities, crash dumps, and future integrations remain outside this evidence.

### Replay, crash, and uncertain external effects

R2 state is in memory. There is no durable replay ledger, atomic crash recovery, exactly-once guarantee, or external-effect reconciliation. A type representing `UnknownOutcome` is a design boundary, not an implementation of recovery. Non-idempotent uncertain effects must not be assumed safe to retry.

### Multi-agent collusion

The authority-kernel tests cover delegation graphs, but the runtime still executes one agent and supplies no evidence about scheduler isolation, collusion, or coalition authority. Those claims are explicitly out of scope.

## Required follow-on work

R3 must add crash-safe durable authority plus offline-verifiable action/execution evidence before durability or third-party-verification claims. R6 must add multi-agent scheduling, emergency control, and bounded writer admission; R8 must add resource-scoped coalition budgets; R9 must add IFC/MAC, AEON-IQ memory, and gated declassification; and R10 must add staged external effects, reconciliation, compensation, and the full transactional effect-certificate extension. R13 may add a scoped TLA+ model-check result, while implementation conformance and cryptographic correctness remain separately tested. See [BUILD_PLAN.md](BUILD_PLAN.md).
