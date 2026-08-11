
# AEON PROTOCOL v1.4 — FINAL OFFICIAL PRE-CODEX SPECIFICATION
## Architecture Locked — Final Data-Model Corrections Applied

---

## EXECUTIVE SUMMARY

This specification is the **final architecture and data-model baseline** for the AEON Agent Runtime before Codex begins implementation. It incorporates the final audit corrections without changing the core product thesis or AEON/Genesis/Nexus responsibility split.

**Implementation status:** approved to begin **R0 + R1 only**, then STOP for validation.

**Final corrections applied in v1.4:**
1. one source of truth for requested model/tools;
2. immutable signed lease certificate separated from mutable lease state;
3. T11 uses a stable canonical semantic-context digest rather than a freshly incremented version;
4. malformed protocol output is rejected before ActionGate;
5. post-R14 wording distinguishes TLA+ model checking from implementation proof.

The architecture remains verification-oriented. No property is described as formally verified until the corresponding model/check has actually been run and recorded.

---

## 1. THE 5 IMPLEMENTATION CONSTRAINTS

### CONSTRAINT 1: Trusted Runtime Creates SemanticContext — Single Source of Truth

**Problem:** the prior model duplicated requested model/tools between `AgentSpec` and `SemanticRequirements`, creating contradictory inputs. The authoritative semantic context also must be resolved from actual runtime resources, not from model-supplied aliases.

**Fix:**

```rust
// UNTRUSTED PROPOSAL — Strategy Plane
struct AgentSpec {
    role: Role,
    objective: Objective,

    // Single source of truth for requested execution resources.
    requested_model: ModelRef,
    requested_tools: Vec<ToolId>,
    requested_authority: AuthorityRequest,

    output_contract: Contract,
    resource_budget: ResourceRequest,

    // Only semantic resources not already represented above.
    semantic_requirements: SemanticRequirements,
}

struct SemanticRequirements {
    requested_memory: Option<MemoryRef>,
    requested_retrieval_index: Option<RetrievalIndexRef>,
    requested_instruction_profile: Option<InstructionProfileRef>,
}

// TRUSTED RESOLUTION — Control Plane / Authority Kernel
struct ContextResolver;

impl ContextResolver {
    fn resolve(
        &self,
        spec: &AgentSpec,
    ) -> Result<SemanticContext, ContextResolutionError> {
        let model_manifest = self.model_registry.resolve(&spec.requested_model)?;

        let bound_tools = self.tool_registry.resolve_all(&spec.requested_tools)?;
        let tool_registry_root = self.tool_registry.root_digest()?;

        // IMPORTANT: hash the final resolved instruction actually supplied to
        // this agent, after trusted templates/role/objective/profile resolution.
        let resolved_instruction = self.instruction_registry.resolve_for(spec)?;
        let resolved_instruction_digest = hash_canonical(&resolved_instruction);

        let protocol_schema_digest = self.protocol_registry.current_digest()?;
        let policy_epoch = self.policy_engine.current_epoch();

        let memory_generation = spec.semantic_requirements.requested_memory
            .as_ref()
            .map(|m| self.memory_registry.generation(m))
            .transpose()?;

        let retrieval_index_generation = spec.semantic_requirements.requested_retrieval_index
            .as_ref()
            .map(|i| self.retrieval_registry.generation(i))
            .transpose()?;

        Ok(SemanticContext {
            // Metadata only; NOT part of semantic identity.
            context_version: self.next_version(),
            model_manifest_digest: model_manifest.canonical_digest(),
            resolved_system_instruction_digest: resolved_instruction_digest,
            tool_registry_root_digest: tool_registry_root,
            bound_tool_digests: bound_tools.into_iter().map(|t| t.manifest_digest).collect(),
            protocol_schema_digest,
            policy_epoch,
            memory_generation,
            retrieval_index_generation,
        })
    }
}
```

**Rules:**
- `AgentSpec` contains one request for model and tools; there is no duplicate alias in `SemanticRequirements`.
- The model proposes requirements. The trusted runtime resolves the actual resources.
- The final resolved instruction digest is agent-specific.
- `context_version` is metadata only and must not be used as T11 semantic identity.

---

### CONSTRAINT 2: CapabilityManifest Binds Tool Digests

**Problem:** `approved_tools: Vec<ToolId>` only hashes IDs. If "repo.write" 
changes implementation, the capability doesn't invalidate.

**Fix:**

```rust
struct CapabilityManifest {
    version: u8,

    model_manifest_digest: Digest,

    // CHANGED: Vec<ToolId> → Vec<BoundTool>
    approved_tools: Vec<BoundTool>,

    permissions: PermissionSet,
    runtime_config_digest: Digest,

    tool_registry_root_digest: Digest,
}

struct BoundTool {
    tool_id: ToolId,
    tool_manifest_digest: Digest,  // ← binds implementation
}

impl CapabilityManifest {
    fn canonical_digest(&self) -> Digest {
        // Deterministic canonical serialization
        let mut tools = self.approved_tools.clone();
        tools.sort_by(|a, b| a.tool_id.cmp(&b.tool_id));

        hash_canonical(&CanonicalCapabilityManifest {
            version: self.version,
            model_manifest_digest: self.model_manifest_digest,
            approved_tools: tools,
            permissions: self.permissions.clone(),
            runtime_config_digest: self.runtime_config_digest,
            tool_registry_root_digest: self.tool_registry_root_digest,
        })
    }
}
```

**Rule:** Changing a tool's implementation changes its digest, which changes 
the capability manifest digest, which invalidates the lease. Forces 
reauthorization.

---

### CONSTRAINT 3: Remove Mutable consumed_uses from ActionCertificate

**Problem:** `consumed_uses` changes during execution but is signed into the 
certificate. That's ledger state, not stable certificate identity.

**Fix:**

```rust
struct ActionCertificate {
    certificate_id: CertificateId,
    mission_id: MissionId,

    agent_identity_digest: Digest,
    authority_lease_id: LeaseId,

    organization_version: u64,
    policy_epoch: u64,
    semantic_context_digest: Digest,

    action_ref: ActionRef,

    tool_id: ToolId,
    tool_manifest_digest: Digest,

    concrete_input_digest: Digest,

    authorization_record_id: AuthorizationId,
    granted_uses: u32,

    // REMOVED: consumed_uses
    // ADDED: generation for optimistic concurrency
    authorization_generation: u64,

    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,

    signature: Signature,
}

// Execution flow:
// certificate
//     ↓
// AuthorityKernel queries AuthorizationRecord
//     ↓
// Check: still active? remaining budget > 0? same policy/org/context?
//     ↓
// Atomic compare-and-swap on generation
//     ↓
// Execute
```

**Rule:** The durable ledger owns consumption. The certificate is immutable 
once issued. CapLease supports this separation between authorization object 
and durable monotonic consumption state.

---

### CONSTRAINT 4: R1 Gets Minimal Manifest Binding; R2 Gets Full Authority

**Problem:** R1 checklist says "manifest mismatch → reject T8" but R2 is 
"Authority + capability-manifest identity." Overlap.

**Fix:**

```
R0  Architecture + types
    └── All core structs, typed protocol, unit tests

R1  Single-agent secure vertical slice
    ├── One agent, one tool, one mission
    ├── Minimal manifest binding:
    │   └── authorized tool digest == executed tool digest
    │       (enough to prove T8 for one tool)
    ├── Test: valid proposal → executes
    ├── Test: invalid proposal → rejected at ActionGate
    ├── Test: over-authorized → rejected at AuthorityKernel
    ├── Test: manifest mismatch → rejected
    ├── Test: semantic drift → rejected at T11
    └── GOAL: Prove the security boundary works for one agent

    THEN STOP. Validate.

R2  FULL AUTHORITY LIFECYCLE + DELEGATION
    ├── Immutable AuthorityLeaseCertificate + mutable LeaseRecord semantics
    ├── Parent/child delegation attenuation (T2)
    ├── Revocation
    ├── Expiration
    ├── Lease renewal
    ├── Agent cryptographic identity
    ├── Full CapabilityManifest binding (Constraint 2)
    └── Bearer-token non-persistence

R3  Durable MissionStore
    ├── Crash durability
    ├── Tamper-evident history
    ├── Atomic state/event persistence
    └── Recovery provenance

R4  Real model + typed protocol
R5  Dynamic Agent Synthesis (first "Genesis" capability)
...
```

**R1 scope:** Enough to prove the security boundary for one agent with one 
tool. Minimal but complete vertical slice.

**R2 scope:** Full authority lifecycle with delegation, revocation, and 
capability-manifest binding.

---

### CONSTRAINT 5: R1 Uses InMemoryMissionStore

**Problem:** R1 checklist says "Evidence Plane records all transitions" but 
durable MissionStore doesn't arrive until R3.

**Fix:**

```rust
// R1: In-memory only
struct InMemoryMissionStore {
    events: Vec<MissionEvent>,
    auth_records: HashMap<AuthorizationId, AuthorizationRecord>,
}

impl InMemoryMissionStore {
    fn append(&mut self, event: MissionEvent) {
        self.events.push(event);
    }

    fn verify_event_completeness(&self) -> Result<(), MissingEvents> {
        // Check that every trusted transition generated an event
        // But does NOT prove crash durability or tamper evidence
        Ok(())
    }
}

// R3: Durable, tamper-evident, crash-safe
struct DurableMissionStore {
    // Hash-linked event chain
    // Atomic DB transactions
    // External witness anchoring
}
```

**R1 claim:** "Event completeness in the in-memory vertical slice."

**NOT:** "Durable provenance closure" (that's R3/R11).

---

## 2. DOCUMENTATION FIX

**Before:**
> "Authority remains mission-bounded, composition-safe, transactionally 
> consumed, completely mediated, crash-stable, semantically consistent, and 
> cryptographically reconstructible."

**After:**
> "AEON is designed so that authority remains mission-bounded, 
> composition-safe, transactionally consumed, completely mediated, 
> crash-stable, semantically consistent, and cryptographically 
> reconstructible."

**Rationale:** Before TLA+ model checking (R14), these are design targets, 
not proven properties. SentinelAgent can say "mechanically checked" because 
an actual TLA+ model was run. We have not reached that stage yet.

---

## 3. EDITORIAL FIX

**Before:** "all 5 remaining corrections"

**After:** "all 6 remaining corrections" (Constraints 1–5 + documentation fix)

---

## 4. COMPLETE CORRECTED DATA MODEL

### AgentSpec (Untrusted Proposal)

```rust
struct AgentSpec {
    role: Role,
    objective: Objective,

    // Single source of truth.
    requested_model: ModelRef,
    requested_tools: Vec<ToolId>,
    requested_authority: AuthorityRequest,

    output_contract: Contract,
    resource_budget: ResourceRequest,
    semantic_requirements: SemanticRequirements,
}

struct SemanticRequirements {
    requested_memory: Option<MemoryRef>,
    requested_retrieval_index: Option<RetrievalIndexRef>,
    requested_instruction_profile: Option<InstructionProfileRef>,
}
```

### AgentRuntimeRecord (Trusted State)

```rust
struct AgentRuntimeRecord {
    spec_digest: Digest,
    identity: AgentIdentity,
    lease_id: LeaseId,
    lifecycle: AgentLifecycle,
    current_step: u64,

    semantic_context: SemanticContext,
    semantic_context_digest: Digest,
}

enum AgentLifecycle {
    Proposed,
    Authorized,
    Active,
    Paused,
    Revoked,
    Terminated,
    Compromised,
}
```

### SemanticContext (Trusted, Resolved)

```rust
struct SemanticContext {
    // Audit/ordering metadata only. Excluded from canonical semantic identity.
    context_version: u64,

    model_manifest_digest: Digest,
    resolved_system_instruction_digest: Digest,
    tool_registry_root_digest: Digest,
    bound_tool_digests: Vec<Digest>,
    protocol_schema_digest: Digest,
    policy_epoch: u64,
    memory_generation: Option<Digest>,
    retrieval_index_generation: Option<Digest>,
}

impl SemanticContext {
    fn canonical_digest(&self) -> Digest {
        let mut tool_digests = self.bound_tool_digests.clone();
        tool_digests.sort();

        // `context_version` is deliberately excluded so re-resolution of the
        // exact same semantic resources yields the same identity.
        hash_canonical(&CanonicalSemanticContext {
            model_manifest_digest: self.model_manifest_digest.clone(),
            resolved_system_instruction_digest: self.resolved_system_instruction_digest.clone(),
            tool_registry_root_digest: self.tool_registry_root_digest.clone(),
            bound_tool_digests: tool_digests,
            protocol_schema_digest: self.protocol_schema_digest.clone(),
            policy_epoch: self.policy_epoch,
            memory_generation: self.memory_generation.clone(),
            retrieval_index_generation: self.retrieval_index_generation.clone(),
        })
    }
}

enum ContextTransition {
    Exact,
    Compatible(CompatibilityEvidence),    // v2+ only
    Revalidated(RevalidationReceipt),     // v2+ only
}

fn validate_context_continuation(
    original_digest: &Digest,
    current: &SemanticContext,
) -> Result<ContextTransition, ContextViolation> {
    if original_digest == &current.canonical_digest() {
        Ok(ContextTransition::Exact)
    } else {
        Err(ContextViolation::SemanticContextChanged)
    }
}
```

**T11 v1 rule:** exact canonical semantic-context digest equality. A changed `context_version` alone must not fail T11. Any material model, final instruction, bound tool, protocol, policy, memory-generation, or retrieval-generation change does fail T11 and requires re-evaluation.

### Authority Lease Certificate (Immutable, Signed)

```rust
struct AuthorityLeaseCertificate {
    lease_id: LeaseId,
    mission_id: MissionId,
    agent_id: AgentId,
    parent_agent_id: Option<AgentId>,

    organization_version: u64,
    policy_epoch: u64,

    granted_authority: AuthoritySet,
    delegable_authority: AuthoritySet,

    capability_manifest_digest: Digest,
    semantic_context_digest: Digest,

    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,

    signature: Signature,
}
```

### LeaseRecord (Mutable Runtime/Ledger State)

```rust
struct LeaseRecord {
    lease_id: LeaseId,
    state: LeaseState,
    generation: u64,
    revoked_at: Option<DateTime<Utc>>,
    revocation_reason: Option<RevocationReason>,
}

struct LeaseRef {
    lease_id: LeaseId,
    certificate_digest: Digest,
}
```

**Rule:** lease revocation/retirement is mutable ledger state. It does not mutate or re-sign the original certificate. Runtime authorization checks both the immutable certificate and the current `LeaseRecord`.

### CapabilityManifest

```rust
struct CapabilityManifest {
    version: u8,
    model_manifest_digest: Digest,
    approved_tools: Vec<BoundTool>,
    permissions: PermissionSet,
    runtime_config_digest: Digest,
    tool_registry_root_digest: Digest,
}

struct BoundTool {
    tool_id: ToolId,
    tool_manifest_digest: Digest,
}
```

All set-like fields must be deterministically ordered before canonical serialization/hashing.

### CanonicalAction + ActionRef (Semantic Identity)

```rust
struct CanonicalAction {
    mission_id: MissionId,
    effect_kind: EffectKind,
    target: CanonicalResource,
    normalized_parameters: CanonicalJson,
    semantic_scope: SemanticScope,
}

struct ActionRef(Digest);
```

`ActionRef` identifies the logical real-world effect and must remain stable across retries, replacement agents, and alternative execution adapters when the trusted canonicalizer determines the effect is semantically the same.

### ExecutionBinding (Concrete Execution Context)

```rust
struct ExecutionBinding {
    action_ref: ActionRef,
    agent_id: AgentId,
    tool_id: ToolId,
    tool_manifest_digest: Digest,
    organization_version: u64,
    policy_epoch: u64,
    semantic_context_digest: Digest,
    concrete_input_digest: Digest,
}
```

### AuthorizationRecord (Mutable Authorization Ledger)

```rust
struct AuthorizationRecord {
    record_id: AuthorizationId,
    action_ref: ActionRef,
    authority_chain: Vec<LeaseRef>,
    total_budget: Budget,
    remaining_budget: Budget,
    state: AuthorizationState,
    stable_idempotency_key: IdempotencyKey,
    effect_class: EffectClass,
    generation: u64,
}

enum AuthorizationState {
    Issued,
    Prepared,
    Consumed,
    Aborted,
    Revoked,
    Expired,
}
```

### EffectRecord (Physical-World State)

```rust
struct EffectRecord {
    action_ref: ActionRef,
    authorization_id: AuthorizationId,
    state: EffectState,
    reconciliation_required: bool,
    escalation_target: Option<Principal>,
}

enum EffectState {
    None,
    Staged,
    CommitDecided,
    Released,
    Confirmed,
    UnknownOutcome,
    Aborted,
    Compensated,
}
```

**Critical rule:** `AuthorizationState::Consumed` + `EffectState::UnknownOutcome` means reconcile/escalate. Never blind-retry a non-idempotent uncertain external effect.

### ActionCertificate (Immutable)

```rust
struct ActionCertificate {
    certificate_id: CertificateId,
    mission_id: MissionId,
    agent_identity_digest: Digest,
    authority_lease_id: LeaseId,
    organization_version: u64,
    policy_epoch: u64,
    semantic_context_digest: Digest,
    action_ref: ActionRef,
    tool_id: ToolId,
    tool_manifest_digest: Digest,
    concrete_input_digest: Digest,
    authorization_record_id: AuthorizationId,
    granted_uses: u32,
    authorization_generation: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    signature: Signature,
}
```

The certificate is immutable. Before execution, the trusted kernel re-reads the current `AuthorizationRecord` and performs an atomic generation/state/budget check.

### MemoryEntry (Trust-Classified)

```rust
struct MemoryEntry {
    content: Vec<u8>,
    checksum: Hash,
    confidentiality: SecurityLevel,
    integrity: SecurityLevel,
    source_agent: AgentId,
    source_identity_digest: Digest,
    created_at: DateTime<Utc>,
    trust_class: MemoryTrust,
    ttl_seconds: u32,
    expires_at: DateTime<Utc>,
    semantic_context_digest: Digest,
}

enum MemoryTrust {
    Untrusted,
    Advisory,
    SourceVerified,
    SystemAttested,
}
```

**Universal rule:** memory may influence Strategy Plane reasoning. It cannot directly mutate the MissionEnvelope, lease certificate/record, ToolRegistry, policy epoch, authorization consumption, or commit state.

---

## 5. R0 + R1 IMPLEMENTATION CHECKLIST

### R0: Architecture + Types

- [ ] Define `AgentSpec` (single-source `requested_model`/`requested_tools`; no lifecycle)
- [ ] Define `AgentRuntimeRecord` (with lifecycle, semantic_context)
- [ ] Define `SemanticRequirements`, trusted `SemanticContext`, and canonical semantic-context digest (T11)
- [ ] Define `ContextResolver` (trusted runtime resolution)
- [ ] Define immutable `AuthorityLeaseCertificate`, mutable `LeaseRecord`, and `LeaseRef`
- [ ] Define `CapabilityManifest` (with `Vec<BoundTool>`)
- [ ] Define `CanonicalAction` + `ActionRef`
- [ ] Define `ExecutionBinding`
- [ ] Define `AuthorizationRecord` (with `AuthorizationState`)
- [ ] Define `EffectRecord` (with `EffectState::UnknownOutcome`)
- [ ] Define `ActionCertificate` (no `consumed_uses`, has `authorization_generation`)
- [ ] Define `MemoryEntry` (with `MemoryTrust`)
- [ ] Define typed protocol for tool calls
- [ ] Unit tests for all types + serialization

### R1: Single-Agent Secure Vertical Slice

- [ ] Implement `ContextResolver` (resolves AgentSpec requests → actual resources → canonical SemanticContext digest)
- [ ] Implement Strategy Plane (mock LLM output)
- [ ] Implement Control Plane (PlanGate stub)
- [ ] Implement AuthorityKernel (issues immutable lease certificate + in-memory LeaseRecord; minimal manifest binding)
- [ ] Implement ActionGate (mediation, checks digest equality)
- [ ] Integrate Nexus (one WASM tool)
- [ ] Implement `InMemoryMissionStore` (event completeness, not durability)
- [ ] Test: Valid proposal → executes
- [ ] Test: Malformed/raw invalid model output → rejected by ProtocolGate before ActionGate; zero ActionGate calls; zero Nexus execution
- [ ] Test: Well-formed but unauthorized ToolCallProposal → rejected by ActionGate/AuthorityKernel; zero Nexus execution
- [ ] Test: Over-authorized → rejected at AuthorityKernel
- [ ] Test: Manifest mismatch → rejected (T8, minimal)
- [ ] Test: Same resolved semantic resources with a different metadata `context_version` → accepted as exact T11 identity
- [ ] Test: Actual semantic context change → rejected (T11)
- [ ] Test: Event completeness in in-memory store

**GOAL:** Prove the security boundary works for one agent with one tool.

**THEN STOP. Validate before R2.**

---

## 6. FINAL THESIS

> **AEON is designed so that authority remains mission-bounded, 
> composition-safe, transactionally consumed, completely mediated, 
> crash-stable, semantically consistent, and cryptographically 
> reconstructible.**

After R14 (TLA+ model checking), use only a scoped statement such as:

> **The TLA+ model mechanically checked the specified AEON invariants over the configured reachable state space with the recorded model/configuration. Implementation conformance and cryptographic correctness are tested and evidenced separately.**

Do not claim that TLA+ model checking alone proves the Rust implementation or every system property.

---

## 7. ARCHITECTURE DIAGRAM (Final)

```
                         HUMAN PRINCIPAL
                              │
                       MissionEnvelope
                              │
                              ▼
══════════════════════ UNTRUSTED ══════════════════════

                       STRATEGY PLANE
               ┌────────────────────────┐
               │ Mission decomposer     │
               │ Agent synthesizer      │
               │ Replanner              │
               │ Self-modification      │
               │   proposer (R17)       │
               │ Repair proposer (R16)  │
               └───────────┬────────────┘
                           │
              ┌────────────┴────────────┐
              │  AgentSpec               │
              │  - role, objective       │
              │  - requested_tools       │
              │  - requested_authority   │
              │  - requested_model       │
              │  - contract              │
              │  - semantic_requirements │ ← extra semantic-resource requests
              └─────────────────────────┘

════════════════════ TRUST BOUNDARY ════════════════════
                           ▼
                     CONTROL PLANE
                 ┌───────────────────┐
                 │ ContextResolver   │ ← resolves actual resources
                 │ PlanGate          │
                 │ OrganizationGraph │
                 │ Scheduler         │
                 │ CircuitBreaker    │
                 │ EmergencyStop     │
                 └─────────┬─────────┘
                           │
              ┌────────────┴────────────┐
              │  AgentRuntimeRecord      │
              │  - spec_digest           │
              │  - identity              │
              │  - lease_id              │
              │  - lifecycle             │
              │  - semantic_context      │ ← authoritative, resolved
              └─────────────────────────┘
                           │
                           ▼
                    AUTHORITY KERNEL
                 ┌───────────────────┐
                 │ Mission bounds    │ ← T1
                 │ Identity / Leases │ ← T2, T6, T9
                 │ Capability manifest│ ← T8
                 │ IFC / MAC labels  │ ← T7
                 │ Policy epochs     │ ← T9
                 │ Semantic context  │ ← T11
                 │ ActionGate        │ ← T3
                 └─────────┬─────────┘
                           │
                           ▼
                  TRANSACTION MANAGER
                 ┌───────────────────┐
                 │ ActionRef         │ ← canonical identity
                 │ ExecutionBinding  │ ← concrete context
                 │ AuthorizationState│ ← durable ledger
                 │ EffectState       │ ← physical world
                 │ Prepare           │
                 │ Validate          │
                 │ Commit / Abort    │
                 └─────────┬─────────┘
                           │
                           ▼
                 NEXUS EXECUTION PORT
                           │
                           ▼
                         NEXUS
             Wasmtime / capabilities / snapshot
                           │
                           ▼
                    EFFECT ADAPTERS
                           │
                           ▼
                      REAL SYSTEMS

                MISSIONSTORE / EVIDENCE
                  R1: InMemoryMissionStore
                  R3: DurableMissionStore
                  cross-cutting event chain

                       AEON-IQ MEMORY
              advisory semantic context only
              cannot change authority/policy
```

---

## STATUS: FINAL OFFICIAL PRE-CODEX BASELINE

Architecture locked.
Final data-model corrections applied.
R0 + R1 scope locked.
The next architecture review should occur only if R0/R1 implementation evidence exposes a concrete contradiction.

**Approved for Codex R0 + R1 implementation only. Then STOP.**
