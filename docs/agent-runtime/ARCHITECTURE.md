# Genesis Runtime Architecture

## Scope and status

This document describes the standalone `genesis-runtime` workspace. It separates
three things that are easy to conflate, and the separation is load-bearing:

<!-- markdownlint-disable MD013 -->

| Marker | Meaning |
| --- | --- |
| **[R0–R2]** | Implemented and tested in this workspace. Evidence exists and is named. |
| **[TARGET]** | Designed here, not implemented. No security property may be inferred from it. |
| **[OPEN]** | Known gap with no design committed. Recorded so its absence is visible. |

<!-- markdownlint-enable MD013 -->

The normative baseline is [AEON Protocol v1.4](AEON_PROTOCOL_V1_4.md), preserved
byte-for-byte. This document is explanatory and does not amend it. Where the
architecture has outgrown the baseline, the delta is recorded in
[§10 Specification amendment queue](#10-specification-amendment-queue) rather
than silently applied.

R0 and R1 are complete. R2 is **complete, merged, accepted, and post-merge
hardened**. R3 has not started.

**Current evidence state.** Measured against merged implementation commit
`836a13020dead1ef0844a98ef149bf4d45f94b62`: 97 tests passing, 0 failed, across
the workspace at `--all-targets --locked`; 85.61% line coverage, 85.38% region
coverage; `cargo fmt --all -- --check` clean; locked workspace check clean;
`cargo clippy --workspace --all-targets --locked -- -D warnings` clean; and
13/13 pinned Nexus regressions (`integrated_path`, `capability_enforcement`).
These numbers must be re-measured and re-pinned at any implementation commit
that is published.

---

## 1. The one architectural commitment

Everything below follows from a single decision:

> **Authority is derived from an immutable mission envelope, never from position
> in the organization graph.**

If authority were topological — "this agent may do X because it is the root" —
then every reorganization would be a potential privilege escalation, and a
planner that can rewrite the graph could rewrite its own permissions. Deriving
authority from an immutable root instead makes topology security-irrelevant, and
lets the planner be as dynamic as it likes.

The corollary is what makes the system distinctive, and it is an **R3 design
objective**, not a property R0–R2 already possesses universally: authority
decisions and consequential commit transitions should *produce or reference*
cryptographically verifiable enforcement artifacts, so that evidence is derived
from enforcement rather than reconstructed from an observer log. R2 signs
identities, leases, and action certificates and records in-memory events; it does
not yet emit a signed artifact for every check, and the event stream is not yet
durable. §8 is where this objective is discharged.

---

## 2. Trust boundary

**Untrusted.** The model-facing strategy side. It proposes an `AgentSpec`,
requests capabilities and tools, supplies tool arguments, and emits a closed
typed protocol message. It receives no Nexus capability token, no WASM bytes, no
mutable lease state, and no authority-ledger mutation access. It may be
compromised, adversarial, or simply wrong.

Agents are host-side logical workers and state machines; they are not
persistent WASM sandboxes. Nexus remains the sole execution kernel. **[R0–R2]**

**Trusted.** The host runtime: context resolution, typed-output validation,
in-memory key custody, the authority ledger, the tool registry, canonicalization,
and policy inputs.

**Trusted, external.** Nexus at pinned revision
`c4343883cc4bd1f1262f2f878ed81f8015cedd0e` (default features disabled) is the
sole execution kernel. There is no AEON-native fallback executor. This absence is
the mechanism: complete mediation is structural, not conventional.

**Enforced by the type system.** `mod execution` is crate-private and
`ActionGate::authorize` is `pub(crate)`. Execution consumes an
`AuthorizedExecution`, which no untrusted path can construct. Mediation therefore
holds by construction rather than by review discipline. **[R0–R2]**

---

## 3. Request path

```text
MissionEnvelope + AgentSpec
          |
          v
trusted ContextResolver ------------------> reject: no trusted generation
          |                                  registry for memory/retrieval
          v
scripted model response (untrusted bytes)
          |
          v
ProtocolGate ------------------------------> reject: malformed, unknown field,
          |                                  unknown variant, oversize
          v
PlanGate -> ActionGate / AuthorityKernel --> reject: mission bounds, chain,
          |                                  attenuation, Capability::All,
          |                                  manifest digest, semantic context
          v
+---------------------------------------+
|  AUTHORIZATION COMMIT SECTION         |   <-- guard held
|  1. revalidate full live chain        | --> reject: stale generation,
|     signatures, generations, expiry,  |     revocation, epoch drift
|     org version, policy epoch,        |
|     semantic digest, atomic registry  |
|     manifest snapshot                 |
|  2. mint per-call Nexus token         |
|  3. consume single-use authorization  |
+---------------------------------------+
          |                                  <-- guard released
          v
pinned Nexus async execution (fresh hypervisor per call)
          |
          v
execution result
```

Every rejection branch is covered by a named test.

---

## 4. The authorization commit section

This is the core mechanism and the part most worth understanding.

Authorization and execution are separated in time, so a check-once design admits
a time-of-check-to-time-of-use race. Between approval and effect, a lease may be
revoked, a policy epoch may advance, a tool may be substituted, or a semantic
resource may change. The runtime therefore treats freshness as part of the
execution transaction, not as a property of an already-issued certificate.

Final chain revalidation, per-call token issuance, and single-use authorization
consumption are **linearized under one authority guard**. Control-plane
transitions that change authority — revoke, pause, expire, renew — linearize
against the same guard. The guard is released before the asynchronous WASM call,
and each execution uses a fresh hypervisor so bearer-token state does not survive
the call and snapshot identifiers are not reusable across calls. **[R0–R2]**

**The resulting guarantee, stated so it can be falsified:**

- A revocation linearizing **before** the section: execution refused, no token
  issued.
- A revocation linearizing **after** the section but before Nexus entry does not
  invalidate the consumed authorization, and it governs all subsequent calls.
  Fail-closed `AuthorizationConsumed` or `ExecutionStarted` evidence-append
  failures may still prevent Nexus entry.
- Once Nexus execution begins, a later revocation does not cancel that in-flight
  execution and governs all subsequent calls.

The post-commit guarantees are negative results and are deliberately not
softened into "eventual" revocation. Holding the guard across WASM execution
would make revocation cancel in-flight work, at the cost of serializing every
execution in a mission behind the slowest tool call and making one hung tool a
mission-wide denial of service. The shorter region is chosen and the consequence
is stated.

After the protected commit, `AuthorizationConsumed` evidence is appended before
`ExecutionStarted` and before Nexus entry. If the consumption-evidence append
fails, the authorization remains consumed and non-replayable, fresh Nexus state
is discarded, Nexus is not entered, and completeness continues to expose the
missing audit evidence. If `ExecutionStarted` evidence fails after consumption
was recorded, the attempt terminates as `ExecutionRejectedBeforeNexus`; Nexus is
still not entered and that distinct terminal history is complete. **[R0–R2]**

**Writer-acquisition residual.** The standard library documents that
[`std::sync::RwLock`](https://doc.rust-lang.org/std/sync/struct.RwLock.html) does
not guarantee a particular priority policy. Under adversarial/highly concurrent
reader admission, `std::sync::RwLock` does not provide a bounded control-plane
writer acquisition guarantee. R2 preserves correct revoke-vs-commit
linearization but does not claim bounded revocation latency under arbitrary
concurrent admission. Deterministic reader/writer admission, writer-starvation
prevention, bounded control-plane writer acquisition under documented limits,
and adversarial concurrent revoke/commit tests are R6 requirements. The R2 lock
and commit cutpoint are not moved to mask this liveness residual.

**Bounded chains.** `MAX_AUTHORITY_CHAIN_DEPTH = 32`, inclusive, rejected before
insertion — an unbounded delegation chain is a resource-exhaustion vector against
the monitor itself even when every link attenuates correctly. **[R0–R2]**

---

## 5. Data ownership

<!-- markdownlint-disable MD013 -->

| Data | Owner | Status |
| --- | --- | --- |
| `AgentSpec` | Untrusted proposal | Typed request; signing credentials host-side **[R0–R2]** |
| `SemanticContext` | Trusted resolver | Canonical digest excludes metadata-only `context_version` **[R0–R2]** |
| `AgentIdentityCertificate` / `KeyCustody` | Trusted authority path | Signed identity; in-memory custody, redacted `Debug` **[R0–R2]** |
| `AuthorityLeaseCertificate` | Trusted authority path | Immutable; binds subject, issuer, exact parent/renewal predecessor, mission, org version, policy epoch, semantic context, full manifest **[R0–R2]** |
| `LeaseRecord` | Trusted mutable state | Generation-checked lifecycle; in-memory **[R0–R2]** |
| `CapabilityManifest` / `BoundTool` | Trusted registry | Atomic snapshot binding; duplicate tools rejected at canonicalization **[R0–R2]** |
| `CanonicalAction` / `ActionRef` | Trusted canonicalizer | Domain-separated canonical identity **[R0–R2]** |
| `AuthorizationRecord` | Trusted authorization path | Single-use consumption, in-memory **[R0–R2]** |
| `MissionEvent` / `AuthorityEvent` | Evidence plane | Fallible emission, in-memory completeness checks **[R0–R2]** |
| `EffectRecord` | Transaction path | Type model only; no external exactly-once claim **[R0–R2 types, TARGET behavior]** |
| `CompatibilityReceipt` | Trusted context path | **[TARGET]** — §6 |
| `ResourceBudgetLedger` | Trusted authorization path | **[TARGET]** — §7 |
| `ActionEvidenceChain` through `ExecutionReceipt` | Evidence plane | **[TARGET]** — R3 / §8 |
| Full transactional `EffectCertificate` chain | Evidence plane | **[TARGET]** — R10 |

<!-- markdownlint-enable MD013 -->

---

## 6. Authorization-relative semantic compatibility calculus **[TARGET]**

**The problem.** T11 is currently binary: digests match or the continuation is
refused. Any material change to the model manifest, instruction, tool registry
root, protocol schema, or policy epoch forces full re-evaluation. For a workflow
that runs for hours or days across a fleet whose registry is updated
continuously, "refuse on any change" degrades to "refuse constantly," and the
practical response is to disable the check — which is worse than not having it.

The `context_version` exclusion already in the implementation is the seed of the
answer: it proves that some context deltas are provably immaterial to a given
authorization. Generalize it.

**The design.** Define a partial order over semantic contexts and a relation
`compatible_for(Σ, Σ′, A)` — context `Σ′` is a safe continuation of `Σ` for
authorization class `A`. Proposed relation classes, weakest to strongest:

<!-- markdownlint-disable MD013 -->

| Class | Rule | Safe for |
| --- | --- | --- |
| `Identical` | `H(Σ) = H(Σ′)` | everything (today's behavior) |
| `MetadataOnly` | only non-identity fields differ | everything **[R0–R2]** |
| `MonotoneRegistryExtension` | tools added; none removed, mutated, or re-digested; **and no added tool is visible to this agent's bound interface** | any `A` not referencing a changed tool |
| `CertifiedModelEquivalence` | model substituted within an equivalence class signed by a trusted equivalence authority | any `A` whose effect class tolerates it |
| `InstructionRefinement` | instruction change proved strictly narrowing | any `A` |
| `Incompatible` | otherwise | nothing — re-authorize |

<!-- markdownlint-enable MD013 -->

Compatibility is **not** transitively assumed: `Σ→Σ′` and `Σ′→Σ″` compatible does
not imply `Σ→Σ″`. Each transition is evaluated against the originally bound
context, so drift cannot accumulate through a chain of individually small steps.

`MonotoneRegistryExtension` carries a subtle trap. If the model can observe the
global tool registry, then *adding* a tool changes what the model sees even when
the eventual action never invokes it — the semantic context has materially
changed. The class is therefore safe only when the added tools are not visible to
the agent's bound interface, in addition to the originally bound tools being
unchanged. This is why compatibility must be judged across the whole observable
context, not only the resource an action eventually uses.

**The receipt.** Each accepted transition emits a signed `CompatibilityReceipt`
binding `(H(Σ), H(Σ′), class, authorization_class, timestamp, policy_epoch)`. A
signature alone only proves what the runtime *claimed*; for genuine third-party
verification the receipt must carry evidence the auditor can *recompute*. For the
deterministic classes that means the receipt includes, or points to, the inputs
that let an offline verifier re-derive the result: identity-field comparison for
`MetadataOnly`; both manifest commitments for `MonotoneRegistryExtension`; the
actual narrowing proof for `InstructionRefinement`; and the signed equivalence
certification for `CertifiedModelEquivalence`. Without that, a receipt is evidence
of a runtime assertion, not verification of compatibility.

**Boundaries.** `InstructionRefinement` requires proving a natural-language
instruction is strictly narrowing — that is a research problem, and the honest
initial position is to support it only for structured instruction fragments and
refuse otherwise. `CertifiedModelEquivalence` requires a trusted authority to
sign the behavioral-equivalence relation between two models for an authorization
class — note that runtime *attestation* proves only which model artifact was
loaded, not that two models are behaviorally equivalent, so the two must not be
conflated. Without such an equivalence authority the class is unusable and must
fail closed.

**Related work to differentiate against.** SemIso names the anomaly classes.
ContextNest (arXiv:2607.02116) addresses verifiable context governance and
source-node lifecycle. Neither supplies a compatibility relation that gates
*authorization continuation*. That is the open ground.

---

## 7. Resource-scoped coalition budgets **[TARGET]**

**The problem.** The per-agent induction bounds `⋃ Eff(aᵢ)`. It says nothing
about `Eff(Handoffs(S))`. Two consequences, and they need different mechanisms:

1. *Informational.* A reads payroll, hands to B, B emails externally. Each stays
   in envelope; the composition exfiltrates. Labels address this.
2. *Quantitative.* Two agents each authorized to move `x` jointly move `2x`.
   Every per-agent check passes. **Labels do not address this at all** — they
   bound information flow, not the arithmetic of authorized effects.

Aggregate multi-agent budgets are *not* new: Agent Contracts (arXiv:2601.08815)
already formalizes conservation laws ensuring delegated budgets sum within parent
constraints across hierarchical delegation, and practitioner literature names the
quantitative case as "cross-dimensional leakage." The proposed differentiation
is enforcing ResourceScope accounting as a security mechanism at the authority
commit boundary with **canonical resource identity across heterogeneous tools**
— so the budget cannot be bypassed by reaching the same resource through a
differently named tool. That, not aggregate budgeting per se, is the defensible
research position.

**The design.** Move the budget from the principal to the **resource**. Today
`AuthorizationRecord` enforces single-use consumption per `ActionRef`. Extend the
ledger with budgets scoped to the mission's `ResourceScope`:

```text
consume(action_ref, resource_scope, quantity)
  -> Ok  if  Σ consumed(resource_scope) + quantity ≤ budget(resource_scope)
  -> Err otherwise
```

Consumption reuses **the existing commit section** as its linearization point,
reducing the new concurrency surface. R8 must still establish shared-ledger
atomicity, canonical `ResourceScope` identity across heterogeneous tools, budget
conservation, authority/budget interaction, no double-spend under R6
parallelism, and adversarial concurrent behavior.

**Gated declassification.** Declassification is normally a trusted-code escape
hatch. Here it becomes a first-class authorized effect: it consumes a budgeted
authorization, emits a signed receipt naming the labels crossed and the
authorizing principal, and is refused when the declassification budget is
exhausted. A coalition can therefore be permitted to declassify *some* bounded
volume, with every instance individually accountable.

**[OPEN]** Resource identity across heterogeneous tools. "The same bank account"
reached through two different tools must resolve to one `ResourceScope` or the
budget is trivially bypassed. This is the hard part and it has no committed
design.

---

## 8. Verifiable action-evidence chain **[TARGET]**

**The problem.** The target is evidence a **third party can verify without
trusting the live runtime that produced it**. The regulatory and standards work
makes this relevant, but it does not establish that Genesis is a high-risk AI
system or compliant with any law. [Article 12 of Regulation (EU)
2024/1689](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689)
requires high-risk AI systems to technically allow automatic event logging over
their lifetime, supporting purpose-appropriate traceability; it does not mandate
this cryptographic evidence design. The [European Commission's current AI Act
timeline](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
states that the Act became generally applicable on 2 August 2026, the final AI
Omnibus entered into force on 27 July 2026, Annex III / Article 6(2) high-risk
rules apply from 2 December 2027, and Article 6(1) product-integrated rules apply
from 2 August 2028. The relevant logging standards remain under development:
[ISO/IEC FDIS 24970](https://www.iso.org/standard/88723.html) is at approval stage
50.00, and [prEN 18229-1:2026](https://www.dinmedia.de/en/draft-standard/din-en-18229-1/402825863)
is published by DIN as a draft standard. These facts are motivation and
preparation context, not a compliance claim or hard deadline for this roadmap.

**The design.** Every authorized execution produces an evidence chain verifiable
offline:

```text
MissionEnvelope (principal-signed)
  └─> AgentIdentityCertificate (issuer-signed)
      └─> AuthorityLeaseCertificate (parent-signed, transitively attenuated)
          └─> ActionCertificate (canonical action + bindings)
              └─> CompatibilityReceipt(s)      [if continuation occurred]
              └─> BudgetConsumptionReceipt     [if budgeted resource touched]
                  └─> ExecutionReceipt (tool digest, Nexus revision, outcome)
```

The target API is a standalone
`verify_action_evidence_chain(chain, trust_roots) -> Verdict` that links against
no live runtime state, so an auditor, regulator, or counterparty can reproduce the
verdict independently. This API does not exist in R0–R2.

Offline verification also requires R3 to choose and freeze a **versioned
canonical verification representation**. Artifact classes must remain
appropriately domain-separated; deterministic cross-language verification vectors
must be published; ambiguous or noncanonical encodings must be rejected; and
version/migration semantics must be explicit. R0–R2 already use domain-separated
canonical identities for their current artifacts. RFC 8785/JCS may be evaluated
as a candidate for the future cross-language representation, but is not selected
by this document and existing identity/domain strings are not changed here.

Chain heads are committed to a Merkle transparency structure. As specified for
Certificate Transparency in [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html),
an inclusion proof establishes membership relative to a selected signed tree
head, while a consistency proof establishes append-only consistency between
checkpoints. Global omission or split-view resistance additionally requires
monitoring, witnesses, checkpoint gossip, or external commitments. A Merkle
structure by itself does not prove that nothing was omitted.

**Stage boundary.** What R3 delivers is this chain through `ExecutionReceipt` —
an `ActionEvidenceChain` covering authority, identity, delegation, canonical
action, and the execution result. It deliberately stops there. The transactional
receipts for *external* effects — commit-decision, effect-release, effect-outcome,
and compensation — belong to staged external effects (§10 / roadmap R10) and only
then extend this into a full `EffectCertificate` chain. R3 must not claim
external-effect semantics it does not yet implement.

**Why the design is positioned differently from observer-only logging:** the
current runtime already creates signed grants as enforcement artifacts. R3's
research objective is to preserve and extend those artifacts into independently
verifiable evidence rather than reconstruct permission solely from an observer
log. This is a proposed differentiation, not a universal claim about every audit
product or runtime.

**[OPEN]** Key rotation and revocation of *issuer* keys across a chain that must
remain verifiable years later. In-memory custody (§2) caps this: chains are only
as strong as the host that held the keys.

---

## 9. Kernel compartmentalization / TCB reduction **[TARGET]**

The authority kernel is small, deterministic, and performs no I/O — which makes
it a candidate to run as a restricted WASM component, isolated from other
untrusted guest logic with a narrowed import and capability surface. This reduces
accidental coupling, shrinks the trusted computing base, and gives a future model
check a real component boundary to verify.

**What this does not do.** It does **not** remove the hostile-host assumption.
WebAssembly's isolation model protects the *host* from an untrusted *guest*; it
does not protect a guest from a malicious or compromised host embedding the
runtime. A compromised host can alter the kernel's inputs, ignore or fake its
decision, replace the module, bypass it entirely, or steal host-held secrets.
Running the kernel in WASM therefore narrows the TCB but leaves the host inside
it.

**[OPEN]** Genuine host-compromise resistance requires a stronger boundary —
hardware-backed confidential computing (a TEE) with remote attestation, or another
independently trusted execution environment. Key custody inside any such boundary
has its own exposure, and the host still schedules the kernel. This section should
never be described as removing the host-compromise ceiling; it lowers the TCB,
and the TEE path is a separate, later commitment.

## 10. Specification amendment queue

Items where the architecture has outgrown [AEON Protocol v1.4](AEON_PROTOCOL_V1_4.md).
None are applied unilaterally.

1. **T4, T5, T10 are unlabeled in the baseline.** The repository does not invent
   definitions. Until an authoritative source defines them, the underlying
   properties are carried as *named properties* — single-use consumption,
   authorization/effect separation — not as numbered invariants.
2. **Bounded chain depth** (§4) is enforced but has no baseline label.
3. **Compatibility classes** (§6) would amend the T11 v1 rule of exact digest
   equality. Requires baseline approval; must not be applied by editorial choice.
4. **Resource-scoped budgets** (§7) introduce an authorization dimension the
   baseline data model does not carry.
5. **Action evidence chain** (§8) extends provenance from the event stream to an
   offline-verifiable `ActionEvidenceChain` through `ExecutionReceipt` in R3;
   R10 later extends it with full transactional `EffectCertificate` semantics.

---

## 11. Evidence boundary

R0 establishes properties of represented types and canonicalization for test
inputs. R1 executes one scripted agent and a fixture WASM tool through the real
pinned Nexus dependency plus fixed rejection branches. R2 exercises in-memory
signed identity/lease chains, transitive attenuation, lifecycle transitions,
full-manifest drift, bounded depth, poisoned-ledger cases, and deterministic race
cases including a blocked revoke at the consumed-under-read-lock cutpoint.

The accepted post-merge R2 hardening also bounds and validates untrusted
`AgentSpec` collections and steps, rejects `Capability::All` during validation
and deserialization, validates bounded `ActionTarget` values, preserves
`AuthoritySet` invariants, contracts production/test-only APIs, builds context
and manifests from atomic registry snapshots, rejects fail-open schemas, supports
tool-free renewal, requires manifest-version attenuation, mechanically binds the
closed protocol wire shape to its schema identity, separates issuer-signature
convenience checks from trust decisions, makes security/evidence accessors fail
closed, preserves consumed/non-replayable evidence-failure semantics, and makes
authority traversal and event ordering deterministic. These are R2 properties,
not R3 features.

This is **not** evidence of durable state, crash recovery, tamper evidence,
external-effect reconciliation, generalized policy completeness, multi-agent
scheduling or isolation, or coalition behavior. Revocation is linearized at the
final authorization-consumption step and does not interrupt a Nexus call already
past that point.

**The standing limitation.** All authority state, authorization records, and
evidence are in memory and lost on process loss. A reference monitor whose ledger
does not survive a crash is a demonstration of a monitor. R3 is where that
changes, and no durability claim may be made before it lands.
