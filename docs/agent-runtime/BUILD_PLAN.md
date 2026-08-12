# Build Plan

<!-- markdownlint-disable MD013 -->

## Stage control

R0–R2 are complete. The control point is: **complete the evidence, validate, and
stop before the next stage.** A later stage is a target, not an implemented
feature, and never an inherited security claim.

This plan replaces the previous R0–R18 sequence. That sequence optimized for
**completeness** — sixteen stages, each a feature, all treated as equally
necessary. Finishing all of it would produce a thorough system that is still, at
its core, capability systems applied to agents. This plan optimizes for **depth**:
three tracks selected as proposed research and product differentiators, and an
explicit list of what was cut to pay for them.

Old-stage disposition is in [§Disposition](#disposition-of-the-previous-r0r18-plan)
so nothing silently disappears.

---

## Status

| Stage | Target | Status |
| --- | --- | --- |
| R0 | Architecture and core types | **Complete** — contract/type evidence |
| R1 | Single-agent secure vertical slice | **Complete** — one-agent/one-tool evidence through pinned Nexus |
| R2 | Full authority lifecycle and delegation | **Complete / merged / accepted / post-merge hardened** — in-memory identity, chain, lifecycle, bounded depth, race and poison evidence |
| R3 | Durable authority + offline-verifiable action/execution evidence | Next — not started |
| R4 | Real model integration and protocol hardening | Not active |
| **R5** | **Authorization-relative semantic compatibility calculus** | Not active — **Track A** |
| R6 | Multi-agent runtime, scheduler isolation, circuit breaker, emergency interrupt | Not active |
| R7 | Dynamic agent synthesis | Not active — thesis demonstration |
| **R8** | **Resource-scoped coalition budgets** | Not active — **Track B** |
| R9 | IFC/MAC labels, AEON-IQ memory, gated declassification | Not active |
| R10 | Transactional staged effects | Not active |
| R11 | Kernel compartmentalization / TCB reduction | Not active |
| R12 | Adversarial benchmark suite | Not active |
| R13 | Scoped TLA+ model check | Not active |

**Current measured state.** Measured against merged implementation commit
`836a13020dead1ef0844a98ef149bf4d45f94b62`: 97 tests passing, 0 failed
(`--workspace --all-targets --locked`); 85.61% line / 85.38% region coverage;
`fmt`, locked workspace check, and `clippy -D warnings` clean; 13/13 pinned Nexus
regressions. R3 has not started. Re-measure and re-pin at any published
implementation commit.

---

## R0–R2 acceptance evidence (complete)

**R0.** Single-source model/tool requests in `AgentSpec`; typed identifiers and
strict serialization; deterministic domain-separated canonical digests; semantic
context identity excluding metadata-only `context_version`; bound tool-manifest
identity; immutable certificates separated from mutable records; distinct
authorization and effect state; closed size-bounded output protocol.

**R1.** Resolve one agent's model, instruction profile, and fixture tool into
trusted semantic context; accept scripted model bytes only through `ProtocolGate`;
apply plan, mission, authority, capability, manifest, and context checks; issue a
scoped token only at the execution boundary; execute only through pinned Nexus;
record in-memory event completeness; exercise rejection branches before Nexus;
confirm the model-facing trace contains neither tokens nor WASM bytes.

**R2.** Signed identities bound to issuer and key identifiers without exposing
signing material; every immutable lease bound to subject, issuer, exact
parent/renewal predecessor, mission, org version, policy epoch, semantic context,
and full manifest; transitive capability and tool attenuation with
`Capability::All` rejected; generation-checked pause, resume, expiry, cascading
revocation, immutable renewal; revalidation of every generation, signature,
context, and atomic manifest snapshot immediately before token issuance; final
validation, token issuance, and single-use consumption under one guard as the
commit section; fresh Nexus hypervisor per execution; `MAX_AUTHORITY_CHAIN_DEPTH`
of 32 inclusive, rejected before insertion; duplicate-manifest rejection at
canonicalization; fallible authority events; poisoned-ledger and deterministic
race coverage including a blocked revoke at the consumed-under-read-lock cutpoint.
The accepted post-merge hardening additionally bounds untrusted `AgentSpec`
collections and steps; rejects `Capability::All` during validation and
deserialization; validates bounded `ActionTarget` values; preserves
`AuthoritySet` invariants; contracts production/test-only surfaces; derives
context and manifests from one atomic registry snapshot; rejects fail-open
schemas; supports tool-free renewal; requires manifest-version attenuation;
mechanically couples protocol-schema identity to the closed accepted wire shape;
separates issuer-signature checks from trust decisions; makes security/evidence
accessors fail closed; preserves consumed/non-replayable authorization semantics
when consumption evidence cannot be appended; represents a later
`ExecutionStarted` evidence failure as a complete pre-Nexus rejection; and makes
authority traversal and event ordering deterministic.

Validation command:

```bash
cargo fmt --all -- --check
cargo check --workspace --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo llvm-cov --workspace --all-targets --locked \
  --fail-under-lines 85 --fail-under-regions 85
```

R2 is merged and accepted. This roadmap does not require or create a tag before
R3; any future release/tag policy remains a separate repository decision.

---

## R3 — Durable authority and offline-verifiable action/execution evidence

Merges the old R3 (durable store) and R11 (evidence/proof system). They were
never separable: durable storage without verifiability is a database, and
verifiability without durability is a demo.

**Acceptance evidence:**

1. Crash-safe atomic persistence of authority state, authorization records, and
   the event chain, with recovery provenance.
2. Recovery non-expansion and committed-reduction preservation: recovery
   reconstructs the exact last durably committed lifecycle state; a revoked,
   paused, expired, or renewal-retired lease cannot reappear active, and
   reconstructed authority remains bounded by the pre-crash ceiling. Tested by
   fault injection at every persistent authority, authorization, and evidence
   transition and its state/evidence boundaries, including issuance/delegation,
   renewal, pause/resume, revocation and cascading revocation, expiry,
   authorization issuance/consumption, and execution commit cutpoints; not by
   inspection.
3. An offline-verifiable `ActionEvidenceChain` through `ExecutionReceipt`,
   binding mission, identity, lease/delegation, canonical action, authorization,
   tool/Nexus identity, and execution outcome.
4. A target standalone API such as
   `verify_action_evidence_chain(chain, trust_roots) -> Verdict`, linking against
   no live runtime state. If the verdict requires the runtime that produced the
   chain, it is not third-party verification.
5. A chosen and frozen versioned canonical verification representation,
   appropriate artifact-class domain separation, deterministic cross-language
   verification vectors, rejection of ambiguous/noncanonical encodings, and
   explicit version/migration semantics. RFC 8785/JCS may be evaluated but is not
   selected in advance.
6. Transparency/checkpoint structure with precise assumptions: inclusion proves
   membership relative to a signed checkpoint; consistency proves append-only
   consistency between checkpoints; global omission/split-view resistance also
   requires monitoring, witnesses, checkpoint gossip, or external commitments.
7. Adversarial evidence and fault-injection tests: truncated or reordered
   history, forged intermediate certificate, dropped action/execution evidence,
   noncanonical encoding, recovery at each commit cutpoint, and checkpoint fork.

**Stop gate.** Do not claim tamper-evidence until an external witness exists.
An append-only structure the same process can rewrite is not tamper-evident.

**Does not claim:** distributed consensus, long-term key rotation, exactly-once
external effects, effect release/reconciliation, compensation, or the full
transactional `EffectCertificate` chain. Those external-effect semantics remain
in R10.

---

## R4 — Real model integration and protocol hardening

Replace the scripted model with a real one behind the same `ProtocolGate`. The
security surface is unchanged by design; the point is to demonstrate that.

**Acceptance evidence:** the full R0–R2 rejection suite passes unmodified against
live model output; protocol violations under real generation are rejected at the
same point; output size bounds hold under adversarial prompting.

---

## R5 — Authorization-relative semantic compatibility calculus  ·  **TRACK A**

The strongest research contribution available, and the one that generalizes past
this runtime. Full design in ARCHITECTURE §6.

**Acceptance evidence:**

1. `compatible_for(Σ, Σ′, A)` implemented for `Identical`, `MetadataOnly`, and
   `MonotoneRegistryExtension`. These three are decidable and testable now.
2. Non-transitivity enforced and tested: `Σ→Σ′` and `Σ′→Σ″` compatible must not
   imply `Σ→Σ″`. Evaluation is always against the originally bound context.
3. Signed `CompatibilityReceipt` per accepted transition, verifiable offline.
4. `InstructionRefinement` and `CertifiedModelEquivalence` **fail closed** until
   a proof procedure and an explicit trusted equivalence policy/certification
   authority respectively exist for the relevant authorization scope. Model
   attestation may identify an artifact; it does not prove behavioral
   equivalence. Shipping either class as permissive is a security regression, not
   a feature.
5. Adversarial suite: registry extension that removes a tool while appearing to
   add one; re-digested tool under an unchanged identifier; drift accumulated
   through a chain of individually compatible steps.

**Stop gate.** This amends the baseline T11 rule (ARCHITECTURE §10 item 3) and
requires protocol-owner approval before landing.

---

## R6 — Multi-agent runtime, scheduler isolation, circuit breaker, emergency interrupt

The authority kernel already validates delegation graphs; the runtime still
executes one agent. That gap is where the interesting bugs live.

**Acceptance evidence:** concurrent execution of multiple leased agents under one
mission; scheduler isolation evidence; deterministic `CircuitBreaker` limits
derived from the mission envelope (active agents, spawn depth, concurrency, tool
calls, retries, reorganizations, token/monetary budget, wall-clock); each limit
check and its corresponding reservation or consumption share one atomic admission
linearization point, with concurrent boundary tests proving no mission-level
oversubscription; fail-closed `CircuitOpen` preserving evidence state; concurrent
revocation under real parallelism, not simulated interleaving.
`EmergencyInterrupt` is carried forward from the old R10 explicitly: once an
emergency stop is durably committed, no new authority consumption, task
scheduling, or external-effect release proceeds — without falsely promising
cancellation of a Nexus call already past the commit point
([Architecture §4](ARCHITECTURE.md#4-the-authorization-commit-section)). The
protected authorization commit is the linearization point: later revocation
cannot retroactively invalidate the committed authorization consumption;
fail-closed failures after commit may still prevent Nexus entry; once Nexus
execution begins, later revocation does not cancel that in-flight execution; and
later calls are governed by the revocation.

The stage must also define deterministic reader/writer admission. Once
revoke/pause/emergency writer intent is pending, an unlimited stream of new
execution commits cannot starve it. Under the documented concurrency limit,
control-plane writer acquisition is bounded; revoke-first rejects, commit-first
permits only the already-linearized execution, and later executions reject.
Deterministic adversarial stress tests must cover those schedules. R2 preserves
the current commit linearization but does not claim bounded writer acquisition
under arbitrary reader admission.

**Does not claim:** coalition safety. That is R8/R9.

---

## R7 — Dynamic agent synthesis

The thesis says arbitrary runtime reorganization cannot expand authority. Until
agents are actually synthesized at runtime, that claim is untested against the
case it was designed for. This stage is a **demonstration**, not a research
contribution — and it should be cheap, because R2 already did the hard part.

**Acceptance evidence:** planner-proposed agents synthesized, delegated to,
retired, and reorganized at runtime under load, with the full T1/T2 suite green
throughout; a red-team attempt to escalate through synthesis, reported with
whatever got through.

---

## R8 — Resource-scoped coalition budgets  ·  **TRACK B**

The quantitative half of composition safety — the half labels structurally cannot
reach. Full design in ARCHITECTURE §7. Aggregate delegated budgets are not novel
(Agent Contracts, arXiv:2601.08815, formalizes conservation laws for them); the
contribution here is enforcing them at the authority commit boundary with
canonical resource identity across heterogeneous tools.

**Acceptance evidence:**

1. `ResourceBudgetLedger` with consumption scoped to `ResourceScope`, enforced
   inside the existing commit section and reusing the protected
   authorization-commit linearization point. R8 must independently establish
   shared-ledger atomicity, budget conservation, and authority/budget interaction.
2. The canonical test: two agents, each individually authorized to move `x`,
   jointly refused at `2x` when the resource budget is `x`. Every per-agent check
   passes; the aggregate is refused.
3. Resource identity across heterogeneous tools — the same account reached
   through two tools resolves to one scope. **This is the hard part and has no
   committed design.** Do not start R8 until it does.
4. Concurrent consumption under R6 parallelism without double-spend.

---

## R9 — IFC/MAC labels, AEON-IQ memory integration, and gated declassification

The informational half. Confidentiality × integrity labels on runtime objects;
labels carried across handoffs; sinks check labels.

**The novel part is declassification**, not the lattice: declassification
consumes a budgeted authorization and emits a signed receipt naming labels
crossed and authorizing principal. A trusted escape hatch becomes an accountable,
bounded, evidenced operation.

**AEON-IQ memory integration** lands here rather than vanishing from the roadmap.
Memory is advisory by design and must never directly mutate mission, authority,
registry, policy, or consumption state; integrating it means memory provenance,
confidentiality/integrity labels on retrieved entries, semantic-generation
binding so stale memory cannot re-authorize, and cross-session poisoning defenses.
If AEON-IQ is not integrated at this stage it is explicitly **deferred**, not
silently dropped.

**Does not claim:** covert-channel elimination or a full noninterference result.
Noninterference is a relational hyperproperty — it constrains pairs of executions,
not single traces — and is not established by label-carrying mechanisms alone.

---

## R10 — Transactional staged effects

Effect classification in the trusted registry (never model output); shadow state
for locally reversible effects; staged external effects and an effect outbox;
composed-flow validation before commit; explicit release, outcome recording, and
reconciliation; compensation for compensatable effects; and unknown-outcome
handling that never authorizes blind replay. R10 extends R3's
`ActionEvidenceChain` into the full transactional `EffectCertificate` chain with
commit-decision, effect-release, effect-outcome, reconciliation, and compensation
evidence.

The effect-release path must consult the same durable `EmergencyInterrupt` state
at its release linearization point. Integration tests must prove that an
interrupt-first race rejects release, a release-first race permits only the
already-linearized release, and every later release rejects after the committed
stop.

**Position honestly:** this is largely Cordon's contribution. Cite it, do not
re-present it as novel, and describe the delta — Cordon contains a task; this
system preserves authority across organizational mutation, and staged effects are
the piece it is missing rather than the piece it invented.

**Does not claim:** exactly-once external effects. `UnknownOutcome` requires
reconciliation or escalation; blind retry stays prohibited.

---

## R11 — Authority-kernel compartmentalization / TCB reduction

Run the authority kernel as a restricted WASM component, isolated from other
untrusted guest logic with a narrowed import and capability surface. This reduces
accidental coupling, shrinks the trusted computing base, and gives R13 a real
component boundary to verify.

**Acceptance evidence:** the kernel executes as an isolated component with no I/O;
other guest logic cannot forge or bypass its decisions *within the WASM boundary*;
measured overhead reported.

**Explicit non-claim.** This does **not** protect against a malicious or
compromised host. WebAssembly isolates the host from the guest, not the guest from
the host: a compromised host can alter inputs, fake or ignore the kernel's
decision, replace the module, bypass it, or steal host-held keys. Host-compromise
resistance is a *separate* commitment requiring hardware-backed confidential
computing (a TEE) plus remote attestation, and must not be claimed from WASM
isolation alone.

## R12 — Adversarial benchmark suite

The reviewed baseline did not identify an established benchmark focused on this
runtime's agent-authority threat surface. R12 therefore proposes publishing a
public benchmark intended to support comparable reports across runtimes. This is
a strategic research objective, not a universal claim that no adjacent benchmark
exists.

**Acceptance evidence:** a public harness of attack scenarios any agent runtime
must refuse, seeded from the existing suite and generalized past this
implementation; a reference report format; **at least one scenario this system
fails**, published. A benchmark its own author passes completely is a marketing
document, not a benchmark.

---

## R13 — Scoped TLA+ model check

Model the authority lattice, delegation, lifecycle, and the commit section.
Check the labeled baseline invariants over a configured state space.

**Wording constraint, non-negotiable:** "The model check mechanically verified the
specified invariants over the configured reachable state space with the recorded
model and configuration. Implementation conformance and cryptographic correctness
are tested and evidenced separately." Model checking alone never proves the Rust.

**What model checking can and cannot reach.** Ordinary safety invariants — no
effect released without authorization, authority bounded by the envelope,
delegation attenuated, a stale lease cannot commit, budget never exceeds its
limit, emergency stop blocks new commits — are trace properties: a single finite
bad trace violates them, so they are expressible as TLA+ state invariants. What is
*not* an ordinary trace property is noninterference-style information-flow security
(the informational half of composition, F5), which is relational — it compares
multiple executions — and is a genuine hyperproperty requiring appropriate
relational/hyperproperty methods rather than a plain invariant check. Do not
conflate the two: complete mediation is checkable here; noninterference is not.

---

## Disposition of the previous R0–R18 plan

| Old stage | Disposition |
| --- | --- |
| R0, R1, R2 | Kept, complete |
| R3 Durable MissionStore | **Merged** into new R3 with the evidence system |
| R4 Real model + typed protocol | Kept as R4 |
| R5 Dynamic Agent Synthesis | **Moved later** (R7) — demonstration, not contribution; needs R6 first |
| R6 Multi-agent runtime | Kept as R6, merged with circuit breaker |
| R7 Canonical actions and transactions | **Merged** into R10 |
| R8 Staged effects | **Merged** into R10 |
| R9 IFC and memory | **Split** — labels + AEON-IQ memory to R9, budgets promoted to R8 as a track |
| R10 Circuit breaker and emergency stop | **Merged** into R6 (circuit breaker *and* emergency interrupt) |
| R11 Evidence and proof system | **Merged** into new R3 and promoted |
| R12 Product and MCP surface | **Deferred** — distracts from the research contribution; revisit when there is something worth productizing |
| R13 Behavioral verification | **Deferred** — probabilistic, weak evidence, high cost |
| R14 TLA+ model checking | Kept as R13 |
| R15 Adversarial evaluation | Promoted to R12 and broadened to a public benchmark |
| R16 Repair | **Deferred indefinitely** — dilutes the story |
| R17 Self-modification | **Cut.** The flashiest item and the least defensible. It invites the skepticism that contaminates everything solid. Revisit only after R11 and R13. |
| R18 Constrained decoding | **Deferred indefinitely** — a model-side concern, not a runtime authority concern |

---

## Sequencing guidance

**R3 is prerequisite to everything.** Both remaining tracks need durable state,
and an in-memory reference monitor caps every claim the system can make.

**Then pick one track and go deep.** Three deep contributions is a team-year.
One deep contribution on the existing R0–R2 foundation is a real paper and a real
differentiator, and it beats sixteen boxes ticked.

| If the goal is | Take |
| --- | --- |
| The strongest paper | **R5** — Track A generalizes past this runtime and gets cited by people who never run it |
| The strongest system | **R8** — Track B targets heterogeneous resource identity at the authority commit boundary |
| The strongest commercial position | **R3** alone — third-party-verifiable evidence aligned with an active regulatory and standards-preparation period |

**Standing prohibitions.** Do not weaken a test threshold, CI recipe, or
benchmark bound to make a claim hold. Do not run timing-sensitive tests from
`/mnt/c`. Do not infer a later stage's property from a type that anticipates it.
Do not publish a number that was not measured at the commit being published.
