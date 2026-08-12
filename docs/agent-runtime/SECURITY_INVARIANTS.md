# Security Invariants and Evidence

<!-- markdownlint-disable MD013 -->

## Reading this document

T1-T11 are architecture targets. The supplied v1.4 baseline explicitly labels only T1, T2, T3, T6, T7, T8, T9, and T11. It does not define the labels for T4, T5, or T10; this repository does not invent definitions for them.

R0-R2 evidence is limited to fixed runtime fixtures, in-memory authority chains, and the named rejection branches. "Exercised" below means a repository test addresses that subset; it does not mean the full target is proven.

## Target and evidence matrix

| ID | Baseline target | R0-R2 evidence | Current limitation |
| --- | --- | --- | --- |
| T1 | Mission bounds | Mission tool and capability allowlists are checked in fixed runtime cases | No generalized mission-policy proof or multi-agent coverage |
| T2 | Delegation/identity subset | Signed identity and exact signed parent references are checked across bounded multi-level chains; capabilities and tool sets must attenuate transitively | Runtime scheduling still executes one agent; no coalition analysis or distributed trust anchor |
| T3 | Complete mediation through ActionGate | Malformed, unknown-tool, disallowed-tool, and over-authorized fixtures stop before Nexus | Evidence covers the runtime's exposed path, not every future effect adapter |
| T4 | Unspecified in the supplied baseline | None claimed | Definition and acceptance criteria require an authoritative source |
| T5 | Unspecified in the supplied baseline | None claimed | Definition and acceptance criteria require an authoritative source |
| T6 | Lease/identity/revocation subset | Immutable certificates and mutable generation-checked records support pause/resume, expiry, cascading revocation, and immutable renewal in memory | No durable/distributed propagation; calls past the commit point are not interrupted |
| T7 | IFC/MAC labels | None claimed | IFC/MAC implementation is scheduled for R9 |
| T8 | Tool/capability-manifest identity | Full model, tool, permission, runtime-config, and registry-root bindings are checked from one atomic registry snapshot at gate and commit | Registry and authority state are process-local |
| T9 | Organization/policy freshness | Organization version and policy epoch are signed into every lease and checked along the live chain | No distributed freshness or durable epoch history |
| T10 | Unspecified in the supplied baseline | None claimed | Definition and acceptance criteria require an authoritative source |
| T11 | Semantic-context continuity | Metadata-only `context_version` changes preserve identity; material context changes are rejected at execution and cannot be blessed by renewal | Compatibility and revalidation modes are future work; v1 uses exact canonical digest equality |

## Additional R0-R2 rules

The following rules are represented and exercised without assigning them an undefined T-number:

- Model output must match the closed, size-bounded protocol before ActionGate.
- Unknown fields and malformed messages are rejected.
- `Capability::All` is rejected in mission, agent, registry, and authority paths.
- Model-facing request/trace structures do not contain Nexus bearer capability tokens or fixture WASM bytes in the tested path.
- Set-like inputs used for canonical identity are deterministically ordered.
- Canonical hash domains for tools, semantic contexts, identities, leases, and actions are separated.
- Mutable consumption/revocation state is not embedded in immutable certificate identity.
- Key custody does not expose signing keys through serialization or debug output.
- A final live chain, generation, context, and manifest check, scoped token issuance, and authorization consumption share one authority guard; failures drop the fresh per-call Nexus hypervisor.
- Authority and identity validation enforce a fixed kernel chain-depth bound; this is separate from future agent-spawn topology.
- The authority-event and action-certificate evidence accessors remediated in R2 fail with `Internal` on poisoned locks rather than returning empty evidence.
- `AuthorizationState` and physical `EffectState` are distinct types; their existence does not provide exactly-once execution.
- Memory is advisory by design and must not directly mutate mission, authority, registry, policy, consumption, or commit state; R2 does not implement the full memory/IFC system.

## Evidence interpretation

The evidence suite should be run with `cargo test --workspace --all-targets --locked`. A passing run is necessary for an R0-R2 checkpoint but is not sufficient for a production or formal-verification claim.

No durability, crash-stability, tamper-evidence, exactly-once, distributed-revocation, coalition-safety, implementation-proof, or formal-verification claim is made. R13 is the roadmap stage for a scoped TLA+ model check; even that would not by itself prove Rust implementation conformance or cryptographic correctness.
