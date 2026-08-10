# Security Invariants and Evidence

## Reading this document

T1-T11 are architecture targets. The supplied v1.4 baseline explicitly labels only T1, T2, T3, T6, T7, T8, T9, and T11. It does not define the labels for T4, T5, or T10; this repository does not invent definitions for them.

R0/R1 evidence is limited to fixed one-agent/one-tool fixtures and the named rejection branches. “Exercised” below means a repository test addresses that subset; it does not mean the full target is proven.

## Target and evidence matrix

| ID | Baseline target | R0/R1 evidence | Current limitation |
| --- | --- | --- | --- |
| T1 | Mission bounds | Mission tool and capability allowlists are checked in fixed R1 cases | No generalized mission-policy proof or multi-agent coverage |
| T2 | Delegation/identity subset | Certificate and identity types exist; the R1 direct-agent path is typed | Parent/child delegation and attenuation begin at R2 and are not exercised |
| T3 | Complete mediation through ActionGate | Malformed, unknown-tool, disallowed-tool, and over-authorized fixtures stop before Nexus | Evidence covers the runtime's exposed R1 path, not every future effect adapter |
| T4 | Unspecified in the supplied baseline | None claimed | Definition and acceptance criteria require an authoritative source |
| T5 | Unspecified in the supplied baseline | None claimed | Definition and acceptance criteria require an authoritative source |
| T6 | Lease/identity/revocation subset | Immutable lease-certificate payload and mutable lease-state types are separated | Full revocation, expiry, renewal, and runtime race handling begin at R2 |
| T7 | IFC/MAC labels | None claimed | IFC/MAC implementation is scheduled for R9 |
| T8 | Tool/capability-manifest identity | A registered one-tool implementation substitution changes the manifest digest and is rejected before Nexus | This is minimal R1 binding, not the full manifest/authority lifecycle |
| T9 | Organization/policy freshness | Organization version and policy epoch are represented; policy drift participates in the tested T11 context digest | Full freshness/revocation behavior is not implemented or proven |
| T10 | Unspecified in the supplied baseline | None claimed | Definition and acceptance criteria require an authoritative source |
| T11 | Semantic-context continuity | Metadata-only `context_version` changes preserve identity; material context changes are rejected in fixed tests | Compatibility and revalidation modes are future work; v1 uses exact canonical digest equality |

## Additional R0/R1 rules

The following rules are represented and exercised without assigning them an undefined T-number:

- Model output must match the closed, size-bounded protocol before ActionGate.
- Unknown fields and malformed messages are rejected.
- `Capability::All` is rejected for the R1 mission/spec and registered tool paths.
- Model-facing request/trace structures do not contain Nexus bearer capability tokens or fixture WASM bytes in the tested path.
- Set-like inputs used for canonical identity are deterministically ordered.
- Canonical hash domains for tools, semantic contexts, and actions are separated.
- Mutable consumption/revocation state is not embedded in immutable certificate identity.
- `AuthorizationState` and physical `EffectState` are distinct types; their existence does not provide exactly-once execution.
- Memory is advisory by design and must not directly mutate mission, authority, registry, policy, consumption, or commit state; R1 does not implement the full memory/IFC system.

## Evidence interpretation

The evidence suite should be run with `cargo test --workspace --all-targets`. A passing run is necessary for an R0/R1 checkpoint but is not sufficient for a production or formal-verification claim.

No durability, crash-stability, tamper-evidence, exactly-once, coalition-safety, implementation-proof, or formal-verification claim is made. R14 is the roadmap stage for a scoped TLA+ model check; even that would not by itself prove Rust implementation conformance or cryptographic correctness.
