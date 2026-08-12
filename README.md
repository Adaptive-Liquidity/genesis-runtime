# AEON Genesis Runtime

`genesis-runtime` is a standalone Rust workspace for the host-side AEON agent runtime. It implements the R0 type/contracts foundation, the fixed R1 secure vertical slice, and the in-memory R2 authority lifecycle described by the [AEON Protocol v1.4 baseline](docs/agent-runtime/AEON_PROTOCOL_V1_4.md).

## Current scope

R0–R2 are complete, and R2 is merged, accepted, and post-merge hardened. The
authoritative roadmap now runs from R0 through R13; R3 has not started. The
implemented/tested surface remains deliberately narrow:

- one mission;
- one executing agent, with delegated identity/lease chains exercised at the authority-kernel boundary;
- one requested and registered fixture tool per successful run;
- scripted typed model output rather than a production model service;
- trusted protocol, plan, authority, and action gates in the host runtime;
- signed agent identities, attenuated authority chains, and in-memory pause, resume, expiry, revocation, and renewal;
- Nexus as the sole capability-enforcing WASM execution kernel; and
- an in-memory event store used to check event completeness for the exercised process lifetime.

The workspace pins Nexus by Git revision:

```toml
nexus = { git = "https://github.com/adaptiveliquidity/Nexus.git", rev = "c4343883cc4bd1f1262f2f878ed81f8015cedd0e", default-features = false }
```

AEON does not provide an alternate tool executor. The execution port issues scoped Nexus capability tokens only after final live authority revalidation and delegates WASM execution to that pinned kernel. R2 creates a fresh Nexus hypervisor for each call so bearer-token state is dropped when that call completes.

## Evidence

The repository's R0 contract tests cover typed serialization, canonical and domain-separated digests, immutable certificate versus mutable state separation, closed/size-bounded protocol parsing, and exact T11 semantic-context identity.

The R1 vertical-slice tests exercise a successful Nexus-backed fixture call and bounded rejection cases: malformed protocol output, unknown or mission-disallowed tools, authority excess, forbidden `Capability::All`, tool substitution, material semantic drift (T11), and model-facing token/WASM exclusion.

The R2 tests exercise signed identity and lease verification, bounded transitive
attenuation, bounded untrusted requests, atomic registry/context bindings,
full capability-manifest validation, generation-checked lifecycle transitions,
cascading revocation, same-context immutable renewal, fail-closed evidence paths,
live pre-token revalidation, and deterministic authorization race schedules.
These tests are evidence for those fixed fixtures and branches only; they are not
evidence for the complete T1–T11 target set or for production deployment.

Run the local evidence suite with:

```powershell
cargo test --workspace --all-targets --locked
```

## Explicit non-claims

This repository does **not** currently claim:

- durable, crash-safe, or tamper-evident storage;
- exactly-once external effects or safe recovery of uncertain outcomes;
- durable or distributed authority propagation, cross-process revocation, or coalition safety;
- production model integration, dynamic synthesis, multi-agent scheduling, or self-modification;
- complete information-flow control or mandatory access control;
- formal verification, implementation proof, or full T1-T11 coverage;
- interruption of a Nexus call already past the R2 authorization commit point; or
- production readiness.

Passing tests show the behavior of the tested implementation and fixtures. They do not turn roadmap invariants into general or formally verified properties.

## Documentation

- [Architecture](docs/agent-runtime/ARCHITECTURE.md)
- [Security invariants and evidence](docs/agent-runtime/SECURITY_INVARIANTS.md)
- [Threat model](docs/agent-runtime/THREAT_MODEL.md)
- [Authoritative R0–R13 build plan](docs/agent-runtime/BUILD_PLAN.md)
- [Official AEON Protocol v1.4 baseline](docs/agent-runtime/AEON_PROTOCOL_V1_4.md)
