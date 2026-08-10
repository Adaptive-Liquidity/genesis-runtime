# AEON Genesis Runtime

`genesis-runtime` is a standalone Rust workspace for the host-side AEON agent runtime. It implements only the R0 type/contracts foundation and the fixed R1 secure vertical slice described by the [AEON Protocol v1.4 baseline](docs/agent-runtime/AEON_PROTOCOL_V1_4.md).

## Current scope

R0 and R1 are the only active roadmap stages. The implemented/tested surface is deliberately narrow:

- one mission;
- one agent;
- one requested and registered fixture tool per successful run;
- scripted typed model output rather than a production model service;
- trusted protocol, plan, authority, and action gates in the host runtime;
- Nexus as the sole capability-enforcing WASM execution kernel; and
- an in-memory event store used to check event completeness for the exercised process lifetime.

The workspace pins Nexus by Git revision:

```toml
nexus = { git = "https://github.com/adaptiveliquidity/Nexus.git", rev = "c4343883cc4bd1f1262f2f878ed81f8015cedd0e", default-features = false }
```

AEON does not provide an alternate tool executor. The R1 execution port issues a scoped Nexus capability token and delegates WASM execution to that pinned kernel.

## Evidence

The repository's R0 contract tests cover typed serialization, canonical and domain-separated digests, immutable certificate versus mutable state separation, closed/size-bounded protocol parsing, and exact T11 semantic-context identity.

The R1 vertical-slice tests exercise a successful Nexus-backed fixture call and bounded rejection cases: malformed protocol output, unknown or mission-disallowed tools, authority excess, forbidden `Capability::All`, one-tool manifest substitution (the R1 subset of T8), material semantic drift (T11), and model-facing token/WASM exclusion. These tests are evidence for those fixed fixtures and branches only; they are not evidence for the complete T1-T11 target set or for production deployment.

Run the local evidence suite with:

```powershell
cargo test --workspace --all-targets
```

## Explicit non-claims

This repository does **not** currently claim:

- durable, crash-safe, or tamper-evident storage;
- exactly-once external effects or safe recovery of uncertain outcomes;
- full authority lifecycle, delegation, revocation, renewal, or coalition safety;
- production model integration, dynamic synthesis, multi-agent scheduling, or self-modification;
- complete information-flow control or mandatory access control;
- formal verification, implementation proof, or full T1-T11 coverage; or
- production readiness.

Passing tests show the behavior of the tested implementation and fixtures. They do not turn roadmap invariants into general or formally verified properties.

## Documentation

- [Architecture](docs/agent-runtime/ARCHITECTURE.md)
- [Security invariants and evidence](docs/agent-runtime/SECURITY_INVARIANTS.md)
- [Threat model](docs/agent-runtime/THREAT_MODEL.md)
- [R0-R18 build plan](docs/agent-runtime/BUILD_PLAN.md)
- [Official AEON Protocol v1.4 baseline](docs/agent-runtime/AEON_PROTOCOL_V1_4.md)
