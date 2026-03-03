# hc-stark — Height-Compressed, Streaming ZK STARK Prover

`hc-stark` is a **height-compressed, sublinear-space ZK-STARK prover** designed to make **very long zero-knowledge proofs** practical on fixed-memory hardware (CPUs, GPUs, and edge devices).

It implements a **streaming prover** for STARK-style proofs: instead of buffering the entire trace and all derived polynomials, the prover walks a **height-compressed computation tree** and recomputes small tiles on demand from compact checkpoints.

The result:

- **Prover memory:** ~√T (up to polylog factors) instead of T
- **Prover time:** ~T · polylog²(T) (near-standard STARK time with a small replay overhead)
- **Verifier & proof:** unchanged STARK-like (polylog(T) verification, polylog(T) proof size)
- **Security:** transparent + hash-based (STARK-style, plausibly post-quantum)

---

## What's new: AI-agent-native proving

hc-stark now ships an **MCP (Model Context Protocol) server** that lets AI agents discover, generate, and verify zero-knowledge proofs through standard tool interfaces. This is the first ZK proving system designed from the ground up for the age of autonomous agents.

**Why this matters:** As AI agents increasingly take actions on behalf of users — transferring funds, signing contracts, accessing data, making purchases — they need a way to **prove** those actions were executed correctly, within policy, and without tampering. Zero-knowledge proofs provide that trust layer, and hc-stark makes it accessible to any agent that speaks MCP.

See [AI Agent Integration](#ai-agent-integration-mcp) for setup and usage.

---

## Table of contents

- **Getting started**
  - [Quickstart: build and test](#quickstart-build-and-test)
  - [AI agent integration (MCP)](#ai-agent-integration-mcp)
  - [CLI usage](#cli-usage)
  - [HTTP service](#http-service)
  - [Docker Compose stack](#docker-compose-stack)
  - [Production deployment](#production-deployment)
- **Understanding the system**
  - [Why this matters](#why-this-matters)
  - [How the repo is organized](#how-the-repo-is-organized)
  - [How the prover works](#how-the-prover-works)
  - [Complexity comparison](#complexity-comparison)
- **Proof templates**
  - [Template catalog](#proof-template-catalog)
  - [DSL compilation](#dsl-compilation)
- **Using the system**
  - [Extending with new AIRs](#extending-with-new-airs)
  - [Benchmarking](#benchmarking)
  - [Test suite](#test-suite)
  - [CI and regression](#ci-and-regression)
- **Vision and roadmap**
  - [The agent future](#the-agent-future)
  - [Status and roadmap](#status-and-roadmap)
  - [Development standards](#development-standards)

---

## Quickstart: build and test

```bash
# Build and test the entire workspace
cargo test --workspace

# Run the MCP server for AI agent integration
cargo run -p hc-mcp --bin hc-mcp-stdio

# Run the CLI
cargo run -p hc-cli -- --help

# Run the HTTP service
cargo run -p hc-server

# Run the full stack (API + Prometheus + Grafana)
docker compose up --build
```

---

## AI Agent Integration (MCP)

hc-stark includes a native **Model Context Protocol (MCP)** server that exposes zero-knowledge proving as discoverable tools for AI agents. Any MCP-compatible agent (Claude, GPT, or custom agents) can generate and verify proofs without any cryptographic expertise.

### How it works

The MCP server exposes 10 tools that follow a natural workflow:

1. **Discover** — `list_templates`, `list_workloads`, `describe_template`, `get_capabilities`
2. **Prove** — `prove_template` or `prove_workload` (returns a `job_id`)
3. **Monitor** — `poll_job` (check status: pending / running / succeeded / failed)
4. **Retrieve** — `get_proof` (base64 proof bytes) or `get_proof_summary` (human-readable)
5. **Verify** — `verify_proof` (independent verification)

### Setup

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "hc-stark": {
      "command": "cargo",
      "args": ["run", "-p", "hc-mcp", "--bin", "hc-mcp-stdio"]
    }
  }
}
```

**Claude Code** (`.mcp.json`):
```json
{
  "mcpServers": {
    "hc-stark": {
      "command": "cargo",
      "args": ["run", "-p", "hc-mcp", "--bin", "hc-mcp-stdio"]
    }
  }
}
```

### Configuration

| Variable | Default | Description |
|---|---:|---|
| `HC_MCP_MAX_INFLIGHT` | `2` | Max concurrent proof jobs |

### Example agent conversation

> **Agent:** "I need to prove that a series of financial transactions are internally consistent."
>
> The agent calls `list_templates`, discovers `accumulator_step`, calls `describe_template` to learn the parameters, then:

```json
// prove_template
{
  "template_id": "accumulator_step",
  "parameters": {"initial": 1000, "final": 1045, "deltas": [10, 20, 15]},
  "zk": false
}
// Returns: {"job_id": "abc-123", "status": "running"}

// poll_job → {"status": "succeeded"}
// get_proof → {"proof_b64": "...", "size_bytes": 4832}
// verify_proof → {"valid": true}
```

The agent now has a cryptographic proof that the state transition `1000 → 1045` via deltas `[10, 20, 15]` is valid, and can present it to any verifier.

---

## Proof Template Catalog

Templates are parameterized proof patterns designed for AI agent consumption. Each template carries rich metadata (descriptions, parameter schemas, examples) that agents use for tool discovery.

| Template | What It Proves | Key Params | Tags |
|----------|---------------|------------|------|
| **`accumulator_step`** | A chain of additive deltas transitions correctly from initial to final state | `initial`, `final`, `deltas[]` | state-transition, accumulator |
| **`computation_attestation`** | f(secret_steps) = public_output, without revealing the inputs | `steps[]`, `expected_output` | attestation, zero-knowledge |
| **`hash_preimage`** | Prover knows a secret whose iterative hash equals a public digest | `digest`, `preimage_steps[]` | hash, commitment, zero-knowledge |
| **`range_proof`** | A secret value lies within [min, max] without revealing it | `min`, `max`, `witness_steps[]` | range, privacy, zero-knowledge |
| **`policy_compliance`** | Accumulated actions stay within a threshold (spending limits, quotas) | `actions[]`, `threshold` | policy, compliance, agent |
| **`data_integrity`** | Data elements sum to a committed checksum (batch audit, ledger balance) | `elements[]`, `checksum` | data, integrity, audit |

Templates build `Program` objects directly from VM instructions — no DSL roundtrip needed. Each validates parameters and returns descriptive errors that help agents self-correct.

---

## DSL Compilation

hc-stark includes a DSL compiler for agents that need custom proof programs beyond the built-in templates:

```rust
use hc_vm::compile;

let program = compile("add 5\nadd 3\nadd 7")?;
// Returns a Program with 3 AddImmediate instructions
```

The `compile()` function composes `parse()` and `lower()` into a single call, with structured error types (`CompileError::Parse` / `CompileError::Lower`) that include position information for agent-friendly error correction.

---

## CLI Usage

The CLI in `hc-cli` supports end-to-end prove/verify flows:

```bash
# Basic prove and verify
cargo run -p hc-cli -- prove --output proof.json
cargo run -p hc-cli -- verify --input proof.json

# With zero-knowledge masking
cargo run -p hc-cli -- prove --zk-mask-degree 8

# Benchmarks
cargo run -p hc-cli -- bench --iterations 5 --block-size 64 --scenario prover
cargo run -p hc-cli -- bench --scenario merkle --leaves 4096 --queries 128
cargo run -p hc-cli -- bench --scenario lde --columns 4 --degree 512
cargo run -p hc-cli -- bench --scenario recursion --proofs 8
cargo run -p hc-cli -- bench --scenario height --leaves 65536 --block-size 128

# Auto-tuned block size selection
cargo run -p hc-cli -- prove --auto-block --trace-length 1048576 --target-rss-mb 256

# Recursion artifact generation
cargo run -p hc-cli -- recursion \
  --proof proof_a.json \
  --proof proof_b.json \
  --artifact recursion_artifact.json
```

### CLI presets and auto-tuning

The CLI resolves block sizes by layering: defaults → presets → config file → explicit flags. Built-in presets: `balanced`, `memory`, `latency`, `laptop`, `server`.

```bash
# Laptop-friendly with hardware detection
cargo run -p hc-cli -- prove --preset laptop --auto-block --hardware-detect

# CI-style server run
cargo run -p hc-cli -- bench --scenario prover --preset server --trace-length 8388608
```

User presets can be defined in `~/.hc-cli.toml`:

```toml
[presets.gpu_lab]
auto_block = true
target_rss_mb = 4096
profile = "latency"
hardware_detect = true
commitment = "stark"
```

---

## HTTP Service

The server in `hc-server` exposes a REST API:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/prove` | POST | Submit async prove job (returns `job_id`) |
| `/prove/{job_id}` | GET | Poll job status + retrieve proof |
| `/verify` | POST | Synchronous proof verification |
| `/healthz` | GET | Liveness check |
| `/readyz` | GET | Readiness check |
| `/metrics` | GET | Prometheus metrics |
| `/docs` | GET | Swagger UI |

```bash
cargo run -p hc-server
```

---

## Docker Compose Stack

```bash
docker compose up --build
```

Brings up `hc-server` + Prometheus + Grafana with a starter dashboard. See `docs/runbooks/deploy_docker_compose.md`.

---

## Production Deployment

### Deployment options

- **Docker Compose** (recommended for handoff/demo): `docker compose up --build`
- **Docker image**: `docker build -t hc-server . && docker run -p 8080:8080 hc-server`
- **Native binary**: `cargo run -p hc-server`

### Authentication

Set `HC_SERVER_API_KEYS=tenant:key,tenant2:key2` to enable multi-tenant API key auth. Clients send `Authorization: Bearer <key>`.

### Workload model

By default, production **does not** accept arbitrary programs. Clients must use registered `workload_id` values. Set `HC_SERVER_ALLOW_CUSTOM_PROGRAMS=true` only with a deliberate sandboxing story.

### Server configuration

| Variable | Default | Description |
|---|---:|---|
| `HC_SERVER_DATA_DIR` | `.hc-server` | Job storage directory |
| `HC_SERVER_MAX_INFLIGHT` | `4` | Max concurrent prove jobs |
| `HC_SERVER_MAX_PROVE_SECS` | `300` | Per-job timeout |
| `HC_SERVER_API_KEYS` | unset | Tenant API keys |
| `HC_SERVER_ALLOW_CUSTOM_PROGRAMS` | `false` | Allow arbitrary programs |
| `HC_SERVER_MAX_BODY_BYTES` | `26214400` | Max request body size |
| `HC_SERVER_MAX_VERIFY_INFLIGHT` | `8` | Max concurrent verify requests |
| `HC_SERVER_VERIFY_TIMEOUT_MS` | `30000` | Verify timeout (ms) |
| `HC_SERVER_RETENTION_SECS` | `86400` | Job GC interval |
| `HC_SERVER_JOB_INDEX_SQLITE` | `false` | Enable SQLite job index |
| `HC_SERVER_MAX_PROVE_RPM` | `0` | Per-tenant prove rate limit (0 = disabled) |
| `HC_SERVER_MAX_VERIFY_RPM` | `0` | Per-tenant verify rate limit (0 = disabled) |

### Zero-knowledge mode

ZK-masked native STARK proofs (protocol v4). Non-deterministic commitments, same public statement verification.

- **CLI**: `--zk-mask-degree 8` (any degree > 0 enables ZK)
- **Server**: `zk_mask_degree` field in `ProveRequest`
- **MCP**: `"zk": true` in `prove_template` params

---

## Why This Matters

STARKs are a way to sell **trust** for expensive computation: compute once, produce a proof, let everyone verify cheaply. The main bottleneck is **prover memory**, which drives cost, operational fragility, and workload limitations.

hc-stark changes the equation:

> If you can make proving work in bounded memory, you can lower the cost-per-proof and unlock workloads that are otherwise impractical — enabling a real product business.

For a non-technical guide, see [`BUSINESS_GUIDE.md`](BUSINESS_GUIDE.md).

---

## How the Repo Is Organized

```text
hc-stark/
  crates/
    hc-core/        # Field arithmetic (Goldilocks), FFTs, tiled FFT, SIMD hooks
    hc-commit/      # Vector commitments, standard/streaming Merkle trees
    hc-hash/        # Hash digests, transcripts, Fiat-Shamir, protocol transcript
    hc-fri/         # Streaming FRI prover/verifier built on TraceReplay
    hc-air/         # AIR definitions, constraints, multi-column support, selectors
    hc-vm/          # 28-instruction register VM, trace generator, DSL compiler
    hc-replay/      # Block producers, deterministic replay engine
    hc-prover/      # Pointerless DFS scheduler, replay-aware streaming prover
    hc-verifier/    # STARK verifier matching prover transcript
    hc-sdk/         # SDK surface: proof bytes, (de)serialization, EVM calldata
    hc-workloads/   # Workload registry + proof template system (6 templates)
    hc-mcp/         # MCP server: AI agent tool interface (10 tools, stdio transport)
    hc-server/      # axum HTTP API: /prove, /verify, /metrics, OpenAPI
    hc-cli/         # CLI: prove/verify/bench/recursion + JSON I/O
    hc-bench/       # Programmatic benchmarking harness
    hc-recursion/   # Recursive aggregation, Halo2/KZG circuits, IVC scaffolding
    hc-height/      # Generalized height-compression interfaces (Merkle + KZG)
    hc-simd/        # SIMD-accelerated field operations
    hc-node/        # Distributed proving node
    hc-rollup/      # Rollup integration layer
    hc-wasm/        # WebAssembly bindings
    hc-python/      # Python bindings
    hc-examples/    # Sample flows: zkVM, zkML dense layer, replay helpers

  clients/          # Client SDKs
  contracts/        # On-chain verifier contracts
  deploy/           # Deployment configs (Grafana, Prometheus)
  docs/             # Whitepaper, design notes, proof format specs, runbooks
  scripts/          # Test suite, benchmark aggregation, CI scripts
  fuzz/             # Fuzz testing harnesses
```

**Architecture layers:**

- **Primitives** (`hc-core`, `hc-commit`, `hc-hash`, `hc-fri`, `hc-height`): Generic crypto building blocks, reusable by other projects.
- **Computation** (`hc-air`, `hc-vm`, `hc-replay`): What to prove — VMs, AIRs, deterministic replay.
- **Proving** (`hc-prover`, `hc-verifier`, `hc-recursion`): The streaming prover engine with height compression.
- **Agent interface** (`hc-workloads`, `hc-mcp`): Template system and MCP server for AI-native access.
- **Product** (`hc-server`, `hc-cli`, `hc-sdk`): HTTP API, CLI, and SDK for production use.

---

## How the Prover Works

### Classic STARK pipeline

A standard in-core STARK prover materializes the full trace (T rows), performs FFTs over full vectors, builds Merkle trees for each oracle, and answers queries. Memory: **O(T)**.

### Height-compressed pipeline

hc-STARK refactors this into a height-compressed computation tree:

1. **Block tiling:** Choose block size `b ~ √T`. The trace becomes `T/b ~ √T` blocks of size `b`.
2. **Computation tree:** Each STARK step becomes a binary tree of block computations. Leaves are block-local (tile FFTs, range hashing). Internal nodes combine children.
3. **Pointerless DFS:** The tree is traversed with a small stack of O(log T) frames — no heap-allocated tree, just compact checkpoints.
4. **Replay engine:** Only O(1) blocks of size `b` are live at any time. When a block is needed again, it's replayed from checkpoints with O(b) working memory.

Peak prover space: **~O(√T · polylog(T))**.

### Complexity summary

| Metric | hc-STARK | In-core STARK |
|--------|----------|---------------|
| Prover space | ~O(√T · polylog T) | O(T) |
| Prover time | ~O(T · log² T) | ~O(T · log T) |
| Verifier time | polylog(T) | polylog(T) |
| Proof size | polylog(T) | polylog(T) |
| Transparent | Yes | Yes |
| Post-quantum | Yes (hash-based) | Yes (hash-based) |

---

## Complexity Comparison

| System | Prover Time | Prover Space | Verifier Time | Proof Size | Transparent? | Post-Quantum? |
|--------|-------------|-------------|---------------|------------|-------------|--------------|
| **hc-STARK** | ~O(T · log² T) | **~O(√T)** | ~O(polylog T) | ~O(polylog T) | Yes | Yes |
| In-core STARK | ~O(T · log T) | O(T) | ~O(polylog T) | ~O(polylog T) | Yes | Yes |
| Groth16/Plonk | ~O(T · polylog T) | O(T) | ~O(1) | O(1) | No (SRS) | No |
| IPA/Bulletproof | ~O(T · log T) | O(T) | ~O(polylog T) | ~O(log T) | Often yes | No |

hc-STARK trades a small time overhead for a **quadratic reduction in prover memory** while maintaining transparency and post-quantum security.

---

## The Agent Future

### Why ZK proofs will be infrastructure for the agent economy

We are entering an era where AI agents will autonomously execute complex tasks: managing finances, negotiating contracts, operating infrastructure, and making decisions on behalf of people and organizations. This creates a fundamental trust problem:

**How do you verify that an agent did what it claimed, followed the rules you set, and didn't tamper with the results?**

Zero-knowledge proofs are the answer. They provide cryptographic guarantees that:

- **Actions were executed correctly** — An agent can prove it followed a specific computation without the verifier re-executing it.
- **Policies were respected** — An agent can prove it stayed within spending limits, rate limits, or access controls without revealing every action it took.
- **Data wasn't tampered with** — An agent can prove a dataset is complete and unmodified without exposing the data itself.
- **Secrets remain secret** — An agent can prove it knows a credential, satisfies a threshold, or computed a result without revealing the underlying values.

### What hc-stark enables for agents

hc-stark is purpose-built for this future:

1. **MCP-native interface** — Agents discover and use proof templates through standard tool protocols. No cryptography PhD required.
2. **Parameterized templates** — Pre-built proof patterns for common agent needs (state transitions, policy compliance, data integrity, range proofs, computation attestation, hash preimage knowledge).
3. **Streaming architecture** — Bounded-memory proving means agents can generate proofs on edge devices, in containers, or on cost-effective cloud instances without provisioning large-RAM machines.
4. **Self-describing tools** — Every template carries rich metadata (descriptions, parameter schemas, examples) designed for LLM consumption. An agent can learn to use the system by reading the tool descriptions alone.

### Concrete agent use cases

| Use Case | Template | What the Agent Proves |
|----------|----------|----------------------|
| Financial transaction audit | `accumulator_step` | A series of transactions correctly transitions an account balance |
| Spending limit compliance | `policy_compliance` | Total spend across actions stays within an authorized budget |
| Age/credit verification | `range_proof` | A value meets a threshold without revealing the exact number |
| Inference attestation | `computation_attestation` | An ML model produced a specific output (without revealing weights) |
| Data pipeline integrity | `data_integrity` | A batch of records is complete and matches a committed checksum |
| Credential proof | `hash_preimage` | The agent possesses a secret (API key, password hash) without revealing it |

### The roadmap to agent-native infrastructure

**Phase 1 (complete):** MCP server with 10 tools, 6 proof templates, in-process proving, stdio transport.

**Phase 2 (next):**
- Streamable HTTP transport (agents connect to a remote proving service)
- DSL compilation tool (agents write custom proof programs)
- Help tools: `explain_proof` (natural language summary), `estimate_cost` (resource estimation)
- REST v2 API with template-based proving endpoints
- EVM calldata generation for on-chain verification

**Phase 3 (future):**
- **Intent understanding** — Natural language to proof: "Prove I stayed under budget" automatically selects the right template and fills parameters.
- **Proof aggregation tools** — Recursive wrapping via MCP for agents that need to batch multiple proofs.
- **On-chain submission** — Direct EVM transaction submission with proof calldata.
- **Multi-agent coordination** — Shared proof job queues, priority scheduling, resource estimation across agent fleets.
- **Proof marketplace** — Agents publish proving capabilities; other agents discover and request proofs.

---

## Extending with New AIRs

1. Implement a VM / transition function in `hc-vm` (state representation, next-state logic, boundary conditions).
2. Define the corresponding AIR in `hc-air` (trace columns, constraint polynomials, degree bounds).
3. Wire into `hc-prover` with a block replay adapter.
4. Add an example binary in `hc-examples`.

---

## Benchmarking

```bash
# Prover scenario with auto-tuning
cargo run -p hc-cli -- bench --scenario prover --auto-block-size --trace-length 1048576

# Streaming Merkle path replay
cargo run -p hc-cli -- bench --scenario merkle --leaves 4096 --queries 128

# Batched LDE throughput
cargo run -p hc-cli -- bench --scenario lde --columns 4 --degree 512

# Height-compression comparison (Merkle vs KZG)
cargo run -p hc-cli -- bench --scenario height --leaves 65536 --block-size 128

# Recursion aggregation
cargo run -p hc-cli -- bench --scenario recursion --proofs 8
```

All bench scenarios accept `--metrics-dir <path>` and `--metrics-tag <label>` to persist JSON/CSV history for dashboards. CI runs `scripts/check_bench_thresholds.py` against `benchmarks/baseline.json` to gate regressions.

---

## Test Suite

```bash
# All tests
./scripts/test_suite.sh all

# Specific categories
./scripts/test_suite.sh sanity   # Build verification, unit tests, CLI roundtrip
./scripts/test_suite.sh stress   # Edge cases, parameter variations, Merkle/LDE micro-benches
./scripts/test_suite.sh ladder   # Scaling analysis with O(√T) verification, RSS tracking
```

The ladder phase collects `profile_duration` and `memory_kb` per block size, computes normalized ratios, and demonstrates constant-time and √T-memory behavior.

---

## CI and Regression

`.github/workflows/ci.yml` runs on every push/PR:

- `cargo fmt`, `cargo clippy --workspace --all-targets`, `cargo test --workspace`
- Full test suite (sanity, stress, ladder)
- Benchmark threshold checks via `scripts/check_bench_thresholds.py`
- Artifact upload (`benchmarks/latest.json`, `ladder_latest.{json,csv}`)

---

## Status and Roadmap

### Completed

- Height-compressed streaming STARK prover with O(√T) memory
- Complete verifier with streaming Merkle replay and FRI query propagation
- Zero-knowledge mode (protocol v4) with ZK masking
- **MCP server** with 10 tools for AI agent integration
- **6 proof templates** (accumulator, computation attestation, hash preimage, range proof, policy compliance, data integrity)
- **DSL compiler** with `compile()` convenience function
- Workload registry with compile-time registration (`inventory`)
- Recursive aggregation with Halo2/KZG circuits
- Streaming Merkle trees with configurable fanouts
- Batched LDE kernels (Rayon-backed parallel column evaluation)
- Block-wise LDE/composition with hashed commitments
- CLI with prove/verify/bench/recursion commands and auto-tuning
- HTTP API with async proving, multi-tenant auth, rate limiting
- Docker Compose stack with Prometheus + Grafana
- Comprehensive test suite with √T scaling verification
- CI pipeline with benchmark regression gating

### In progress

- Recursive wrapping circuits with scheduled fan-in trees
- Multi-layer aggregation specs
- Automated CI dashboards for √T metric tracking
- Expanding AIR/zkVM examples beyond the toy VM

### Future directions

- GPU acceleration with real CUDA/Metal kernels
- Streamable HTTP transport for MCP (remote agent access)
- DSL compilation MCP tool (custom proof programs from agents)
- Intent understanding layer (natural language to proof)
- Multi-agent proof coordination and marketplace
- On-chain proof submission tools
- Production zkVM and zkML framework integrations
- Distributed proving across multiple machines

---

## Development Standards

- **Toolchain:** Rust stable, `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test --workspace`
- **Safety:** All crates use `#![forbid(unsafe_code)]`
- **Error handling:** `hc_core::HcError`, `HcResult<T>`, `hc_ensure!` macro; no `panic!` in library code
- **Docs:** Every module starts with `//!` overview
- **Benchmarks:** Deterministic scenarios for CI regression tracking

---

## Additional resources

- [`BUSINESS_GUIDE.md`](BUSINESS_GUIDE.md) — Non-technical guide to building a business on hc-stark
- `docs/whitepaper.md` — Formal specification and proofs
- `docs/proof_format_v4_zk.md` — ZK proof format specification
- `docs/design_notes/` — Architecture decision records
- `docs/runbooks/` — Deployment and operations guides
- `docs/security/` — Security considerations and threat model
