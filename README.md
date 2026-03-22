# hc-stark — Height-Compressed ZK-STARK Prover

**[TinyZKP.com](https://tinyzkp.com)** | **[API Docs](https://tinyzkp.com/docs)** | **[Swagger](https://api.tinyzkp.com/docs)** | **[Sign Up (free)](https://tinyzkp.com/signup)**

`hc-stark` is the open-source engine behind [TinyZKP](https://tinyzkp.com) — a production ZK-STARK proving service. Generate and verify zero-knowledge proofs with a single API call. No cryptography expertise required.

```bash
# Prove a secret is in range [0, 100] without revealing it
curl -X POST https://api.tinyzkp.com/prove \
  -H "Authorization: Bearer tzk_..." \
  -H "Content-Type: application/json" \
  -d '{"workload_id":"range_proof","secret":42,"min":0,"max":100}'

# Verify (free, no charge)
curl -X POST https://api.tinyzkp.com/verify \
  -H "Authorization: Bearer tzk_..." \
  -d '{"proof": {...}}'
# → {"valid": true, "verified_in_ms": 2.8}
```

## Why hc-stark

The prover uses a **height-compressed streaming architecture** that runs in O(√T) memory instead of O(T). This makes long proofs practical on fixed-memory hardware — the core innovation that enables a real per-proof pricing model.

| Property | hc-stark | Standard STARK |
|----------|----------|----------------|
| Prover memory | **~O(√T)** | O(T) |
| Prover time | ~O(T · log² T) | ~O(T · log T) |
| Verifier time | polylog(T) | polylog(T) |
| Proof size | polylog(T) | polylog(T) |
| Transparent | Yes | Yes |
| Post-quantum | Yes (hash-based) | Yes (hash-based) |

---

## Use the hosted API

The fastest way to start is the hosted service at **[api.tinyzkp.com](https://tinyzkp.com/docs)**. Free tier: 100 proofs/month, no credit card.

### 1. Get an API key

Sign up at [tinyzkp.com/signup](https://tinyzkp.com/signup). Your key arrives via email instantly.

### 2. Submit a proof

```bash
curl -X POST https://api.tinyzkp.com/prove \
  -H "Authorization: Bearer tzk_..." \
  -H "Content-Type: application/json" \
  -d '{
    "workload_id": "accumulator_step",
    "initial_acc": 1000,
    "final_acc": 1045,
    "deltas": [10, 20, 15],
    "block_size": 4,
    "fri_final_poly_size": 2
  }'
```

### 3. Poll and verify

```bash
# Poll job status
curl https://api.tinyzkp.com/prove/<job_id> \
  -H "Authorization: Bearer tzk_..."

# Verify (free)
curl -X POST https://api.tinyzkp.com/verify \
  -H "Authorization: Bearer tzk_..." \
  -d '{"proof": {...}}'
```

### Client SDKs

**Python:**
```python
from tinyzkp import TinyZKP

async with TinyZKP("https://api.tinyzkp.com", api_key="tzk_...") as client:
    job_id = await client.prove(program=["add_immediate 1"], initial_acc=5, final_acc=6)
    proof  = await client.wait_for_proof(job_id)
    result = await client.verify(proof)  # free!
```

```bash
pip install tinyzkp
```

**TypeScript:**
```typescript
import { HcClient } from "tinyzkp";

const client = new HcClient("https://api.tinyzkp.com", { apiKey: "tzk_..." });
const jobId  = await client.prove({ program: ["add_immediate 1"], initialAcc: 5, finalAcc: 6 });
const proof  = await client.waitForProof(jobId);
const result = await client.verify(proof);  // free!
```

```bash
npm install tinyzkp
```

---

## Pricing

Pay per proof based on trace complexity. Verification is always free.

| Tier | Trace Steps | Price |
|------|-------------|-------|
| Free | — | 100 proofs/month, no credit card |
| Tiny | < 10K | $0.05/proof |
| Standard | 10K – 100K | $0.50/proof |
| Large | 100K – 1M | $2.00/proof |
| Enterprise | 1M – 10M | $5.00/proof |
| XL | > 10M | $20.00/proof |

**Plan limits** (rate limits, concurrency, monthly caps) vary by tier — see [tinyzkp.com/docs#plans](https://tinyzkp.com/docs#plans).

---

## Proof templates

Six built-in templates cover common zero-knowledge use cases. Pass the template name as `workload_id`.

| Template | What It Proves | Key Parameters |
|----------|---------------|----------------|
| `accumulator_step` | A chain of additive deltas transitions correctly | `initial`, `final`, `deltas[]` |
| `computation_attestation` | f(secret_steps) = public_output without revealing inputs | `steps[]`, `expected_output` |
| `hash_preimage` | Prover knows a secret whose hash equals a public digest | `digest`, `preimage_steps[]` |
| `range_proof` | A secret value lies within [min, max] | `min`, `max`, `witness_steps[]` |
| `policy_compliance` | Actions stay within a threshold (spending, quotas) | `actions[]`, `threshold` |
| `data_integrity` | Data elements sum to a committed checksum | `elements[]`, `checksum` |

---

## AI agent integration (MCP)

hc-stark ships as an **MCP server** so AI agents (Claude, GPT, Cursor) can generate and verify proofs natively.

### Install

```bash
cargo install --path crates/hc-mcp
```

Or download from the [releases page](https://github.com/logannye/hc-stark/releases).

### Configure

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "tinyzkp": {
      "command": "hc-mcp",
      "args": ["--api-key", "tzk_..."]
    }
  }
}
```

### MCP tools

| Tool | Description |
|------|-------------|
| `prove` | Submit a proof job |
| `verify` | Verify a proof |
| `prove_status` | Poll job status |
| `list_jobs` | List jobs for your tenant |
| `healthz` | Service health check |
| `list_programs` | List registered workloads |
| `describe_program` | Get workload details + parameter schema |
| `list_workloads` | Browse proof templates |
| `submit_workload` | Submit a proof via template |
| `workload_status` | Poll workload job status |

---

## API reference

Base URL: `https://api.tinyzkp.com`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/prove` | Required | Submit an async prove job |
| GET | `/prove/:job_id` | Required | Get job status and result |
| POST | `/prove/batch` | Required | Submit multiple prove jobs |
| POST | `/prove/:job_id/cancel` | Required | Cancel a running job |
| DELETE | `/prove/:job_id` | Required | Delete a completed job |
| GET | `/prove` | Required | List jobs (`?status`, `?limit`, `?offset`) |
| POST | `/verify` | Required | Verify a proof (free, no charge) |
| GET | `/usage` | Required | View usage and estimated costs |
| GET | `/proof/:job_id/calldata` | Required | Get EVM on-chain calldata |
| GET | `/healthz` | None | Liveness check |
| GET | `/metrics` | None | Prometheus metrics |
| GET | `/docs` | None | Interactive Swagger UI |

Interactive API explorer: **[api.tinyzkp.com/docs](https://api.tinyzkp.com/docs)**

### Authentication

All endpoints require a Bearer token:

```
Authorization: Bearer tzk_...
```

Verification is free but still requires auth to prevent abuse.

---

## Self-host

### Build from source

```bash
# Build and test
cargo test --workspace

# Run the server locally
HC_SERVER_API_KEYS=demo:demo_key cargo run -p hc-server --release

# Run with Docker Compose (server + Prometheus + Grafana + billing)
GRAFANA_ADMIN_PASSWORD=changeme docker compose up --build
```

### Docker Compose stack

The full production stack includes:

| Service | Purpose |
|---------|---------|
| `hc-server` | Rust proving API (port 8080) |
| `billing-webhook` | Stripe webhook handler (Flask) |
| `billing-cron` | Hourly usage sync to Stripe |
| `prometheus` | Metrics collection (port 9090) |
| `grafana` | Dashboards (port 3000) |
| `alertmanager` | Alert routing (port 9093) |

```bash
# Production deploy (Hetzner example)
docker compose -f docker-compose.yml -f deploy/hetzner/docker-compose.prod.yml up -d
```

See [`docs/operations.md`](docs/operations.md) for full configuration reference.

### Server configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `HC_SERVER_API_KEYS` | unset | `tenant:key` pairs (comma-separated) |
| `HC_SERVER_API_KEYS_FILE` | unset | Path to API keys file (`tenant:key:plan` per line) |
| `HC_SERVER_MAX_INFLIGHT` | `4` | Max concurrent prove jobs per tenant |
| `HC_SERVER_MAX_PROVE_SECS` | `300` | Per-job timeout |
| `HC_SERVER_ALLOW_CUSTOM_PROGRAMS` | `false` | Allow arbitrary VM programs |
| `HC_SERVER_MAX_PROVE_RPM` | `100` | Per-tenant prove rate limit |
| `HC_SERVER_MAX_VERIFY_RPM` | `300` | Per-tenant verify rate limit |
| `HC_SERVER_JOB_INDEX_SQLITE` | `true` | Enable SQLite job index |

### Zero-knowledge mode

ZK-masked proofs (protocol v4) hide the computation while maintaining verifiability:

- **API**: Set `zk_mask_degree > 0` in the prove request
- **CLI**: `cargo run -p hc-cli -- prove --zk-mask-degree 8`
- **MCP**: `"zk": true` in prove parameters

---

## How the repo is organized

```
hc-stark/
  crates/
    hc-core/        # Field arithmetic (Goldilocks), FFTs, SIMD
    hc-commit/      # Merkle trees, vector commitments
    hc-hash/        # Hash digests, Fiat-Shamir transcripts
    hc-fri/         # Streaming FRI prover/verifier
    hc-air/         # AIR definitions, constraints, selectors
    hc-vm/          # 28-instruction register VM, DSL compiler
    hc-replay/      # Block producers, deterministic replay
    hc-prover/      # Height-compressed streaming prover
    hc-verifier/    # STARK verifier
    hc-sdk/         # Proof serialization, EVM calldata
    hc-workloads/   # 6 proof templates + workload registry
    hc-mcp/         # MCP server for AI agents (10 tools)
    hc-server/      # axum HTTP API with multi-tenant auth
    hc-cli/         # CLI: prove/verify/bench/recursion
    hc-bench/       # Benchmarking harness
    hc-recursion/   # Recursive aggregation (Halo2/KZG)
    hc-height/      # Height-compression interfaces
    hc-simd/        # SIMD-accelerated field ops
    hc-wasm/        # WebAssembly bindings
    hc-python/      # Python bindings
  clients/          # Python + TypeScript client SDKs
  billing/          # Stripe billing (tenant provisioning, usage sync)
  site/             # Marketing site (tinyzkp.com, Cloudflare Pages)
  deploy/           # Docker, Prometheus, Grafana configs
  docs/             # Whitepaper, operations, proof format specs
  contracts/        # On-chain verifier contracts
```

---

## How the prover works

### Classic STARK pipeline

A standard STARK prover materializes the full trace (T rows), FFTs over full vectors, builds Merkle trees, and answers queries. Memory: **O(T)**.

### Height-compressed pipeline

hc-stark refactors this into a streaming computation tree:

1. **Block tiling** — Choose block size `b ~ √T`. The trace becomes `T/b ~ √T` blocks.
2. **Computation tree** — Each STARK step becomes a binary tree of block computations.
3. **Pointerless DFS** — The tree is traversed with O(log T) stack frames — no heap-allocated tree.
4. **Replay engine** — Only O(1) blocks are live at any time. Blocks are replayed from checkpoints.

Peak prover space: **~O(√T · polylog(T))**.

---

## Development

```bash
# Full test suite
./scripts/test_suite.sh all

# Specific categories
./scripts/test_suite.sh sanity   # Build, unit tests, CLI roundtrip
./scripts/test_suite.sh stress   # Edge cases, parameter variations
./scripts/test_suite.sh ladder   # √T scaling verification with RSS tracking

# Benchmarks
cargo run -p hc-cli -- bench --scenario prover --auto-block-size --trace-length 1048576
cargo run -p hc-cli -- bench --scenario merkle --leaves 4096 --queries 128
cargo run -p hc-cli -- bench --scenario recursion --proofs 8
```

### Standards

- **Toolchain:** Rust stable, `cargo fmt`, `cargo clippy -- -D warnings`
- **Safety:** All crates use `#![forbid(unsafe_code)]`
- **Error handling:** `HcError` / `HcResult<T>` / `hc_ensure!` — no panics in library code
- **CI:** `.github/workflows/ci.yml` runs fmt, clippy, test, full suite, and benchmark regression gating on every push

---

## Roadmap

### Shipped

- Height-compressed streaming prover with O(√T) memory
- Complete verifier with streaming Merkle replay
- Zero-knowledge mode (protocol v4)
- MCP server with 10 tools for AI agents
- 6 proof templates
- DSL compiler for custom programs
- Recursive aggregation with Halo2/KZG
- Multi-tenant HTTP API with rate limiting
- **Production service at [tinyzkp.com](https://tinyzkp.com)**
- Stripe billing (free tier + metered usage)
- Python and TypeScript client SDKs
- Docker Compose production stack with monitoring
- EVM calldata generation

### Next

- Streamable HTTP transport for MCP (remote agent access)
- Self-service API key rotation and Stripe Customer Portal
- GPU acceleration (CUDA/Metal kernels)
- Intent understanding — natural language to proof
- Proof aggregation tools via MCP
- On-chain verifier contracts deployment
- Distributed proving across multiple machines

---

## Links

- **Product:** [tinyzkp.com](https://tinyzkp.com)
- **API Docs:** [tinyzkp.com/docs](https://tinyzkp.com/docs)
- **Swagger UI:** [api.tinyzkp.com/docs](https://api.tinyzkp.com/docs)
- **Sign Up:** [tinyzkp.com/signup](https://tinyzkp.com/signup)
- **Contact:** [tinyzkp.com/contact](https://tinyzkp.com/contact)
- **Business Guide:** [`BUSINESS_GUIDE.md`](BUSINESS_GUIDE.md)
- **Whitepaper:** [`docs/whitepaper.md`](docs/whitepaper.md)
- **Operations:** [`docs/operations.md`](docs/operations.md)
- **Proof Format:** [`docs/proof_format_v4_zk.md`](docs/proof_format_v4_zk.md)
- **Privacy Policy:** [tinyzkp.com/privacy](https://tinyzkp.com/privacy)
- **Terms of Service:** [tinyzkp.com/terms](https://tinyzkp.com/terms)
