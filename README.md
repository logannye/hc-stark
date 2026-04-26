# TinyZKP — Verifiable Receipts for AI Agents

[![npm](https://img.shields.io/npm/v/%40tinyzkp%2Fcli?label=%40tinyzkp%2Fcli&color=2ee8d4)](https://www.npmjs.com/package/@tinyzkp/cli)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Free tier](https://img.shields.io/badge/free%20tier-100%20proofs%2Fmo-34d399)](https://tinyzkp.com/signup)

**[tinyzkp.com](https://tinyzkp.com)** &middot; **[Try it in browser](https://tinyzkp.com/try)** &middot; **[API docs](https://tinyzkp.com/docs)** &middot; **[Free signup](https://tinyzkp.com/signup)**

Mint a tamper-evident proof that your agent ran the code it claims, on the inputs it claims. **One MCP install. One API call. Verify in milliseconds.** No cryptography degree required.

## Three ways to start in under a minute

### 1. Try in browser, no signup

Mint and verify a real ZK proof at [**tinyzkp.com/try**](https://tinyzkp.com/try) — type a value, hit Generate, hit Verify. Result in ~2 seconds.

### 2. Native install for AI agents (Claude Code)

```bash
claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com
```

Your agent now has 10 ZK proof tools (`prove`, `verify`, `list_workloads`, ...) as native function calls. For Claude Desktop, Cursor, OpenAI agents, and other MCP clients, see [the MCP install guide](https://tinyzkp.com/docs#mcp).

### 3. Terminal CLI (works against any TinyZKP API key)

```bash
npx @tinyzkp/cli templates                                # list available templates
npx @tinyzkp/cli prove range_proof '{"min":0,"max":100,"witness_steps":[42,44]}' --wait
npx @tinyzkp/cli verify proof.json                        # always free
```

`@tinyzkp/cli` is a zero-dependency Node 18+ ESM package. See [`clients/cli/README.md`](./clients/cli/README.md) for the full command reference.

## What you can prove

| Template | What it proves | Typical use |
|----------|---------------|-------------|
| `range_proof` | "I know a value between X and Y" — without revealing it | Age verification, salary bands, score thresholds |
| `hash_preimage` | "I know the secret behind this hash" | Password proofs, file integrity, commitment opening |
| `computation_attestation` | "f(secret inputs) = this public output" | Agent action receipts, batch compute attestation |
| `accumulator_step` | "Starting at X, applying these deltas reaches Y" | State machine attestation, rollup transitions |
| `policy_compliance` | "These actions stayed within the allowed limit" | Spending caps, rate limits, resource quotas |
| `data_integrity` | "These elements add up to this checksum" | Dataset audits, ledger reconciliation |

## Two-line plain HTTP version

```bash
curl -X POST https://api.tinyzkp.com/prove/template/range_proof \
  -H "Authorization: Bearer tzk_YOUR_KEY" \
  -d '{"params":{"min":0,"max":100,"witness_steps":[42,44]}}'
# → {"job_id":"prf_a1b2c3","status":"proving"}
curl https://api.tinyzkp.com/prove/prf_a1b2c3 -H "Authorization: Bearer tzk_YOUR_KEY"
# → {"status":"completed","proof":{"version":4,"bytes":"0x6a8f..."}}
```

Verification is always free. SDKs ship for Python (`pip install tinyzkp`), TypeScript (`npm install tinyzkp`), and Rust. There's also a [browser-side WASM verifier](https://www.npmjs.com/package/@tinyzkp/verify) so end users verify offline in 5ms.

---

## What sits underneath

`hc-stark` is the open-source Rust engine behind TinyZKP. It uses a **height-compressed streaming architecture** that runs in O(√T) prover memory instead of O(T) — the structural advantage that lets us price the small-proof tier at $0.05/proof and offer a real free tier without going broke.

| Property | hc-stark | Standard STARK |
|----------|----------|----------------|
| Prover memory | **~O(√T)** | O(T) |
| Prover time | ~O(T · log² T) | ~O(T · log T) |
| Verifier time | polylog(T) | polylog(T) |
| Proof size | polylog(T) | polylog(T) |
| Transparent (no trusted setup) | Yes | Yes |
| Post-quantum (hash-based) | Yes | Yes |

The technical writeup is in [`docs/whitepaper.md`](docs/whitepaper.md).

---

## Use the hosted API

The fastest way to start is the hosted service at **[api.tinyzkp.com](https://tinyzkp.com/docs)**. Free tier: 100 proofs/month, no credit card.

### 1. Get an API key

Sign up at [tinyzkp.com/signup](https://tinyzkp.com/signup). Your key arrives via email instantly.

### 2. Submit a proof

Use template-based proving — no need to specify block_size, initial/final accumulator, or FRI parameters. The API handles it:

```bash
curl -X POST https://api.tinyzkp.com/prove/template/accumulator_step \
  -H "Authorization: Bearer tzk_..." \
  -H "Content-Type: application/json" \
  -d '{"params":{"initial":1000,"final":1045,"deltas":[10,20,15]}}'
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
    job_id = await client.prove_template("range_proof", params={
        "min": 0, "max": 100, "witness_steps": [42, 44],
    })
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
const jobId  = await client.proveTemplate("range_proof", {
  min: 0, max: 100, witness_steps: [42, 44],
});
const proof  = await client.waitForProof(jobId);
const result = await client.verify(proof);  // free!
```

```bash
npm install tinyzkp
```

**Browser (WASM — no server, no API key):**
```javascript
import init, { verify } from '@tinyzkp/verify';

await init();
const result = verify({ version: 4, bytes: proofBytes });
console.log(result.ok); // true — verified client-side
```

```bash
npm install @tinyzkp/verify
```

---

## Pricing

Pay per proof based on trace complexity. Verification is always free. Our O(√T) architecture means 10–40x lower infrastructure costs — we pass the savings to you.

### Plans

| Plan | Monthly Base | Per-Proof Discount | Key Limits |
|------|-------------|-------------------|------------|
| Free | $0 | — | 100 proofs/mo, 1 inflight, 10 RPM |
| Developer | $0 | Base rates | 4 inflight, 100 RPM, $500/mo cap |
| Team | $49 | 25% off | 8 inflight, 300 RPM, $2,500/mo cap |
| Scale | $199 | 40% off | 16 inflight, 500 RPM, $10,000/mo cap |
| Enterprise | Custom | Up to 50% off | Custom limits, SLA |

### Per-proof base rates (Developer plan)

| Trace Steps | Price |
|-------------|-------|
| < 10K | $0.05/proof |
| 10K – 100K | $0.50/proof |
| 100K – 1M | $2.00/proof |
| 1M – 10M | $8.00/proof |
| > 10M | $30.00/proof |

Team and Scale plans receive automatic discounts (25% and 40% off) on every proof. See [tinyzkp.com/docs#plans](https://tinyzkp.com/docs#plans) for full details.

---

## Proof templates

Six built-in templates cover common zero-knowledge use cases. Browse them via the discovery API:

```bash
# List all templates
curl https://api.tinyzkp.com/templates

# Get full schema + example for a template
curl https://api.tinyzkp.com/templates/range_proof

# Submit a proof using a template (smart defaults, no block_size needed)
curl -X POST https://api.tinyzkp.com/prove/template/range_proof \
  -H "Authorization: Bearer tzk_..." \
  -d '{"params":{"min":0,"max":100,"witness_steps":[42,44]}}'

# Estimate cost before proving (no auth required)
curl -X POST https://api.tinyzkp.com/estimate \
  -d '{"template_id":"range_proof","params":{"min":0,"max":100,"witness_steps":[42,44]}}'
```

> **What are `witness_steps`?** Internal computation values that encode your secret. They are never revealed to the verifier — only the proof (which vouches for them) is shared.

| Template | What It Proves | Key Parameters |
|----------|---------------|----------------|
| `range_proof` | "I know a number between X and Y" — without revealing it | `min`, `max`, `witness_steps[]` |
| `hash_preimage` | "I know the secret that produces this hash" | `digest`, `preimage_steps[]` |
| `computation_attestation` | "f(secret inputs) = this public output" | `steps[]`, `expected_output` |
| `accumulator_step` | "Starting from X, applying these deltas reaches Y" | `initial`, `final`, `deltas[]` |
| `policy_compliance` | "These actions stayed within the allowed limit" | `actions[]`, `threshold` |
| `data_integrity` | "These data elements add up to this checksum" | `elements[]`, `checksum` |

---

## AI agent integration (MCP)

hc-stark ships as an **MCP server** so AI agents (Claude, GPT, Cursor) can generate and verify proofs natively. Supports both local (stdio) and remote (HTTP) transport.

### Remote access (no install)

```bash
# Claude Code
claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com
```

### Local install

```bash
cargo install --path crates/hc-mcp
```

Or download from the [releases page](https://github.com/logannye/hc-stark/releases).

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "tinyzkp": {
      "command": "hc-mcp-stdio",
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
| **Template Discovery** | | | |
| GET | `/templates` | None | List all proof templates |
| GET | `/templates/:id` | None | Get template schema + example |
| POST | `/estimate` | None | Estimate cost, time, proof size |
| **Proving** | | | |
| POST | `/prove/template/:id` | Required | Submit proof via template (recommended) |
| POST | `/prove` | Required | Submit proof via workload_id or program |
| POST | `/prove/batch` | Required | Submit multiple prove jobs |
| GET | `/prove/:job_id` | Required | Get job status and result |
| GET | `/prove/:job_id/inspect` | Required | Detailed proof breakdown + timing |
| POST | `/prove/:job_id/cancel` | Required | Cancel a running job |
| DELETE | `/prove/:job_id` | Required | Delete a completed job |
| GET | `/prove` | Required | List jobs (`?status`, `?limit`, `?offset`) |
| **Verification** | | | |
| POST | `/verify` | Required | Verify a proof (free, no charge) |
| POST | `/aggregate` | Required | Aggregate multiple proofs into one digest |
| **Billing & Ops** | | | |
| GET | `/usage` | Required | View usage and estimated costs |
| GET | `/proof/:job_id/calldata` | Required | Get EVM on-chain calldata |
| GET | `/healthz` | None | Liveness check |
| GET | `/metrics` | None | Prometheus metrics |
| GET | `/docs` | None | Interactive Swagger UI |
| **Account** | | | |
| POST | `/api/rotate-key` | Required | Rotate API key (once per 24h) |

Interactive API explorer: **[api.tinyzkp.com/docs](https://api.tinyzkp.com/docs)**

### Authentication

All endpoints require a Bearer token:

```
Authorization: Bearer tzk_...
```

Verification is free but still requires auth to prevent abuse.

Rotate a compromised key instantly:
```bash
curl -X POST https://tinyzkp.com/api/rotate-key \
  -H "Authorization: Bearer tzk_YOUR_CURRENT_KEY"
```

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
    hc-wasm/        # WASM verifier (@tinyzkp/verify npm package, 785K)
    hc-python/      # Python bindings
    hc-node/        # Node.js native bindings
    hc-rollup/      # Rollup state transition API
  clients/          # Python, TypeScript, and Rust client SDKs
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
- MCP server with 10 tools for AI agents (stdio + HTTP transport)
- Streamable HTTP transport for MCP (remote agent access)
- 6 proof templates with discovery API (`GET /templates`)
- Template-based proving (`POST /prove/template/:id`)
- Cost estimation endpoint (`POST /estimate`)
- Proof inspection endpoint (`GET /prove/:job_id/inspect`)
- Proof aggregation (`POST /aggregate` with recursive hash tree)
- WASM verifier package (`@tinyzkp/verify`, 785K)
- **`@tinyzkp/cli` published to npm** — `npx @tinyzkp/cli verify proof.json`
- On-chain verifier contract (recursive KZG, ~300K gas)
- EVM calldata generation (`GET /proof/:job_id/calldata`)
- Self-service API key rotation (`POST /api/rotate-key`)
- DSL compiler for custom programs
- Multi-tenant HTTP API with rate limiting
- **Production service at [tinyzkp.com](https://tinyzkp.com)**
- Stripe billing (free tier, $9 Developer, $49 Team, $199 Scale, monthly + annual variants at 20% off)
- Python, TypeScript, and Rust client SDKs
- **Browser playground at [`tinyzkp.com/try`](https://tinyzkp.com/try)** — mint and verify proofs without signup
- Live status page at [`tinyzkp.com/status`](https://tinyzkp.com/status)
- Docker Compose production stack with monitoring

### Next

- Custom program sandboxing (paid tier)
- Node.js native bindings package
- GPU acceleration (CUDA/Metal kernels)
- On-chain verifier contract deployment (mainnet)
- Rollup state transition API
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
