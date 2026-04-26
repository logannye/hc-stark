# Business overview — TinyZKP

> **Status**: TinyZKP launched in 2026. This document supersedes the
> pre-launch business plan, which is preserved at
> [`docs/archive/BUSINESS_GUIDE_2025-pre-launch.md`](docs/archive/BUSINESS_GUIDE_2025-pre-launch.md)
> for historical reference.

## What this repo runs

`hc-stark` is the open-source Rust engine behind **[tinyzkp.com](https://tinyzkp.com)** —
a hosted ZK-proof service that gives AI agents (Claude, GPT, Cursor)
verifiable receipts for computation. The pitch: a height-compressed
streaming STARK prover running in **O(√T) memory** instead of O(T),
which is the cost structure that makes per-proof prices below $0.05
viable.

## Customer, surface, distribution

**Who pays:**

- **AI agent builders** (Anthropic / OpenAI / Cursor users) who want
  their agents to mint tamper-evident receipts for tool calls. This
  is the wedge — distribution is the public MCP at
  `mcp.tinyzkp.com`, no signup required, addressable directly via
  `claude mcp add --transport http tinyzkp ...`.

- **Developers integrating ZK proofs** into apps (privacy, attestation,
  state transitions). They hit `api.tinyzkp.com` with a Bearer key,
  use the Python / TypeScript / Rust SDK, or the `@tinyzkp/cli` npm
  package.

- **Enterprise** users (custom programs, SLAs, higher per-proof
  ceilings, dedicated capacity).

**Surface:**

| Surface | Path | Auth | Volume cap |
|---------|------|------|------------|
| HTTP API | `api.tinyzkp.com` | Bearer | per-tenant RPM + monthly cap |
| MCP (HTTP transport) | `mcp.tinyzkp.com/mcp` | Optional Bearer | global concurrency + per-tenant RPM when authed |
| Public playground | `tinyzkp.com/try` | None | global rate limit |
| WASM verifier | `@tinyzkp/verify` (npm) | None | client-side |
| CLI | `npx @tinyzkp/cli` | Bearer | n/a |

**Distribution channels live today:**

- Anthropic MCP directory (mcp.tinyzkp.com)
- npm (`@tinyzkp/cli`, `@tinyzkp/verify`, `tinyzkp`)
- PyPI (`pip install tinyzkp`)
- Cargo (`tinyzkp` Rust SDK)
- Cloudflare Pages marketing site at `tinyzkp.com` (with embedded playground)

## Pricing — current

| Plan | Monthly base | Per-proof discount | Inflight | RPM | Monthly cap |
|------|-------------|-------------------|----------|-----|-------------|
| Free | $0 | — | 1 | 10 | 100 proofs |
| Developer | $0 | base rates | 4 | 100 | $500 |
| Team | $49 | 25% off | 8 | 300 | $2,500 |
| Scale | $199 | 40% off | 16 | 500 | $10,000 |
| Enterprise | custom | up to 50% off | custom | custom | custom |

**Per-proof base rates** (Developer plan):

| Trace steps | Price |
|-------------|-------|
| < 10K | $0.05 |
| 10K – 100K | $0.50 |
| 100K – 1M | $2.00 |
| 1M – 10M | $8.00 |
| > 10M | $30.00 |

Verification is always free. See `README.md` for canonical pricing.

## Operations stack

- **Compute**: Hetzner dedicated boxes via Docker Compose. Stack:
  `hc-server` (Rust HTTP API) + `hc-mcp-http` + `hc-worker` (per-job
  fork+exec, capped via `HC_SERVER_MAX_WORKER_SPAWN`) + Prometheus +
  Grafana + Alertmanager.
- **Billing**: Stripe — `billing/sync_usage.py` cron syncs unbilled
  proofs to Stripe meter events hourly with idempotency keys. See
  [`billing/STRIPE_SETUP.md`](billing/STRIPE_SETUP.md).
- **State**: SQLite for jobs + usage today; Postgres migration plan
  in [`docs/postgres_migration.md`](docs/postgres_migration.md). Single
  Hetzner box ceiling is roughly tens of proves/min sustained; horizontal
  scaling unblocks at Postgres cutover.
- **Marketing site**: Cloudflare Pages, `site/` directory.
- **Auth**: Bearer keys with file-based hot-reload + 5min rotation
  grace window. Per-IP brute-force lockout.

## What's deferred / on the roadmap

- **Postgres cutover** — the next structural unlock. See above.
- **Cross-process tenant quota** — MCP and API maintain independent
  per-tenant windows today. A shared backing store (Redis-class) would
  make a tenant's quota deplete uniformly across both surfaces.
- **Worker warm pool** (vs current spawn-per-job) — ops concern under
  hundreds-per-min QPS. Currently bounded via the spawn-cap semaphore.
- **GPU acceleration** — CUDA/Metal for the heaviest provers.
- **Recursive aggregation production endpoint** — `POST /aggregate`
  exists; the on-chain verifier contract is shipped but not yet
  deployed to mainnet.
- **Cancer-superintelligence... wait wrong repo.** The extension wave
  for hc-stark is in [`ROADMAP_EXTENSIONS.md`](ROADMAP_EXTENSIONS.md):
  zkML, zkVM, sumcheck/HyperPlonk, IPA / Bulletproofs.

## Where to look for what

| Question | Document |
|---|---|
| How do I use the API? | [README.md](README.md) |
| How does the prover work? | [docs/whitepaper.md](docs/whitepaper.md) |
| How do I run my own deployment? | [docs/operations.md](docs/operations.md) |
| What's the proof format? | [docs/proof_format_v4_zk.md](docs/proof_format_v4_zk.md) |
| What's coming next, technically? | [ROADMAP_EXTENSIONS.md](ROADMAP_EXTENSIONS.md) |
| How does Stripe billing work? | [billing/STRIPE_SETUP.md](billing/STRIPE_SETUP.md) |
| What's the original business case? | [docs/archive/BUSINESS_GUIDE_2025-pre-launch.md](docs/archive/BUSINESS_GUIDE_2025-pre-launch.md) |
