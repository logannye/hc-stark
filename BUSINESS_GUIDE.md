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

- Hosted MCP transport at `mcp.tinyzkp.com` (publicly reachable, no auth required for the anonymous lane). MCP *directory* listings (Anthropic / Smithery / mcp.so) are submission packets prepared but **not yet submitted** — see [`marketing/MCP_DIRECTORY*.md`](marketing/) and "What's deferred" below.
- npm (`@tinyzkp/cli`, `@tinyzkp/verify`, `tinyzkp`)
- PyPI (`pip install tinyzkp`)
- Cargo (`tinyzkp` Rust SDK)
- Cloudflare Pages marketing site at `tinyzkp.com` (with embedded playground)

## Pricing — current

`pricing.json` at the repo root is the single source of truth. Stripe self-serve checkout exposes three plans (Free / Developer / Scale) plus a usage-based Compute product. Team is retained in `pricing.json` and provisioned by hand as a sales-issued contract; Enterprise is fully custom.

**Self-serve plans:**

| Plan | Monthly base | Per-proof discount | Inflight | RPM | Monthly cap |
|------|-------------|-------------------|----------|-----|-------------|
| Free | $0 | — | 1 | 10 | $5 (≈100 proofs) |
| Developer | $19 | base rates | 4 | 100 | $500 |
| Scale | $199 | 40% off | 16 | 500 | $10,000 |

Annual billing: 20% off any paid plan.

**Usage-based product (no monthly base):**

| Plan | Pricing | Inflight | RPM | Trace ceiling |
|------|---------|----------|-----|---------------|
| Compute | $0.50 per million trace steps | 8 | 100 | 100M steps |

**Sales-issued plans (no Stripe self-serve checkout):**

| Plan | Monthly base | Per-proof discount | Inflight | RPM | Monthly cap |
|------|-------------|-------------------|----------|-----|-------------|
| Team | custom (≈$49) | 25% off | 8 | 300 | $2,500 |
| Enterprise | custom | up to 50% off | custom | custom | custom |

**Per-proof base rates** (Developer plan):

| Trace steps | Price |
|-------------|-------|
| < 10K | $0.05 |
| 10K – 100K | $0.50 |
| 100K – 1M | $2.00 |
| 1M – 10M | $8.00 |
| > 10M | $30.00 |

Verification is always free. See `README.md` for the customer-facing copy.

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

## Recently shipped (post-sweep + 2026-04-28 gap closure)

Closing the engineering side of the post-launch backlog so the next
quarter is a customer-discovery and structural-scale conversation,
not a code-cleanup one:

- **Publish-ready client SDKs** — Python (PyPI), TypeScript (npm,
  ESM+CJS dual build), Rust (Cargo), CLI (`@tinyzkp/cli` on npm).
- **MCP-directory submission packets** — Anthropic + smithery.ai + mcp.so,
  in [`marketing/`](marketing/). All three are operator-driven web forms;
  packets contain pre-flight checklists + exact submission steps. None of
  the three is CLI/PR-submittable (verified 2026-04-28: `smithery-ai/registry`
  is issue-tracker-only; `chatmcp/mcp-directory` is the website source code,
  not a registry).
- **Marketing tiers collapsed to Stripe reality** — site, signup,
  and Stripe checkout now agree on Free / Developer $19 / Scale
  $199 + Compute usage-based; Team retained as a sales-issued
  custom contract via [`/contact`](https://tinyzkp.com/contact).
- **Real Grafana panels + honest status page** at
  [`tinyzkp.com/status`](https://tinyzkp.com/status).
- **Templates copy-paste examples** — six full curl + Python +
  TypeScript snippets on [`tinyzkp.com/docs`](https://tinyzkp.com/docs)
  with an integration test at
  `crates/hc-workloads/tests/template_examples.rs` asserting every
  documented example builds.
- **User-interview pipeline** — recruit / script / synthesis
  playbook in [`marketing/USER_INTERVIEWS.md`](marketing/USER_INTERVIEWS.md);
  target is 5 interviews / 14 days against free-tier signups, MCP
  installs, and playground completions.
- **Workspace recovery, round 2** — workspace-test scaffolding
  (hc-bench / hc-core / hc-hash / hc-prover / hc-verifier),
  hc-server's binary entry point, deny.toml, and the
  hc-node / hc-python / fuzz crate skeletons all lifted into
  version control. Fresh-clone `cargo metadata` now load-bearing-clean.
- **Doc/contract assets lifted** — ROADMAP_EXTENSIONS.md, the
  Solidity verifier interface (`contracts/IHcStarkVerifier.sol`),
  the security/audit triple under `docs/security/`, the proof
  format v4 spec, the parameter guide, and the Hetzner deploy
  runbooks all under version control.

## What's deferred / on the roadmap

- **Postgres cutover** — the next structural unlock. See above.
- **Cross-process tenant quota** — MCP and API maintain independent
  per-tenant windows today. A shared backing store (Redis-class) would
  make a tenant's quota deplete uniformly across both surfaces.
- **Customer discovery (5 interviews / 14 days)** — the gating input
  for whether the next quarter is Postgres + scale, the zkML wedge,
  or template redesign. Pipeline drafted in
  [`marketing/USER_INTERVIEWS.md`](marketing/USER_INTERVIEWS.md).
- **HN launch + MCP-directory submission** — drafted in
  [`marketing/HN_LAUNCH.md`](marketing/HN_LAUNCH.md) (Tuesday/Wednesday
  8–9:30 a.m. ET window) and the MCP-directory packets — operator
  needs to pull the trigger.
- **Worker warm pool** (vs current spawn-per-job) — ops concern under
  hundreds-per-min QPS. Currently bounded via the spawn-cap semaphore.
- **GPU acceleration** — CUDA/Metal for the heaviest provers.
- **Recursive aggregation production endpoint** — `POST /aggregate`
  exists; the on-chain verifier contract is shipped but not yet
  deployed to mainnet.
- **Cancer-superintelligence... wait wrong repo.** The extension wave
  for hc-stark is in [`ROADMAP_EXTENSIONS.md`](ROADMAP_EXTENSIONS.md):
  zkML (Phase 1 — highest revenue), zkVM, sumcheck/HyperPlonk, IPA /
  Bulletproofs.

## Where to look for what

| Question | Document |
|---|---|
| How do I use the API? | [README.md](README.md) |
| How does the prover work? | [docs/whitepaper.md](docs/whitepaper.md) |
| How do I run my own deployment? | [docs/operations.md](docs/operations.md) |
| How do I deploy the latest production sweep to Hetzner? | [docs/runbooks/deploy_2026-04-28.md](docs/runbooks/deploy_2026-04-28.md) |
| What's the proof format? | [docs/proof_format_v4_zk.md](docs/proof_format_v4_zk.md) |
| What's coming next, technically? | [ROADMAP_EXTENSIONS.md](ROADMAP_EXTENSIONS.md) |
| How does Stripe billing work? | [billing/STRIPE_SETUP.md](billing/STRIPE_SETUP.md) |
| What's the threat model / soundness story? | [docs/security/](docs/security/) |
| How do I run user interviews? | [marketing/USER_INTERVIEWS.md](marketing/USER_INTERVIEWS.md) |
| How do I launch on HN? | [marketing/HN_LAUNCH.md](marketing/HN_LAUNCH.md) |
| What's the original business case? | [docs/archive/BUSINESS_GUIDE_2025-pre-launch.md](docs/archive/BUSINESS_GUIDE_2025-pre-launch.md) |
