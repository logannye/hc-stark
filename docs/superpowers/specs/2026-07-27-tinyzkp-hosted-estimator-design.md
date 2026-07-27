# TinyZKP hosted estimator — Phase 1b design

Date: 2026-07-27
Status: approved design, pending implementation plan
Parent spec: `docs/superpowers/specs/2026-07-26-tinyzkp-passive-proving-utility-design.md`
Builds on: `main` @ `42b3e98` (Phase 0 + 1a shipped)

## Why this phase exists

The parent spec's staged strategy rests on one claim: *estimation harvests demand,
and demand tells us which proving profile to fund.* Phase 1a shipped the estimator
as a **local CLI with no telemetry** — deliberately. The consequence is that
`request_digest`, built specifically as the demand-aggregation key, aggregates
nothing.

The pre-committed kill criterion — *fewer than ~15 distinct organizations in 90
days ⇒ the demand thesis is false, stop before building the fleet* — is therefore
**currently unmeasurable**. The clock is not running because there is no clock.

**This phase's job is not revenue. It is cheap falsification.** It exists so the
business can be killed for the price of a serverless function rather than the
price of Phase 3's months of cryptographic engineering.

Corollary worth stating plainly: **Phase 2 is not the revenue phase either.**
Metered proving on Goldilocks `p3_uni_stark` sells into a market for which no
evidence was found. Realistic first dollar requires Phase 3 (multi-table + LogUp).
Building the ledger, credits, and spot fleet before Phase 3 is a toll booth on a
road with no traffic.

## Architecture

**Cloudflare Worker + the estimator compiled to WebAssembly.**

Feasibility is not assumed — `.github/workflows/ci.yml:69` already runs
`cargo check --locked -p hc-wasm --target wasm32-unknown-unknown` on every commit
and CI is green, so `hc-plonky3` compiles for `wasm32` today. `crates/hc-wasm`
is the existing precedent (a browser verifier built on the same crate).

Why a Worker rather than a container: true scale-to-zero at $0 idle, on the same
account and edge as the existing Pages site. The parent spec's governing
constraint is that nothing may be always-on; the previous hosted plane died as a
box billing 24/7 against $0 revenue.

### One source of truth for the cost model

The Worker wraps the **same Rust `estimate_config::run()`** compiled to WASM. The
cost model is never reimplemented in TypeScript.

This is non-negotiable, and the reason is empirical: Phase 1a shipped a
`conventional` estimate that diverged from the codebase's canonical model by
**7.8x** precisely because the same concept was computed two ways. A TS
reimplementation would recreate that bug class at the API boundary, where it would
be invisible until a customer contradicted a published number.

### Components

| Component | Responsibility |
|---|---|
| `POST /v1/estimate` Worker | validate, invoke WASM estimator, return `EstimateResponseV1` |
| WASM estimator module | `estimate_config::run()` compiled to `wasm32-unknown-unknown` |
| Rate limiter | per-IP for anonymous, per-key for keyed |
| Key minter | `POST /v1/keys` — email only, no account, no password |
| Demand log (D1) | append-only, shape-only records |
| Kill-criterion report | distinct organizations over a rolling 90 days |
| `/estimate` page | form + the CLI one-liner, on the existing Pages site |

## Access model

**Anonymous by default; an optional free key raises the limit.**

- Anonymous: callable instantly, no signup, low per-IP rate.
- Keyed: `POST /v1/keys` with an email returns an opaque key. No account, no
  password, no dashboard. Higher rate limit.

Rationale: this tool is from a vendor nobody has heard of. A signup wall in front
of a free tool is the most reliable way to get zero trials and then misread that
as zero demand — which would trip the kill criterion for the wrong reason.
Anonymous access maximises trial; the keyed tier captures identity from exactly
the people using it seriously, who are the population the 15-organization
threshold is actually about.

Consequence to accept honestly: distinct-organization counting is **exact for
keyed traffic and approximate for anonymous**. The kill-criterion report must
present both numbers separately and must never silently blend them.

## Demand log

Append-only. **Shape-only — never the full request.** Each record:

- `request_digest` (the existing shape key; excludes `logical_rows` by design, so
  one AIR probed at several sizes aggregates as one signal)
- `field`, `extension_degree`
- `trace_width` and `logical_rows` as **buckets**, not exact values
- the eight `AirFeaturesV1` flags
- `provable_today` and the blocking reason codes
- coarse timestamp
- `key_id` when keyed, else a salted IP hash

No witness, no AIR source, no paths — the estimator never receives any of those,
and the log must not become the first place they could appear.

## Kill-criterion report

A scheduled query producing, over a rolling 90 days: distinct keyed organizations,
distinct approximate anonymous sources, the top request digests by volume, and the
distribution of blocking reason codes.

That last one is the profile-expansion queue: the most frequent blocking reason
across distinct organizations is the empirical answer to "which profile do we fund
next", replacing the current guess (SP1-shaped BabyBear multi-table).

The report must state the criterion's verdict explicitly — `CONTINUE` or
`KILL_THRESHOLD_MET` — rather than emitting numbers a human has to interpret
favourably.

## Explicitly out of scope

Metered proving, the credit ledger, prepaid billing, the merchant-of-record, the
spot worker fleet, and any paid tier. Those are Phase 2 and must not begin until
this phase's data justifies them. Also out of scope: the regression-CI GitHub
Action (a later phase), and publishing the estimate JSON schemas (blocked on
`site/schemas/` and the `cli_roundtrip.rs` count pin).

## Constraints inherited

- Rust `1.95.0` pinned; Plonky3 exact-pinned `0.6.1`; no dependency bumps —
  the root `Cargo.lock` hash is frozen at `974b3506…` in several places and a
  bump reds `plonky3_compatibility_gate.py`.
- Adding any dependency also stales `fuzz/Cargo.lock` and
  `clients/rust/Cargo.lock`, which are standalone workspaces not covered by a
  root gate. Both must be regenerated if the dependency graph changes.
- `scripts/ci/claim_containment_scan.py` scans `docs/**/*.md` for
  `\bzero[- ]knowledge\b`; tripping it blocks the Pages deploy.
- No new always-on infrastructure.

## Open items for the implementation plan

- D1 vs R2 for the demand log (D1 assumed; volume is trivially small).
- Whether the WASM module is built in CI and committed, or built at deploy time.
- Rate-limit numbers for anonymous and keyed tiers.
- Bucket boundaries for `trace_width` and `logical_rows`.
- Whether `/v1/estimate` reuses the `ReasonCodeV1` error envelope verbatim
  (it should) and what HTTP status maps to each reason class.
