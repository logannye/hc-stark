# TinyZKP.com — passive proving utility: business model and product design

Date: 2026-07-26
Status: approved design, pending implementation plan
Supersedes: the TinyZKP Guard `$499/mo` local-supervisor SKU as the commercial direction

## Problem

TinyZKP has a verified engineering advantage and no way to monetize it.

The Guard model sells a local supervisor for a customer-run binary. That model
structurally cannot capture the advantage: when the customer runs the engine on
their own hardware, the customer pockets the resource savings and TinyZKP
collects a flat licence fee. It also cannot meter usage, because the design
deliberately never observes the workload.

A cost advantage becomes a pricing weapon only when the seller owns the compute.

## The advantage, verified

Measured on a 4-vCPU / 16 GiB GitHub runner, from
`release/evidence/backend-v1-evidence.json` at release SHA `5eb407c`:

| Workload | Peak RSS bounded vs conventional | RAM win | CPU cost |
|---|---|---|---|
| Fibonacci 1M | 119 MiB vs 703 MiB | 5.90x | 3.11x slower |
| Poseidon2 1M | 567 MiB vs 3,526 MiB | 6.22x | 2.39x slower |
| Fibonacci 16M | 1,815 MiB (conventional does not fit) | n/a | 659 s |

Two properties follow, and both are load-bearing for the business:

1. **Memory is a policy-pinned ceiling, not an emergent value.** `fibonacci-1m.json`
   and `fibonacci-16m.json` both set `max_resident_bytes: 2147483648`. A 16x larger
   trace ran under an identical 2 GiB ceiling; the growth was absorbed by scratch
   (1 GB to 10 GB). A conventional prover's memory grows roughly linearly and
   eventually cannot run at all.
2. **CPU is linear in trace length.** 659.24 s at 16.7M rows versus 42.20 s at 1M
   rows is 15.6x for 16x the rows. A linear price therefore holds constant margin
   at every scale.

The underlying trade is substrate arbitrage: RAM at roughly $3-5/GB-month is
exchanged for NVMe scratch at roughly $0.08-0.10/GB-month.

### Structural COGS advantage, honestly sized

| Effect | Source | Multiple |
|---|---|---|
| Job density per host | 3,526 MiB to 567 MiB | 6.2x |
| CPU penalty (works against us) | 291 s vs 122 s | /2.39 |
| Net throughput on identical iron | | ~2.6x |
| Spot eligibility via deterministic checkpoint-resume | competitors cannot checkpoint mid-proof | ~3-4x |
| **Combined** | | **~8-10x** |

The defensible claim is roughly an order of magnitude lower cost floor. It is not
the 20-30x a RAM-only reading suggests; the CPU penalty is real and must be netted
out. Above the OOM threshold the advantage stops being a multiple and becomes
categorical, because the competitor cannot run the job at any price.

## Decisions taken

| Decision | Choice |
|---|---|
| Compute model | Reopen hosted proving, fully automated, scale-to-zero |
| Profile strategy | Stage it: sell any-profile estimation now, build multi-table proving next |
| Customer-facing meter | Flat rate per trace-cell unit, any trace size, no cliff |
| Guard | Repurposed as the internal fleet supervisor; public SKU retired |
| Data posture | Public-input workloads only; witness never claimed private |

## What TinyZKP.com becomes

**The proving utility with no memory cliff.**

Homepage claim, which competitors cannot make and the evidence pipeline can prove:

> Submit a trace of any size. We hold memory flat and charge one linear rate —
> no instance class, no OOM, no cliff.

Three surfaces, and nothing else:

| Surface | What it does | Price |
|---|---|---|
| Estimator | Any Plonky3 config. Returns predicted peak RSS, scratch, CPU-time, and a bounded-vs-conventional comparison. No proving, no witness. | Free, rate-limited by API key |
| Proving API | POST a job manifest, poll, download a proof verifiable by the unmodified upstream verifier | Metered, flat rate |
| Regression CI | GitHub Action wrapping the estimator; fails the build on RAM or time regression | Free tier, paid above a monthly run count |

Explicitly absent: plans, seats, trials, sales calls, SLAs, support tiers, and any
dashboard beyond usage and receipts.

The estimator is a strategic asset rather than a giveaway. It runs on configurations
that cannot yet be proved, so every call is a logged, self-identifying demand signal.
Profile expansion becomes a queue sorted by revenue instead of a guess.

## Data and trust posture

Reopening a hosted plane reverses the pivot's stated promise that no witness,
trace, or proof enters TinyZKP infrastructure. That reversal is deliberate and must
be stated plainly rather than quietly dropped.

The posture is **public-input workloads only**:

- Hosted proving targets workloads whose trace derives from public data, such as
  rollup and zkVM proving. This is the same posture Succinct and Boundless operate
  under.
- TinyZKP makes **no confidentiality claim** about submitted workloads. The site
  says so directly rather than implying protection it cannot provide.
- **Zero retention:** scratch lives on worker instance-store NVMe and is destroyed
  with the worker; the proof is delivered and then purged on a published schedule.
- Anyone with a genuinely private witness is pointed at the MIT local engine, which
  remains free and unchanged. This keeps the local path meaningful without selling
  or supporting it as a SKU.

This is the smallest liability surface consistent with hosting, and it makes no
cryptographic claim the evidence pipeline cannot back.

## Pricing mechanics

**Customer-facing meter: trace cells.** One published rate per Gcell
(`padded_rows x columns`), per supported profile. Flat at every trace size. Both
inputs are declared in the job manifest and server-verified before admission, so
the meter cannot be gamed.

A naive flat rate per row would be exploitable: at identical 1M rows, Poseidon2
costs 291 CPU-s against Fibonacci's 42 CPU-s, 6.9x more work for the same row
count. Metering on cells with a published per-profile degree factor fixes this
while preserving the no-cliff property.

**Internal calibration: CPU-seconds.** Each profile's Gcell rate derives from
measured CPU-seconds per Gcell on reference hardware, republished whenever the
benchmark moves. The customer never sees a CPU meter; that framing would advertise
the 2.4-3.1x slowdown while concealing the 6x density gain.

**Quote before run.** Proving is deterministic, so the estimator returns a firm
price before admission. Quote equals charge, always. No reconciliation, no true-up,
no billing disputes.

**Prepaid credits, never invoices.** Customers buy credits; jobs debit; at zero,
jobs stop. This deletes the dunning, collections, chargeback, and involuntary-churn
surface entirely — the largest hidden ops burden in usage billing and the one that
would otherwise defeat the hands-off goal. Optional auto-top-up. Failed proofs
auto-credit with no human in the loop.

**Setting the number.** At spot around $0.03/vCPU-hour, Poseidon2-1M costs about
$0.0024 to prove. Pricing near 10x COGS yields roughly 90% gross margin with room
to undercut. Do not publish a $/Gcell figure until multi-table profiles are
measured; the honest input is real workload COGS, not Fibonacci.

## Architecture

Governing constraint: **$0 when idle, and preemption is routine rather than an
incident.** The previous hosted plane died as an always-on box billing 24/7 against
$0 revenue. Nothing in this design may be always-on.

**Do not revive the retired stack.** `hc-server`, `hc-beta-api`, `hc-mcp`, and
`billing/` total roughly 20k LOC built for a different model. The new control plane
is small, fresh, and stateless. Deleting the legacy crates also clears the
`legacy_obligations_resolved` overhang.

### Components

| Component | Responsibility | Why it is hands-off |
|---|---|---|
| Control plane (serverless) | auth, quote, admit, enqueue, status, download | scale-to-zero, $0 idle, no host to patch |
| Ledger and job store (managed SQL) | credit balance, holds, job records | single source of truth, no reconciliation cron |
| Managed batch queue on spot | autoscale 0 to N on queue depth, native preemption retry | the provider owns the autoscaler |
| Worker image: bounded engine + repurposed Guard supervisor (source: private `logannye/tinyzkp-guard`, minus `entitlement.rs` and the licence/activation surface) | run job, checkpoint, resume after preemption | Guard's crash-resume is what makes spot safe |
| Object storage | manifests in, proofs out; instance-store NVMe for scratch | scratch never leaves the worker; proofs are small |
| Merchant-of-record | credit purchase, tax, receipts | payments are never touched directly |
| Existing evidence CI | publishes price and capability tables | prices become generated artifacts, not hand-edited copy |

### Flow

Submit manifest, validate against the profile contract, estimator returns a firm
quote, check balance, place a credit hold, enqueue, spot worker claims, prove with
checkpointing, upload proof, debit exactly the quote, release the hold.

### Failure handling — all automatic

- **Spot preemption:** Guard resumes from the last checkpoint on a new worker.
  Billing is on cells rather than attempts, so retries cost the customer nothing.
- **Unrecoverable crash:** hold released, job failed, zero charge.
- **Insufficient scratch or unsupported config:** rejected at admission by the
  estimator, before compute is spent.
- **Self-verification failure:** auto-credit and alert. This is the only true
  incident class and is already gated by the official-verifier CI.

### Test surface

Extend the existing evidence pipeline with three additions:

1. **Metering parity test** — declared cells equal server-computed cells equal
   billed cells.
2. **Quote-versus-COGS drift monitor** — alarms if realized margin inverts on any
   profile.
3. **Paid end-to-end canary** on every deploy — buys credits, proves, verifies with
   the upstream verifier, confirms the ledger debit.

## Ops envelope

Target: **under 2 hours per month.** Review the margin-drift monitor, triage the
profile-expansion queue, answer GitHub issues. Payments, tax, dunning, preemption,
retries, refunds, and scaling are owned by the merchant-of-record, the batch
scheduler, or the ledger. There is deliberately no dashboard to watch, no status
page to maintain, and no support SLA.

## Staging

**Phase 0 — clear the decks (1-2 weeks).** Confirm or delete the Hetzner box to stop
silent burn. Retire the Guard SKU publicly. Delete the legacy hosted crates. Publish
`backend-v0.1.0`, which is currently an unpublished draft and is free. Collapse the
nine launch gates to the three that gate a hosted service. Ship three distribution
acts: awesome-plonky3 submission, a forward-pointing banner on the 50-star
`space-efficient-zero-knowledge-proofs` repo, and a Rosalind cross-link.

**Phase 1 — free estimator and demand harvesting (~6 weeks).** The unlock is that
estimation is an analytic cost model over field, columns, rows, blowup, and query
count — it does not require a prover. The estimator therefore serves any Plonky3
config on day one while proving stays narrow. Every call logs config shape and
requester, producing a demand queue ranked by real interest. No billing yet.

**Phase 2 — metered proving (~8 weeks).** Control plane, spot fleet, credits, paid
canary. Launches on today's Goldilocks profiles: a small market, but it proves the
machine end-to-end and earns the first dollar.

**Phase 3 — demand-pulled expansion (month 5+).** Build the top-ranked profile from
Phase 1 data. Multi-table plus LogUp on BabyBear/KoalaBear is expected to top it.

## Kill criteria

Decided in advance and to be honored:

- Fewer than roughly 15 distinct organizations hit the estimator within 90 days:
  the demand thesis is false; stop before building the fleet.
- Realized margin inverts on any profile: pull that rate immediately and
  automatically.
- Owner time exceeds roughly 4 hours per month for two consecutive months: cut
  scope rather than absorb it.

## Phase 4 — DEFERRED: marketplace node

Recorded deliberately. Not in scope for the current implementation plan.

The endgame and the most passive model available: run cost-advantaged capacity that
bids into external proof marketplaces. Zero go-to-market, zero support, zero
billing, zero customer relationship. The network supplies demand, escrow,
settlement, and dispute resolution; TinyZKP runs iron and collects.

**Phase 3 is the prerequisite for Phase 4.** SP1 is itself built on Plonky3 with
multi-table AIRs and LogUp on BabyBear/KoalaBear, so the engineering that opens the
direct-API market is the same engineering that makes Succinct Prover Network
compatibility possible. One investment, two demand channels. Marketplace jobs then
act as the load balancer that fills idle fleet capacity between direct customers.

Risks to carry forward:

- **Latency, not cost, is the bidding constraint.** Bounded mode is 2.4-3.1x slower
  and networks enforce deadlines with slashing. Bid on large, long-deadline jobs
  where rivals cannot run at all; never on latency-sensitive small jobs.
- **Staking and slashing** put capital at risk and create a downside tail that
  differs materially from the prepaid-credit model.
- Boundless and RISC Zero use a separate proof system and are later-or-never.

Entry sequence when the time comes: bounded multi-table BabyBear proving, then SP1
profile compatibility, then a prover node bidding selectively on large jobs, then
capacity balancing between direct API and network demand.

## Scope note

Phases 0 through 2 form one implementation plan: they share a codebase, a meter,
and a funnel, and they end at the first metered dollar. Phase 3 (profile expansion)
and Phase 4 (marketplace node) each require their own spec and plan, gated on the
Phase 1 demand data and the Phase 2 kill criteria respectively.

## Open items for the implementation plan

- Choice of serverless control-plane host and managed batch provider.
- Exact trace-cell definition and per-profile degree factor formula.
- Merchant-of-record selection for prepaid credits (the existing Lemon Squeezy
  evidence assumed subscriptions).
- Which three launch gates survive the collapse from nine.
