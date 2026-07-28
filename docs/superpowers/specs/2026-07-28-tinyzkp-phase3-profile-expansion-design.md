# TinyZKP Phase 3 — profile expansion beyond single-table Goldilocks

Date: 2026-07-28
Status: approved design, pending implementation plan
Parent spec: `docs/superpowers/specs/2026-07-26-tinyzkp-passive-proving-utility-design.md`
Predecessor: `docs/superpowers/specs/2026-07-27-tinyzkp-hosted-estimator-design.md`
Builds on: `main` @ `033520c` (Phases 0, 1a, 1b shipped)

## Why this phase exists

The parent spec's staging argument ends here. Phase 1a built an estimator that
prices any configuration. Phase 1b put it on the network so the demand log can
say which configuration people actually bring. Phase 2 (ledger, credits,
merchant-of-record, fleet) builds the machinery to charge — but charging
requires something worth buying, and today the engine proves exactly one thing:
a single-table AIR over Goldilocks with a degree-3 constraint bound, verified by
`p3_uni_stark` 0.6.1.

Approximately nobody in the Plonky3 ecosystem runs that. SP1, Valida, and every
zkVM-shaped workload are multi-table with cross-table lookups, on a 31-bit field.
**Phase 3 is the phase where TinyZKP acquires a market, and it is therefore the
phase that gates the first dollar — not Phase 2.**

## The governing finding

**Plonky3 0.6.1 ships no interaction argument at all.**

This was verified directly against the pinned sources, not inferred:

- `p3_uni_stark::prove(config, air, trace, public_values)` takes exactly one AIR
  and one trace (`p3-uni-stark-0.6.1/src/prover.rs:379-394`). Its only richer
  entry point, `prove_with_preprocessed` (`prover.rs:24-38`), adds preprocessed
  columns — not tables.
- Grepping `p3-air-0.6.1/src/` and `p3-uni-stark-0.6.1/src/` for
  `logup|LogUp|Interaction|interaction` returns **zero matches**.
- There is no `Machine`, `Chip`, or multi-table abstraction anywhere in either
  crate.

The upstream projects that do multi-table proving build that layer themselves —
SP1's `sp1-stark` is the reference example. So "add multi-table and LogUp" is not
an integration task against an upstream feature. It means **TinyZKP authoring a
new proof system layer**, with its own soundness argument and its own verifier.

That single fact reshapes the whole phase, because of what it collides with:

> "The proof remains ordinary. … The ordinary Plonky3 verification path."
> — `site/index.html:64,67`

`VERIFIER = "p3_uni_stark_0.6.1"` is pinned at `tinyzkp-contracts/src/lib.rs:23`,
asserted in `hc-plonky3/src/contracts.rs:193` and `:408`, emitted at six further
sites, test-pinned at `hc-cli/tests/cli_roundtrip.rs:145,158,250`, and folded into
`CheckpointIdentityV2`. The claim that verification uses stock upstream code is
the load-bearing trust proposition of the entire product, and a TinyZKP-authored
multi-table verifier retires it.

This repository has been wrong about home-rolled cryptography before — the
2026-05-29 audit found the then-current core unsound on three counts. Any design
that puts a new interaction argument on the critical path must treat that as
evidence about this codebase, not as ancient history.

## The decomposition

The instinct is to treat "multi-table + LogUp on BabyBear" as one deliverable. It
is three, with sharply different cost, risk, and claim consequences. Only the
third is new cryptography.

| Sub-phase | What it adds | New crypto? | Verifier | Opens the market? |
|---|---|---|---|---|
| **3A** Field generalization | BabyBear / KoalaBear single-table | No | stock `p3_uni_stark` | No |
| **3B** Multi-table scheduling | N tables under one RAM ceiling | No | stock `p3_uni_stark`, per table | Partly |
| **3C** LogUp interactions | cross-table lookup soundness | **Yes** | **TinyZKP-authored** | Yes |

### 3A — Field generalization

**The dependency cost is far lower than assumed.** Every normal dependency of
`p3-baby-bear` 0.6.1 (`p3-challenger`, `p3-field`, `p3-mds`, `p3-monty-31`,
`p3-poseidon1`, `p3-poseidon2`, `p3-symmetric`, `rand ^0.10.1`) is *already
resolved in the frozen lock* — `p3-monty-31` arrives transitively through
`p3-challenger`, and `rand 0.10.2` already satisfies the requirement. Adding
BabyBear therefore adds **exactly one package entry** to `Cargo.lock`, with zero
version bumps. The re-freeze across the eight pin sites plus `fuzz/Cargo.lock`
and `clients/rust/Cargo.lock` is routine, and is the same drill Phase 1b Task 1
already executed successfully.

**The estimator needs no arithmetic change.** `canonical_extension_degree`
(`estimate_params.rs:366-372`) already prices `babybear`, `koalabear`, and
`mersenne31` at 4-byte base and degree 4. Phase 1a built the cost model
field-generic on purpose. Only the admission gate at
`tinyzkp-contracts/src/lib.rs:613-614` — `self.field != FIELD ||
self.extension_degree != EXTENSION_DEGREE` — has to learn a second profile.

**The real work is the durable scratch element.** `GoldilocksWord`
(`hc-plonky3/src/dft.rs:36`) is the on-SSD element format: `CanonicalElement`
with `WIDTH = 8` (`dft.rs:51`), encoded as `as_canonical_u64().to_le_bytes()`
(`dft.rs:54`). BabyBear is a 31-bit Monty-form field with a 4-byte
representation, so every scratch file layout, every offset computation, and every
checksum over that layout changes. `ScratchMatrixStore` and `BlockMatrix` become
generic over the element width in a way they currently are not, and
`DurableGoldilocksMmcs` (`bounded_pcs.rs:15`) must follow.

**Density of the coupling**, by Goldilocks references per file: `fri.rs` 111,
`mmcs.rs` 103, `dft.rs` 100, `hc-fri/src/simd_fold.rs` 84, `hc-simd/src/neon.rs`
70. This is mechanical but broad.

**Honest performance consequence.** `hc-simd` implements packed Goldilocks for
AVX2 and NEON, selected by a runtime `TypeId` check (`hc-fri/Cargo.toml:24-25`).
BabyBear will fall through to the scalar path until equivalent packed kernels
exist. The 3A benchmark numbers must be published with that caveat attached and
must not be presented as the field's steady-state performance.

**A cost-model caveat that is already live.** `/v1/estimate` answers BabyBear
queries today, and `estimate_params.rs:145-158` documents in-code that one term
of `quotient_transform_peak` is not verified for non-Goldilocks fields: the fixed
`+3` chunk-equivalent floor is inferred only from the algebraic relation
`192 = 3 * 64`, and for Goldilocks `192` is equally consistent with
`6 * digest_bytes` or `24 * field_bytes`. No current test holds `ext_field_bytes`
and `digest_bytes` apart, so the unit attribution — and therefore the term's
scaling to a 4-byte field — is unestablished. The comment names the remedy
explicitly: *"if a BabyBear/KoalaBear/Mersenne31 estimate is ever contradicted by
measurement, start here."* **3A must begin by measuring a real BabyBear run
against the estimator's prediction and correcting the term**, because 3A is the
first point at which that prediction becomes checkable. Until then the published
BabyBear numbers carry a known, documented uncertainty on one term.

**Contract-versioning consequence.** `ProfileIdentifierV1`
(`tinyzkp-contracts/src/lib.rs:397-400`) has exactly two variants, one of them
`TinyzkpP3GoldilocksV1`. A second profile adds a variant to an enum published in
`reason-v1.schema.json`, which is in `PUBLISHED_SCHEMA_NAMES` and ships signed
with releases. Because the contract structs use `deny_unknown_fields`, an older
consumer meeting the new variant fails rather than degrading. This needs an
explicit compatibility decision before implementation, not during.

**What 3A does not do:** it does not open the market. A BabyBear *single-table*
uni-STARK is still not what SP1 users run. 3A is a prerequisite that is honestly
sellable on its own terms (bounded-RAM proving on the ecosystem's dominant field)
and is worth doing first because it carries no soundness risk.

### 3B — Multi-table scheduling, without interactions

This is the design call that most changes the cost of Phase 3.

The memory advantage of multi-table proving lives **entirely in the scheduler,
not in the transcript.** A workload with twelve chips fails on a fixed-RAM box
because the twelve traces, their low-degree extensions, and their Merkle trees do
not fit simultaneously. Proving them sequentially under one shared
`max_resident_bytes` ceiling with checkpointed handoff solves exactly that
problem — and that is TinyZKP's whole thesis.

Doing so requires **no new cryptography at all**, provided each table is proved
as its own `p3_uni_stark` proof verified by the stock verifier. The scheduler,
the shared ceiling, the scratch lifecycle, and the resume path are all TinyZKP
code operating *above* an unmodified upstream prover.

The tempting alternative — one shared challenger transcript across all tables —
buys proof-size and a small performance win, and costs the ordinary-verifier
claim. **Recommendation: do not share the transcript in 3B.** Take the memory
result, keep the stock verifier, and defer every transcript change to 3C where
the claim is being retired anyway for other reasons.

Honest framing requirement: 3B is a *batching and scheduling* result. It proves N
tables inside a fixed budget. It says nothing about whether those tables are
consistent with each other — that linkage is precisely what LogUp provides and
what 3B does not. Marketing copy must not blur the two.

### 3C — LogUp interactions

The actual new cryptography: per-table permutation traces, cross-table cumulative
sums, challenge derivation for the log-derivative argument, and a verifier that
checks the sums reconcile.

Two assets already exist and reduce the build:

- `p3_air::virtual_column::VirtualPairCol` (`p3-air-0.6.1/src/virtual_column.rs:81`)
  is the standard interaction-expression building block — present upstream,
  unused by `p3-uni-stark`. It is the same primitive SP1's interaction layer is
  built on.
- `DeclarativeAir` / `AirPackageV1` (`hc-plonky3/src/declarative.rs:14-60`)
  already gives callers a way to author their own AIR as an expression DAG
  (`Constant`, `Public`, `Current`, `Next`, `Add`, `Sub`, `Mul`). It needs
  interaction and bus nodes and a multi-table container — an extension of a
  working design, not a new one.

Non-negotiable conditions on 3C:

1. **It retires the ordinary-verifier claim.** Every site page, schema, and
   constant asserting `p3_uni_stark_0.6.1` must be revised in the same change
   that ships it. Shipping a TinyZKP verifier while the homepage still says
   "the ordinary Plonky3 verification path" would be a false public claim.
2. **It must not ship on self-attestation.** The evidence-gating machinery
   (`guard_launch_gate.py`, signed `guard-launch-evidence-v2.json`) governs
   commercial claims, but a soundness argument is not the kind of thing an
   owner-signed boolean establishes. External cryptographic review is a hard
   prerequisite, given the 2026-05-29 finding.
3. **Its cost model does not exist yet.** Permutation traces add per-table
   columns that `estimate_from_params` does not represent at all. The
   coefficients must be derived and measured for the new shape, and the
   WASM/CLI parity gate (`scripts/ci/estimate_wasm_cli_parity_gate.mjs`)
   extended to cover it.

## The alternative architecture worth naming

There is a second route to "runs what the market actually runs" that skips 3C
entirely: **be the bounded-memory backend inside an existing multi-table prover**
rather than authoring one.

SP1's prover is open source, and its hot loop is per-chip DFT, Merkle
commitment, and FRI — exactly the three primitives TinyZKP has already rebuilt
against a resident-byte ceiling. Substituting TinyZKP's bounded primitives for
the in-memory ones is an integration. The interaction argument stays SP1's, the
soundness surface stays SP1's, and the verifier stays SP1's verifier. No new
cryptography, no retired claim, and the result runs real workloads.

The honest catch: TinyZKP becomes a component inside someone else's prover. That
is materially harder to charge for directly than a product with its own surface,
and it takes a dependency on an upstream that TinyZKP does not control and that
moves fast. It is a real tradeoff, not a free lunch.

It is also the direct prerequisite for the deferred Phase 4 marketplace node,
where the deliverable is cost-advantaged capacity bid into an existing network —
a role that wants exactly this shape.

## Recommendation

**Sequence: 3A → 3B → decision gate → (3C or backend integration).**

3A and 3B are unconditionally correct. They carry no soundness risk, they retire
no public claim, they are the prerequisite for either endgame, and 3B alone
delivers a demonstrable version of the core promise on realistically-shaped
workloads.

The choice between 3C and the backend-integration route should **not** be made
now. Phase 1b exists precisely to replace this guess with evidence: the demand
log's `blocking_reason_codes` distribution over distinct organizations is the
empirical answer to which profile to fund. Committing months of new cryptographic
engineering before that log has produced its first keyed organization would be
the exact mistake Phase 1b was built to prevent.

State the gate concretely so it cannot be quietly skipped: **the 3C-versus-
integration decision is made when the demand report returns `CONTINUE`** — that
is, once at least 15 distinct keyed organizations appear in a rolling 90-day
window (`scripts/ci/demand_report.py`, `KILL_THRESHOLD_ORGANIZATIONS = 15`). Until
then the report reads `KILL_THRESHOLD_MET` by construction, because free keys are
not yet issued and every `key_id` is `NULL`. That is the documented, expected
pre-key state, not a verdict about the thesis.

## Revenue consequence, stated plainly

Neither 3A nor 3B is likely to produce revenue on its own. Bounded-RAM proving of
single-table BabyBear, or of N independent tables, is a real capability that a
small number of teams will find valuable; it is not the SP1-shaped market.
Charging still additionally requires Phase 2 — ledger, credits, merchant-of-
record, fleet — none of which exists (`checkout_enabled: false`,
`commerce_state: unconfigured`, `product_id: null`).

The realistic ordering to a first dollar is: **3A → 3B → demand gate → market
unlock (3C or integration) → Phase 2 commerce.** Building Phase 2's toll booth
before the market unlock puts a payment surface on a road with no traffic.

## Claim discipline for this phase

- Publish 3A benchmarks with the scalar-fallback caveat stated inline, never as
  bare comparative figures against Goldilocks.
- Describe 3B as scheduling and batching under a shared ceiling. Do not describe
  it as multi-table proving in a sense that implies cross-table consistency.
- Do not advertise 3C in any tense before external review completes.
- The `/estimate` endpoint already returns `provable_today: false` with precise
  blocking reasons for configurations outside the profile. That honesty is an
  asset; each sub-phase moves specific reason codes off the blocking list and
  must not move any code off it before the corresponding capability lands.

## Out of scope

Preprocessed columns are **not** in this phase, but should be recorded as
unusually cheap: upstream already implements them (`setup_preprocessed`,
`prove_with_preprocessed`, `p3-uni-stark-0.6.1/src/preprocessed.rs:13,32,48`), so
`uses_preprocessed_columns` is the least expensive of the eight blocked feature
flags to support. It is a candidate for opportunistic inclusion in 3A if the
demand log ranks it highly.

Also out of scope: recursion (`uses_recursion`), GPU execution (`uses_gpu`),
raising `MAX_ROWS` above 2^24, the Phase 2 commerce stack, and the Phase 4
marketplace node.

## Open items for the implementation plan

- Compatibility decision for the additive `ProfileIdentifierV1` variant against
  `deny_unknown_fields` consumers: new variant, versioned schema, or a
  string-typed profile field.
- Whether `ScratchMatrixStore` becomes generic over element width or gains a
  second concrete element type; the checksum and header implications of each.
- Whether 3B's scheduler checkpoints between tables or only within them.
- Bench fixtures for BabyBear: the current fixtures (`fibonacci-1m.json`,
  `fibonacci-16m.json`, Poseidon2) are Goldilocks-shaped and pin the measured
  RAM and CPU baselines.
- Which packed-field kernels, if any, 3A ships for BabyBear versus defers.
- Whether the fixed-host qualification run that would move `backend_gate_status`
  to `qualified` should precede 3A, since it is already required to unblock
  `/estimate` indexing and any backend release.
