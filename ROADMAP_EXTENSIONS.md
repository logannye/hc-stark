# hc-stark Extensions Roadmap

This document defines the phased plan to extend hc-stark — and TinyZKP.com's
commercial API — beyond accumulator-style STARK templates into the four
ZKP application domains where the height-compression discipline produces
the largest commercial leverage.

The four pillars (and their workspace crates) are:

| Pillar | Crate | Application | Phase |
|--------|-------|-------------|-------|
| Verifiable AI inference | [`hc-zkml`](crates/hc-zkml) | zkML (model attestation, AI provenance) | 1 |
| General-purpose execution | [`hc-zkvm`](crates/hc-zkvm) | RV32I-class zkVM (zkEVM, zkApps) | 2 |
| Sumcheck IOPs | [`hc-sumcheck`](crates/hc-sumcheck) | Spartan / HyperPlonk / Jolt-class workloads | 3 |
| Inner product arguments | [`hc-ipa`](crates/hc-ipa) | Bulletproofs / range proofs / confidential txns | 4 |

All four crates currently ship the public API surface and locked-in type
contracts. Cryptographic bodies return `HcError::unimplemented` until the
corresponding phase lands. Type-level contracts are enforced by unit tests
in each crate so that Phase-N implementation work cannot silently change
the public shape of the API.

---

## Architectural ground rules

These apply uniformly across all four pillars. They are not negotiable —
they are the invariants that make the √T promise hold across the entire
TinyZKP product surface.

1. **Verifier invariance.** Whatever the prover does internally, verifiers
   see the same protocol bits as the corresponding standard system
   (STARK / RV32I AIR / sumcheck / Bulletproofs). No bespoke verification
   for hc-stark customers; existing client tooling and on-chain verifier
   contracts work unmodified.

2. **Constant-size interfaces.** Every block / tile / round boundary
   commits to an `O(1)`-machine-word checkpoint. The prover never needs
   to walk back across more than `O(log T)` of these at once.

3. **Replay-from-witness.** Intermediate state (activations, memory pages,
   hypercube tiles, vector entries) is regenerated on demand from the
   witness plus a constant-size index. Never stored, never paged to disk.

4. **`HcError` everywhere.** All public functions return `HcResult<T>`.
   Library code never panics. Configuration validates at the boundary.

5. **`#![forbid(unsafe_code)]`.** Without exception. SIMD acceleration
   lives in `hc-simd` behind a safe trait surface.

---

## Phase 1 — `hc-zkml` (verifiable AI inference)

**Commercial framing:** the highest immediate revenue line item. AI
attestation, model provenance, on-chain ML inference, regulator-facing
"the output came from the registered weights" proofs.

### Deliverables

- [x] Public API: `prove_inference`, `verify_inference`, `ModelGraph`,
      `Tensor`, `Quantization`, `ModelCommitment`.
- [x] Quantization model (symmetric int4/int8/int16) and tensor validation.
- [ ] **Tiled MatMul AIR.** Decompose `C = A·B` into `√K`-sized inner-dim
      tiles. Each tile is a self-contained sub-proof; tile boundaries are
      partial-sum checkpoints.
- [ ] Pointwise activations (`ReLU`, `Add`, fused bias) as transition
      constraints.
- [ ] Approximated `Softmax` via a fixed-point exponentiation table + sum
      reduction tree (kept cheap by quantizing the log-domain).
- [ ] `Conv2d` lowered to `im2col + MatMul`.
- [ ] ONNX-subset frontend (`hc-zkml-frontend` crate, future) so customers
      can submit `(model.onnx, input.npy)` instead of hand-rolling AIR.
- [ ] TinyZKP API templates: `zkml_inference`, `zkml_attestation`.

### Risk register

- **Quantization accuracy regressions.** Symmetric int8 is fine for most
  inference; transformers may need int16 or bfloat16-via-pairs. Plan to
  ship int8 first and add bfloat16 later via column-pair representation.
- **Softmax in-AIR cost.** Worth benchmarking a precomputed-table approach
  vs. a polynomial approximation early.

### Pricing tier

Trace cycles dominated by `Σ over layers (M·N·K)` for matmuls. Existing
`/estimate` endpoint will surface the cycle estimate; the `> 10M cycles`
tier ($30/proof) is the realistic landing zone for medium models.

---

## Phase 2 — `hc-zkvm` (general-purpose RV32I execution)

**Commercial framing:** competes with Risc0, SP1, Jolt for arbitrary-program
proving. Largest individual workload sizes in the industry, so largest √T
memory advantage in absolute terms.

### Deliverables

- [x] Public API: `prove_execution`, `verify_execution`, `RvInstr`,
      `RegFile`, `Memory`, `RiscvProgram`.
- [x] RV32I instruction enum (R/I/S/B/U/J types + ECALL/EBREAK).
- [ ] **Block-streaming trace generator.** Re-execute blocks from a
      constant-size `(reg_file, memory_root, pc)` checkpoint at each block
      boundary; never hold more than one block of trace in memory.
- [ ] Per-instruction-type AIR transition constraints (R / I / S / B / U / J).
- [ ] Page-Merkle commitment for memory; the AIR proves consistency between
      load/store instructions and the committed memory root.
- [ ] Host I/O via `ECALL`: input and output ring buffers committed into
      the public transcript.
- [ ] ELF subset loader (no dynamic linking, no `.bss` magic).
- [ ] Reference toolchain: `riscv32i-unknown-none-elf` cross-compile target,
      `cargo` template repo for customers.
- [ ] TinyZKP API templates: `zkvm_execution`, `zkvm_attested_compute`.

### Risk register

- **Memory-Merkle blowup.** Large heap-using programs touch many pages;
  page-Merkle authentication paths can dominate proof size. Plan to use
  per-block "touched page list" deltas committed against a running root.
- **Branch-heavy programs and speculative re-execution.** AIR cost per
  branch is non-trivial. Mitigated by aggressive block sizing.

### Pricing tier

Cycle count is the price knob; `>10M cycles` ($30/proof) is the realistic
landing zone for non-trivial programs.

---

## Phase 3 — `hc-sumcheck` (sumcheck-based IOPs)

**Commercial framing:** protocol-level diversification. Enables
Spartan-class proofs (over R1CS) and HyperPlonk-class proofs (over PLONK
constraints) without giving up the √T memory budget. Lower per-customer
revenue per proof than Phase 1/2, but unlocks the customer base of teams
that have already built circuits against Spartan/HyperPlonk and want a
lower-memory backend.

### Deliverables

- [x] Public API: `prove_sum`, `verify_sum`, `SumcheckPolynomial` trait,
      `SumcheckClaim`, `SumcheckProof`, `SumcheckRoundMsg`.
- [ ] **Streaming hypercube traversal.** Tile-by-tile evaluation; round
      messages are constant-size; tile size is a hot-reload config knob.
- [ ] `MultilinearExtension` — a streaming dense MLE that replays values
      from a witness commitment.
- [ ] Spartan adapter crate (`hc-sumcheck-spartan`, future): R1CS → 3
      sumcheck rounds.
- [ ] HyperPlonk adapter crate (`hc-sumcheck-hyperplonk`, future): PLONK
      constraint system → boolean-hypercube sumcheck.
- [ ] TinyZKP API templates: `r1cs_proof`, `hyperplonk_proof`.

### Risk register

- **Polynomial-evaluation hot path.** The trait method `evaluate_on_slice`
  is called millions of times per proof; the abstraction must compile away
  to inlined arithmetic. Keep the trait small.
- **Curve / field choice.** Sumcheck systems typically run over BN254 or
  BLS12-381 for elliptic-curve compatibility; plan to expose both via a
  generic field trait.

### Pricing tier

Round count grows linearly with `n` (variables). Cycle counts are smaller
than Phase 1/2 for equivalent-strength claims, so most customers will land
in the `100K–1M` ($2/proof) tier.

---

## Phase 4 — `hc-ipa` (Bulletproofs / IPA / range proofs)

**Commercial framing:** confidential transactions, regulator-friendly
range attestations, batch credential proofs. Per-proof revenue is small
(short proofs, fast verifies), but volume is high — payments and DeFi
workloads can drive millions of proofs per month.

### Deliverables

- [x] Public API: `prove_inner_product`, `verify_inner_product`,
      `prove_range`, `IpaStatement`, `IpaProof`, `RangeProof`,
      `IpaVectorSource` trait.
- [ ] **Streaming fold.** Round-by-round halving via `IpaVectorSource` —
      vector entries pulled in tiles, folded results written back.
- [ ] Pedersen-commitment integration over BN254 / BLS12-381 / curve25519.
- [ ] Bulletproofs range-proof wrapper for `[0, 2^n)` claims up to `n=64`.
- [ ] Aggregation: prove `K` range claims with shared rounds (cost ≈
      `O(K + log(N·K))`).
- [ ] TinyZKP API templates: `confidential_range`, `aggregated_attestation`.

### Risk register

- **Curve operations dominate runtime.** Unlike Phases 1–3, the bottleneck
  is group ops, not field ops. Plan to use `arkworks` MSM acceleration and
  make GPU offload an option from day one.
- **Verifier wants very fast.** Customers expect Bulletproofs verification
  in single-digit milliseconds; preserve the standard verifier completely.

### Pricing tier

Sub-millisecond traces on modest hardware; this is the `< 10K` ($0.05/proof)
tier and the natural fit for the highest-volume Free / Developer plan
workloads.

---

## Cross-phase deliverables

These cross-cut all four pillars and ship in parallel as each phase
matures.

- **Workload registry & MCP integration.** Each new template is registered
  via `inventory::submit!` in `hc-workloads/src/templates/`, becoming
  immediately discoverable through the `/templates` API and the MCP
  `list_workloads` / `submit_workload` tools.
- **`/estimate` endpoint extensions.** Cost / time / proof-size estimators
  per pillar so agents can preflight without authentication.
- **WASM verifier extensions.** `@tinyzkp/verify` already verifies STARK
  proofs in the browser; extend with sumcheck and IPA verifiers (the
  ZKML / zkVM proofs are STARK-format and reuse the existing path).
- **Stripe pricing tiers.** Per-pillar pricing knobs in
  `billing/billing-cron`; usage emission already supports per-template
  cost categories.
- **Per-pillar fuzzing harnesses.** `fuzz/` already scaffolds STARK
  fuzzers; clone for each new prover.
- **Documentation.** Each pillar gets a chapter in `docs/whitepaper.md`
  and a customer-facing guide on tinyzkp.com/docs.

---

## Phase ordering & dependencies

Phases can ship in parallel by separate teams, but the recommended order
is:

1. **Phase 1 (zkml) first** — highest revenue, reuses existing STARK
   prover, minimal new cryptographic surface.
2. **Phase 2 (zkvm) second** — depends on Phase 1's tiled-trace
   discipline and benefits from the same AIR infrastructure.
3. **Phase 3 (sumcheck) third** — protocol-level work; can be built
   without blocking Phase 1/2 but doesn't itself unblock revenue until
   Spartan / HyperPlonk adapters land.
4. **Phase 4 (ipa) fourth** — different cryptographic family entirely
   (group ops, not field ops); benefits from being last because it can
   borrow lessons from the streaming discipline of the earlier phases.

Each phase is gated on:

- Full test parity vs. a reference (non-streaming) implementation, run as
  part of the existing `./scripts/test_suite.sh all`.
- Benchmark regression gates: peak RSS must be `O(√T)` empirically across
  three trace sizes per pillar.
- Customer-facing docs and API templates landed on TinyZKP.com.
- Pricing tier published; Stripe metering wired.

---

## Out-of-scope (for now)

The following ZKP families were considered but excluded from this roadmap.

- **Folding schemes (Nova / SuperNova / HyperNova / ProtoStar).** Already
  benefit less from √T because their accumulator is `O(1)` by design;
  the bottleneck is the final SNARK over the accumulated instance, which
  we'd handle via Phase 3 (sumcheck) or Phase 2 (zkvm) anyway.
- **VOLE-based / garbled-circuit ZK.** Communication-bound, not memory-
  bound — height compression doesn't help.
- **Lattice-based ZK (LaBRADOR / Greyhound).** Active research area; not
  enough customer demand yet to justify a fifth crate.

These can be added later if customer pull warrants. The four pillars in
this roadmap cover the bulk of commercial ZK demand as of 2026.
