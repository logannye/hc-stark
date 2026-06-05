# Auditor's guide — deployed v5 / v7 soundness

A runbook for the Phase-4 external cryptographer. It pairs with:

- [`audit_checklist.md`](audit_checklist.md) — **what** to review (the in-scope
  v5/v7 forgery boundary) and the §Out-of-scope fence.
- [`soundness_proof.md`](soundness_proof.md) — the informal soundness **argument**
  and the explicit assumption (the ethSTARK Reed-Solomon **proximity-gap
  conjecture**; soundness is *conjectured*, not unconditional).
- [`threat_model.md`](threat_model.md) — adversary model.

**Soundness is conjectured under the proximity-gap conjecture and is the subject
of this engagement.** The tests below do not *prove* the conjecture; they
demonstrate that the implementation enforces what the argument requires
(forgeries rejected, floor enforced, challenges in the extension field, etc.).

## One command

```bash
./scripts/run_soundness_suite.sh
```

Runs every group below and reports `N/10 groups passed`. ~70 s on a laptop. Each
group is also runnable individually (commands in the table).

## Claim → demonstration map

| # | Soundness claim | Demonstrated by | Where | Run |
|---|---|---|---|---|
| **G2** | A high-degree (non-codeword) FRI proof is **rejected** by the v5 final-degree check — the previously-vacuous fold is closed. | `forge_poc_g2::v5_rejects_high_degree_codeword` (forges a complete, self-consistent v5 proof whose trace LDE is high-degree) | `crates/hc-verifier/src/api.rs:1336` | `cargo test -p hc-verifier forge_poc_g2` |
| **G7** | A proof below the **verifier security floor** (queries < 40, blowup < 8, grinding < 20, version < 5) is rejected *before* any crypto. | `v5_default_floor_rejects_low_{blowup,query_count,grinding_bits}`, `v7_production_floor_rejects_relaxed_proof` | `crates/hc-verifier/src/v5.rs` | `cargo test -p hc-verifier floor` |
| **1A.2** | The constraint-**composition challenge α is drawn from K = GF(p²) ≈ 2^128** (not the 2^64 base field), and the K-with-embedded-α quotient equals the old F quotient (math unchanged, entropy widened). | `v5_composition_alpha_challenges_use_k_extension`, `k_quotient_with_embedded_alpha_equals_f_quotient` | `crates/hc-prover/src/prove.rs` | `cargo test -p hc-prover alpha` |
| **Leaf** | The Fiat-Shamir transcript's extension-field challenge **binds both coefficients** (c0‖c1); c1 is non-zero (challenge is genuinely ~128-bit, not silently 64-bit). | `extension_field_challenge_nonzero_c1` | `crates/hc-hash/src/transcript.rs:163` | `cargo test -p hc-hash nonzero_c1` |
| **FRI** | An honest low-degree codeword's final-layer coefficients round-trip through commit→verify (the fold + final-degree bound accept honest proofs). | `run_fri_v5_honest_low_degree_final_coeffs_roundtrip` | `crates/hc-prover/src/pipeline/phase2_fri.rs:296` | `cargo test -p hc-prover honest_low_degree` |
| **Grind** | The proof-of-work grinding nonce satisfies the transcript-bound leading-zero-bits requirement. | `v5_grinding_nonce_satisfies_pow_roundtrip` (+ hc-hash grinding tests) | `crates/hc-prover/src/prove.rs:2646` | `cargo test -p hc-prover grinding` |
| **Det** | Proving is **byte-deterministic** (no hidden nondeterminism that could weaken Fiat-Shamir). | `v5_prove_is_deterministic` | `crates/hc-prover/src/prove.rs:2832` | `cargo test -p hc-prover deterministic` |
| **Mal** | **Malleability**: bit-flips never panic; truncation, extension, and wrong-version proof bytes are all rejected; an out-of-range v7 range witness is refused over the whole witness space. | `proptest_soundness` (`bit_flip_never_panics`, `*_causes_rejection`, `v7_range_roundtrip_in_and_out`) | `crates/hc-verifier/tests/proptest_soundness.rs` | `cargo test -p hc-verifier --test proptest_soundness` |
| **Wire** | A production v7 proof round-trips through `verify_proof_bytes` (the live entry point) under the production floor, and is byte-reproducible. | `production_v7_range_roundtrips_through_verify_proof_bytes`, `v7_range_proof_is_deterministic` | `crates/hc-sdk/src/proof.rs` | `cargo test -p hc-sdk v7_range` |
| **AIR** | Each AIR's constraints **vanish on valid witnesses and fire on tampered ones**: accumulator (acc'-acc-delta), range (booleanity + Horner + tie), sorted (booleanity + recomposition + boundary), and the general α-composition detects a single violation. | `range_air`/`sorted_air`/`accumulator_air`/`air_general` test modules | `crates/hc-air/src/*` | `cargo test -p hc-air` |

## Out of scope (fenced from every live path — see `audit_checklist.md` §Out of scope)

KZG (`hc-prover/src/kzg.rs`, recoverable toxic-waste seed, default-off, v2-pinned,
rejected by `verify_proof_bytes` `< v5`, carries a DO-NOT-USE banner); the
non-functional `contracts/StarkVerifier.sol` stub; the gated `hc-recursion`
in-circuit fold (`/aggregate` → 410); and the deprecated pre-v5
`verify_stark_v3` path (rejected by the floor). These produce no live proofs and
should not consume audit budget.

## Suggested order of review

1. Read `audit_checklist.md` (surface) and `soundness_proof.md` (argument + the
   conjecture you are validating against).
2. Run `./scripts/run_soundness_suite.sh` — confirm 10/10 green.
3. Walk the G2 forge-PoC and the verifier floor first (the forgery boundary),
   then the composition/transcript (challenge entropy), then the AIRs.
4. The binding numbers are the **deployed** parameters in
   `crates/hc-verifier/src/v5.rs` (`VerifierSecurityFloor::default`) and
   `crates/hc-prover/src/config.rs` (`SecurityFloor::default`).
