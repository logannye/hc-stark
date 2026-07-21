# Informal Soundness Argument

> **Legacy research — not production evidence.** This historical argument does
> not qualify the supported Guard profile or establish a production claim.

> **Status — conjectured, pending external audit.** The soundness of hc-stark
> rests on the same **proximity-gap conjecture** that every production FRI-STARK
> relies on (the "ethSTARK conjecture"; see References). Under that conjecture
> the deployed parameters target a **conjectured ~128-bit** soundness level —
> this is **not an unconditional bound**, and no specific bit figure is
> advertised to customers until an independent external cryptographer audit
> (Phase 4) signs off. This document is an informal argument, not a proof.

## Overview

hc-stark implements an FRI-based STARK over the Goldilocks field
(p = 2^64 − 2^32 + 1). All soundness-critical challenges (FRI folding
challenges and the constraint-composition challenge) are drawn from the
**quadratic extension** K = GF(p²) ≈ 2^128, so challenge-collision and
composition-soundness terms are governed by |K| ≈ 2^128, not by the 2^64 base
field. The argument below is that no efficient adversary can produce a verifying
proof of a false statement except with probability negligible under the stated
assumptions.

## Protocol Structure

1. **Trace commitment**: the prover commits to the (width-N) execution trace via
   a Merkle tree over its low-degree extension (LDE) evaluations (Blake3 leaves).
2. **Constraint composition**: the verifier checks C(x) = Q(x)·Z_H(x), where the
   composed constraint C is a random K-linear combination of the AIR constraints
   under a single composition challenge drawn from K, and Q is the quotient.
3. **FRI low-degree test**: the prover demonstrates that Q has degree < |H| via
   FRI — a proximity test for the Reed-Solomon code of rate ρ = 1/blowup.
4. **Grinding + query phase**: after a proof-of-work grind over the transcript,
   the verifier spot-checks consistency between the committed evaluations and the
   FRI chain at `query_count` pseudo-random locations.

## Soundness Argument

### Step 1: Commitment Binding

Merkle commitments use Blake3. Under Blake3 collision-resistance the prover
cannot open a committed leaf to two different values, so the committed trace and
FRI layers are binding.

**Assumption**: Blake3 is collision-resistant (256-bit digest).

### Step 2: FRI Soundness (proximity gap)

FRI is a **proximity test**, and its soundness is **not** the naive
Schwartz-Zippel form `(degree/|F|)^q`. It is governed by the **proximity gap**
for Reed-Solomon codes (Ben-Sasson–Carmon–Ishai–Kopparty–Saraf): if the
committed function is δ-far (in relative Hamming distance) from the
rate-ρ = 1/blowup code, then with overwhelming probability over the folding
challenges every FRI layer stays correspondingly far from its code, and each of
the `query_count` independent query openings then catches the inconsistency with
probability ≈ δ. The per-query soundness error is therefore bounded by a function
of the **code rate ρ**, not by trace degree over field size:

- **Conservative (provable up to the 1 − √ρ regime):** per-query error ≈ √ρ, i.e.
  ≈ log₂(1/√ρ) bits per query. For the deployed blowup 8 (ρ = 1/8): ≈ 1.5
  bits/query.
- **Conjectured (ethSTARK proximity-gap conjecture, per-query error ≈ ρ — the
  regime production STARKs operate in):** ≈ log₂(1/ρ) bits per query. For ρ = 1/8:
  ≈ 3 bits/query.

The folding challenges and the FRI consistency are evaluated over K ≈ 2^128, so
the challenge-soundness term is ≈ 2^−128 and is not the bottleneck; the operative
term is the query count, amplified by grinding (below).

**Assumption**: the ethSTARK proximity-gap conjecture for Reed-Solomon codes.

**References**: Ben-Sasson et al., *Fast Reed-Solomon IOPP* (ICALP 2018);
Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, *Proximity Gaps for Reed-Solomon
Codes* (FOCS 2020); StarkWare, *ethSTARK Documentation* (ePrint 2021/582).

### Step 3: Constraint Soundness

If the trace violates the AIR constraints, C does not vanish on H, so
Q = C/Z_H is not a polynomial of the claimed degree, and Step 2 rejects it. The
constraint composition uses a single challenge drawn from K, so the probability
that an unsatisfied constraint system composes to the zero polynomial is bounded
by n_c · d / |K| ≈ (constraint count · max degree) / 2^128, which is negligible.

### Step 4: Fiat-Shamir Security

The protocol is made non-interactive with Fiat-Shamir: every verifier challenge
is derived by hashing the full prior transcript with Blake3, and a proof-of-work
**grind** (deployed floor: 20 leading-zero bits) is bound into the transcript
before the query challenges, raising the cost of transcript-grinding attacks by
≈ 2^20.

**Assumption**: Blake3 behaves as a random oracle for transcript hashing.

**Reference**: Canetti, Goldreich, Halevi, *The Random Oracle Methodology,
Revisited* (STOC 1998).

### Step 5: Zero-Knowledge (opt-in; not the default)

ZK masking is **opt-in and off by default** (`ZkConfig` default = disabled,
`zk_mask_degree = 0`): the default proof is a sound STARK that is *not*
zero-knowledge, and the single live template (`accumulator_step`) ships non-ZK.

When enabled for a **degree-1** AIR, a random polynomial R of degree
`zk_mask_degree` is added as T′(x) = T(x) + R(x)·Z_H(x). Since R·Z_H vanishes on
H, completeness is preserved, and the out-of-domain LDE evaluations are
masked.

**Limitation (degree ≥ 2):** this additive trace mask is degree-incompatible
with constraints of degree ≥ 2 — it raises the masked-trace degree past the FRI
bound, so it cannot be used to make e.g. a `range_proof` (degree-2 booleanity)
zero-knowledge; the query openings would still leak witness information. Genuine
ZK for non-trivial predicates requires randomized trace rows (Winterfell-style)
and is deferred (gated behind the Phase 4 audit); the worked degree-2 analysis
ships as `docs/security/zk_range.md` alongside the Phase 1B range AIR. **Do not
assume input hiding for any template until ZK is explicitly certified for it.**

## Known Limitations

1. **Conjectured, not proven**: soundness is contingent on the ethSTARK
   proximity-gap conjecture (Step 2). No unconditional bound is claimed, and no
   bit figure is advertised pre-audit.
2. **Zero-knowledge is partial**: ZK is opt-in and currently sound only for
   degree-1 AIRs; degree-≥2 ZK is deferred (Step 5).
3. **Metrics not bound**: the proof's non-cryptographic metrics fields (timing,
   block counts) are not in the Fiat-Shamir transcript; modifying them does not
   affect verification (they carry no security claim).
4. **Single hash function**: Blake3 is used for both commitments and
   Fiat-Shamir; a Blake3 break would compromise both. Dual-hash (Blake3 +
   Poseidon) is planned for recursion.

## Concrete Security Parameters (deployed)

The **verifier security floor** is the binding minimum: a proof below it is
rejected before any cryptographic checks
(`crates/hc-verifier/src/v5.rs`, `VerifierSecurityFloor::default`). The prover
emits stronger parameters (`crates/hc-prover/src/config.rs`,
`SecurityFloor::default`).

| Parameter | Verifier floor | Prover (emitted) | Security contribution |
|-----------|----------------|------------------|----------------------|
| Min proof version | 5 | 5 / 7 | rejects the pre-v5 (unsound-fold) path |
| Query count | 40 | 80 | per-query proximity error (Step 2) |
| LDE blowup (rate ρ) | 8 (ρ = 1/8) | 8 | sets per-query error ≈ √ρ … ρ |
| Grinding | 20 bits | 20 bits | ≈ 2^20 transcript-grind cost |
| Challenge field | K = GF(p²) ≈ 2^128 | K ≈ 2^128 | folding + composition soundness |
| Blake3 digest | 256 bits | 256 bits | commitment binding, Fiat-Shamir |
| FRI folding ratio | 2 | 2 | degree halving per round |

**Conjectured soundness (deployed, illustrative).** Query term at blowup 8:
≈ 40 × 1.5 = 60 bits conservative (√ρ regime) to ≈ 40 × 3 = 120 bits under the
ethSTARK conjecture (ρ regime), plus ≈ 20 grinding bits ⇒ a **conjectured ~80–140
bit** level at the verifier floor (higher at the prover's 80 queries). We
therefore describe hc-stark as targeting a **conjectured ~128-bit** soundness
level. This figure is **contingent on the proximity-gap conjecture and on the
pending external audit**; it is not advertised as an unconditional guarantee, and
customers should not rely on a TinyZKP proof as a sole high-value attestation
until that audit completes.
