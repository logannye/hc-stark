//! Higher-degree sumcheck via product-of-multilinears polynomials.
//!
//! ## Why this module exists
//!
//! [`crate::prover::prove`] handles the multilinear (degree 1 per round)
//! case — sufficient for vanilla GKR / dense MLE checks but not for the
//! workloads that drive most modern SNARKs:
//!
//! - **Spartan** reduces R1CS to a sumcheck of `eq_τ(x) · (Aw·Bw - Cw)(x)` —
//!   a product of three multilinears in the cubic part, so each round
//!   message has degree 3.
//! - **HyperPlonk** sumchecks an algebraic combination of selector and
//!   wire polynomials whose degree depends on the gate definition.
//! - **Lasso / Jolt** lookups produce degree-2 product sumchecks.
//!
//! This module exposes a generic [`ProductPoly`] that represents a
//! polynomial of the form `g(x) = ∏_i p_i(x)` where each `p_i` is
//! multilinear. The prover emits degree-`k` round messages (where `k` is
//! the number of factors); the verifier interpolates each round message at
//! the sampled challenge via Lagrange.
//!
//! ## Field-element interpolation points
//!
//! Round messages are encoded as evaluations on consecutive integer points
//! `0, 1, ..., k`. The verifier reconstructs `s(r)` for a field-element
//! challenge `r` via barycentric Lagrange interpolation.

use crate::proof::{SumcheckClaim, SumcheckProof, SumcheckRoundMsg};
use crate::prover::MultilinearPoly;
use crate::HcSumcheckConfig;
use hc_core::field::{FieldElement, GoldilocksField as F};
use hc_core::{HcError, HcResult};
use hc_hash::{Blake3, Transcript};

/// Lagrange interpolation: given evaluations `values[i] = s(i)` for
/// `i = 0..values.len()`, return `s(r)` for an arbitrary field point `r`.
///
/// Errors if a denominator inverse fails (impossible for distinct integer
/// nodes in a prime field of characteristic > deg, which holds for any
/// real degree we use here against Goldilocks).
pub fn lagrange_interpolate_at(values: &[F], r: F) -> HcResult<F> {
    if values.is_empty() {
        return Err(HcError::invalid_argument(
            "lagrange_interpolate_at: empty values",
        ));
    }
    let n = values.len();
    let mut acc = F::ZERO;
    for (i, vi) in values.iter().enumerate().take(n) {
        // L_i(r) = ∏_{j != i} (r - j) / (i - j)
        let mut num = F::ONE;
        let mut den = F::ONE;
        for j in 0..n {
            if j == i {
                continue;
            }
            let rj = F::new(j as u64);
            num = num.mul(r.sub(rj));
            let ij = if i >= j {
                F::new((i - j) as u64)
            } else {
                F::ZERO.sub(F::new((j - i) as u64))
            };
            den = den.mul(ij);
        }
        let den_inv = den
            .inverse()
            .ok_or_else(|| HcError::math("lagrange_interpolate_at: zero denominator"))?;
        acc = acc.add(vi.mul(num).mul(den_inv));
    }
    Ok(acc)
}

/// Product polynomial: `g(x) = ∏_i factors[i](x)`. Every factor must share
/// the same `num_vars`; the resulting polynomial has total degree equal to
/// the number of factors.
#[derive(Clone, Debug)]
pub struct ProductPoly {
    pub factors: Vec<MultilinearPoly>,
}

impl ProductPoly {
    pub fn new(factors: Vec<MultilinearPoly>) -> HcResult<Self> {
        if factors.is_empty() {
            return Err(HcError::invalid_argument(
                "ProductPoly: at least one factor required",
            ));
        }
        let n = factors[0].num_vars;
        for (i, f) in factors.iter().enumerate() {
            if f.num_vars != n {
                return Err(HcError::invalid_argument(format!(
                    "ProductPoly factor {i} has num_vars {} != {n}",
                    f.num_vars
                )));
            }
        }
        Ok(Self { factors })
    }

    pub fn num_vars(&self) -> usize {
        self.factors[0].num_vars
    }

    /// Per-round univariate degree = number of factors.
    pub fn degree(&self) -> usize {
        self.factors.len()
    }

    /// Σ_{x ∈ {0,1}^n} g(x) — naive reference.
    pub fn total_sum(&self) -> F {
        let n = self.num_vars();
        let len = 1usize << n;
        let mut acc = F::ZERO;
        for idx in 0..len {
            let mut prod = F::ONE;
            for f in &self.factors {
                prod = prod.mul(f.evaluations[idx]);
            }
            acc = acc.add(prod);
        }
        acc
    }

    /// Evaluate `g` at an arbitrary field point — used by the final
    /// polynomial-bind step of the verifier.
    pub fn evaluate_at(&self, point: &[F]) -> HcResult<F> {
        let mut prod = F::ONE;
        for f in &self.factors {
            prod = prod.mul(f.evaluate_at(point)?);
        }
        Ok(prod)
    }
}

// ── Prover ─────────────────────────────────────────────────────────────

/// Prove a sumcheck claim about a [`ProductPoly`]. Returns the proof
/// envelope plus the per-round challenges sampled from the transcript.
pub fn prove(
    poly: &ProductPoly,
    claim: &SumcheckClaim,
    config: &HcSumcheckConfig,
) -> HcResult<(SumcheckProof, Vec<F>)> {
    config.validate()?;
    claim.validate(poly.num_vars(), poly.degree())?;
    if F::new(claim.claimed_sum) != poly.total_sum() {
        return Err(HcError::invalid_argument(format!(
            "claimed_sum {} does not match total Σ g(x) = {}",
            claim.claimed_sum,
            poly.total_sum().0
        )));
    }

    let mut transcript: Transcript<Blake3> = Transcript::new(config.domain_separator);
    transcript.append_message(b"sumcheck.num_vars", (poly.num_vars() as u64).to_le_bytes());
    transcript.append_message(b"sumcheck.degree", (poly.degree() as u64).to_le_bytes());
    transcript.append_message(b"sumcheck.claim", claim.claimed_sum.to_le_bytes());

    // Working tables: one per factor, folded in lockstep.
    let mut tables: Vec<Vec<F>> = poly.factors.iter().map(|f| f.evaluations.clone()).collect();
    let degree = poly.degree();
    let mut rounds = Vec::with_capacity(poly.num_vars());
    let mut challenges = Vec::with_capacity(poly.num_vars());

    // Hoist the t-points used per round (small, reused across rounds).
    let t_points: Vec<F> = (0..=degree).map(|i| F::new(i as u64)).collect();

    for _round in 0..poly.num_vars() {
        let half = tables[0].len() / 2;
        // For t ∈ {0, 1, ..., degree}, compute s(t) = Σ_j ∏_f f_at(t, j),
        // where f_at(t, j) = factor.table[2j] + t·(factor.table[2j+1] - factor.table[2j]).
        let mut s_evals = vec![F::ZERO; degree + 1];

        // Tile the j loop so the evaluator never holds more than
        // tile_pairs * num_factors field elements live beyond the (already-
        // folded) tables themselves.
        let tile_pairs = 1usize << config.tile_log_size;
        let mut j = 0;
        while j < half {
            let end = (j + tile_pairs).min(half);
            for jj in j..end {
                for (ti, &t) in t_points.iter().enumerate() {
                    let mut prod = F::ONE;
                    for table in &tables {
                        let low = table[2 * jj];
                        let high = table[2 * jj + 1];
                        // f_at(t, jj) = low + t·(high - low)
                        let v = low.add(t.mul(high.sub(low)));
                        prod = prod.mul(v);
                    }
                    s_evals[ti] = s_evals[ti].add(prod);
                }
            }
            j = end;
        }

        let coefficients: Vec<u64> = s_evals.iter().map(|e| e.0).collect();
        for (i, e) in s_evals.iter().enumerate() {
            transcript.append_message(format!("sumcheck.round.s{i}").as_bytes(), e.0.to_le_bytes());
        }
        let r: F = transcript.challenge_field(b"sumcheck.round.challenge");
        challenges.push(r);
        rounds.push(SumcheckRoundMsg { coefficients });

        // Fold every factor by r in lockstep.
        for table in tables.iter_mut() {
            let mut next = Vec::with_capacity(half);
            for jj in 0..half {
                let low = table[2 * jj];
                let high = table[2 * jj + 1];
                next.push(low.add(r.mul(high.sub(low))));
            }
            *table = next;
        }
    }

    // Final evaluation: product of each factor's last entry.
    let mut final_eval = F::ONE;
    for table in &tables {
        final_eval = final_eval.mul(table[0]);
    }
    transcript.append_message(b"sumcheck.final", final_eval.0.to_le_bytes());

    Ok((
        SumcheckProof {
            version: SumcheckProof::VERSION,
            rounds,
            final_evaluation: final_eval.0,
        },
        challenges,
    ))
}

// ── Verifier (general-degree) ─────────────────────────────────────────

/// Per-round verifier outcome including the sampled challenges.
pub use crate::prover::VerifierOutcome;

/// General-degree sumcheck verifier. Works for any per-round univariate
/// degree (encoded as `degree+1` evaluations on integer points `0..=degree`).
///
/// Returns `Ok(Some(outcome))` if the protocol is internally consistent;
/// `Ok(None)` if any round-sum or final-claim check fails;
/// `Err(...)` for malformed input.
pub fn verify_protocol_general(
    claim: &SumcheckClaim,
    proof: &SumcheckProof,
    config: &HcSumcheckConfig,
) -> HcResult<Option<VerifierOutcome>> {
    config.validate()?;
    if proof.version != SumcheckProof::VERSION {
        return Err(HcError::invalid_argument(format!(
            "unsupported sumcheck proof version {} (expected {})",
            proof.version,
            SumcheckProof::VERSION
        )));
    }
    if proof.rounds.len() != claim.num_variables {
        return Err(HcError::invalid_argument(format!(
            "proof has {} rounds, claim expects {}",
            proof.rounds.len(),
            claim.num_variables
        )));
    }

    let mut transcript: Transcript<Blake3> = Transcript::new(config.domain_separator);
    transcript.append_message(
        b"sumcheck.num_vars",
        (claim.num_variables as u64).to_le_bytes(),
    );
    transcript.append_message(b"sumcheck.degree", (claim.degree as u64).to_le_bytes());
    transcript.append_message(b"sumcheck.claim", claim.claimed_sum.to_le_bytes());

    let mut current = F::new(claim.claimed_sum);
    let mut challenges = Vec::with_capacity(claim.num_variables);

    for round in &proof.rounds {
        if round.coefficients.len() != claim.degree + 1 {
            return Err(HcError::invalid_argument(format!(
                "round message has {} evaluations, expected degree+1 = {}",
                round.coefficients.len(),
                claim.degree + 1
            )));
        }
        let evals: Vec<F> = round.coefficients.iter().map(|&u| F::new(u)).collect();
        // s(0) + s(1) must equal the carried-over claim.
        let s0_plus_s1 = evals[0].add(evals[1]);
        if s0_plus_s1 != current {
            return Ok(None);
        }
        for (i, e) in evals.iter().enumerate() {
            transcript.append_message(format!("sumcheck.round.s{i}").as_bytes(), e.0.to_le_bytes());
        }
        let r: F = transcript.challenge_field(b"sumcheck.round.challenge");
        challenges.push(r);
        // current ← s(r) via Lagrange interpolation.
        current = lagrange_interpolate_at(&evals, r)?;
    }

    let final_evaluation = F::new(proof.final_evaluation);
    if current != final_evaluation {
        return Ok(None);
    }
    transcript.append_message(b"sumcheck.final", final_evaluation.0.to_le_bytes());
    Ok(Some(VerifierOutcome {
        challenges,
        final_evaluation,
    }))
}

/// Full verification including polynomial bind for [`ProductPoly`].
pub fn verify_with_product_poly(
    poly: &ProductPoly,
    claim: &SumcheckClaim,
    proof: &SumcheckProof,
    config: &HcSumcheckConfig,
) -> HcResult<bool> {
    let outcome = match verify_protocol_general(claim, proof, config)? {
        Some(o) => o,
        None => return Ok(false),
    };
    let expected = poly.evaluate_at(&outcome.challenges)?;
    Ok(expected == outcome.final_evaluation)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded(seed: u64, n: usize) -> Vec<F> {
        let mut x = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                F::new(x % (1u64 << 14))
            })
            .collect()
    }

    fn rand_ml(seed: u64, n: usize) -> MultilinearPoly {
        MultilinearPoly::new(n, seeded(seed, 1 << n)).unwrap()
    }

    #[test]
    fn lagrange_at_integer_node_recovers_value() {
        // s(t) = [3, 7, 11, 15] should give s(0) = 3, s(1) = 7, s(2) = 11, s(3) = 15.
        let vs = vec![F::new(3), F::new(7), F::new(11), F::new(15)];
        for i in 0..4u64 {
            assert_eq!(
                lagrange_interpolate_at(&vs, F::new(i)).unwrap(),
                vs[i as usize]
            );
        }
    }

    #[test]
    fn lagrange_linear_matches_explicit() {
        // Linear: s(0) = 5, s(1) = 9 ⇒ s(r) = 5 + r * 4.
        let vs = vec![F::new(5), F::new(9)];
        for r in 0..10u64 {
            let want = F::new(5).add(F::new(r).mul(F::new(4)));
            assert_eq!(lagrange_interpolate_at(&vs, F::new(r)).unwrap(), want);
        }
    }

    #[test]
    fn product_poly_basic_construction() {
        let a = rand_ml(1, 3);
        let b = rand_ml(2, 3);
        let p = ProductPoly::new(vec![a, b]).unwrap();
        assert_eq!(p.degree(), 2);
        assert_eq!(p.num_vars(), 3);
    }

    #[test]
    fn product_poly_rejects_mismatched_factors() {
        let a = rand_ml(1, 3);
        let b = rand_ml(2, 4);
        assert!(ProductPoly::new(vec![a, b]).is_err());
    }

    #[test]
    fn prove_and_verify_product_k2() {
        let a = rand_ml(11, 4);
        let b = rand_ml(22, 4);
        let p = ProductPoly::new(vec![a, b]).unwrap();
        let claim = SumcheckClaim::new(4, 2, p.total_sum().0);
        let cfg = HcSumcheckConfig::default();
        let (proof, _r) = prove(&p, &claim, &cfg).unwrap();
        // Per-round messages must have degree+1 = 3 evaluations.
        for r in &proof.rounds {
            assert_eq!(r.coefficients.len(), 3);
        }
        assert!(verify_with_product_poly(&p, &claim, &proof, &cfg).unwrap());
    }

    #[test]
    fn prove_and_verify_product_k3() {
        // Spartan-style: three multilinears product, degree-3 round messages.
        let a = rand_ml(31, 3);
        let b = rand_ml(32, 3);
        let c = rand_ml(33, 3);
        let p = ProductPoly::new(vec![a, b, c]).unwrap();
        let claim = SumcheckClaim::new(3, 3, p.total_sum().0);
        let cfg = HcSumcheckConfig::default();
        let (proof, _r) = prove(&p, &claim, &cfg).unwrap();
        for r in &proof.rounds {
            assert_eq!(r.coefficients.len(), 4);
        }
        assert!(verify_with_product_poly(&p, &claim, &proof, &cfg).unwrap());
    }

    #[test]
    fn product_verify_rejects_tampered_round() {
        let a = rand_ml(41, 3);
        let b = rand_ml(42, 3);
        let p = ProductPoly::new(vec![a, b]).unwrap();
        let claim = SumcheckClaim::new(3, 2, p.total_sum().0);
        let cfg = HcSumcheckConfig::default();
        let (mut proof, _) = prove(&p, &claim, &cfg).unwrap();
        // Flip the second coefficient of round 0.
        proof.rounds[0].coefficients[1] = proof.rounds[0].coefficients[1].wrapping_add(1);
        let outcome = verify_protocol_general(&claim, &proof, &cfg).unwrap();
        assert!(outcome.is_none());
    }

    #[test]
    fn product_verify_rejects_wrong_final_evaluation() {
        let a = rand_ml(51, 3);
        let b = rand_ml(52, 3);
        let p = ProductPoly::new(vec![a, b]).unwrap();
        let claim = SumcheckClaim::new(3, 2, p.total_sum().0);
        let cfg = HcSumcheckConfig::default();
        let (mut proof, _) = prove(&p, &claim, &cfg).unwrap();
        proof.final_evaluation = proof.final_evaluation.wrapping_add(1);
        assert!(!verify_with_product_poly(&p, &claim, &proof, &cfg).unwrap());
    }

    #[test]
    fn product_prover_rejects_wrong_claim() {
        let a = rand_ml(61, 3);
        let b = rand_ml(62, 3);
        let p = ProductPoly::new(vec![a, b]).unwrap();
        let bogus_claim = SumcheckClaim::new(3, 2, p.total_sum().0.wrapping_add(1));
        let cfg = HcSumcheckConfig::default();
        let err = prove(&p, &bogus_claim, &cfg).unwrap_err();
        assert!(format!("{err}").contains("claimed_sum"));
    }

    #[test]
    fn product_determinism_same_inputs_same_proof() {
        let a = rand_ml(71, 3);
        let b = rand_ml(72, 3);
        let p = ProductPoly::new(vec![a, b]).unwrap();
        let claim = SumcheckClaim::new(3, 2, p.total_sum().0);
        let cfg = HcSumcheckConfig::default();
        let (pa, _) = prove(&p, &claim, &cfg).unwrap();
        let (pb, _) = prove(&p, &claim, &cfg).unwrap();
        assert_eq!(pa.final_evaluation, pb.final_evaluation);
        for (a, b) in pa.rounds.iter().zip(pb.rounds.iter()) {
            assert_eq!(a.coefficients, b.coefficients);
        }
    }
}
