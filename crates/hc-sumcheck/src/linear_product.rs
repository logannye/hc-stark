//! Linear combination of products of multilinears.
//!
//! ## What this represents
//!
//! ```text
//!     g(x) = Σ_i α_i · ∏_j f_{i,j}(x)
//! ```
//!
//! where every `f_{i,j}` is multilinear (degree 1 per variable) and the
//! coefficients `α_i` are field constants. Per-round univariate degree is
//! the maximum factor count across terms.
//!
//! ## Why this exists
//!
//! Many modern proof systems reduce their algebraic relation to a sumcheck
//! of *exactly* this shape:
//!
//! - **Spartan** (R1CS): `g(x) = eq_τ(x)·Aw(x)·Bw(x) - eq_τ(x)·Cw(x)` —
//!   two terms, degrees 3 and 2.
//! - **HyperPlonk gate**: `g(x) = q_M·a·b + q_L·a + q_R·b + q_O·c + q_C` —
//!   five terms, degrees 3, 2, 2, 2, 1.
//! - **Lookup arguments**: linear combinations of permutation polynomials.
//!
//! [`crate::product::ProductPoly`] handles a *single* product. This module
//! handles arbitrary linear combinations, unifying the round-message
//! computation across terms while keeping the verifier protocol identical.

use crate::product::verify_protocol_general;
use crate::proof::{SumcheckClaim, SumcheckProof, SumcheckRoundMsg};
use crate::prover::{MultilinearPoly, VerifierOutcome};
use crate::HcSumcheckConfig;
use hc_core::field::{FieldElement, GoldilocksField as F};
use hc_core::{HcError, HcResult};
use hc_hash::{Blake3, Transcript};

/// One term in the linear combination: a coefficient times a product of
/// multilinear factors.
#[derive(Clone, Debug)]
pub struct Term {
    pub coefficient: F,
    pub factors: Vec<MultilinearPoly>,
}

impl Term {
    pub fn new(coefficient: F, factors: Vec<MultilinearPoly>) -> HcResult<Self> {
        if factors.is_empty() {
            return Err(HcError::invalid_argument(
                "Term: at least one factor required",
            ));
        }
        Ok(Self {
            coefficient,
            factors,
        })
    }

    /// Number of factors → per-term univariate degree.
    pub fn degree(&self) -> usize {
        self.factors.len()
    }
}

/// Linear combination of products of multilinears.
#[derive(Clone, Debug)]
pub struct LinearProductPoly {
    pub terms: Vec<Term>,
}

impl LinearProductPoly {
    pub fn new(terms: Vec<Term>) -> HcResult<Self> {
        if terms.is_empty() {
            return Err(HcError::invalid_argument(
                "LinearProductPoly: at least one term required",
            ));
        }
        let n = terms[0].factors[0].num_vars;
        for (ti, t) in terms.iter().enumerate() {
            for (fi, f) in t.factors.iter().enumerate() {
                if f.num_vars != n {
                    return Err(HcError::invalid_argument(format!(
                        "term {ti} factor {fi} has num_vars {} != {n}",
                        f.num_vars
                    )));
                }
            }
        }
        Ok(Self { terms })
    }

    pub fn num_vars(&self) -> usize {
        self.terms[0].factors[0].num_vars
    }

    /// Per-round univariate degree = max term degree.
    pub fn degree(&self) -> usize {
        self.terms.iter().map(Term::degree).max().unwrap_or(0)
    }

    pub fn total_sum(&self) -> F {
        let len = 1usize << self.num_vars();
        let mut acc = F::ZERO;
        for idx in 0..len {
            for term in &self.terms {
                let mut prod = term.coefficient;
                for f in &term.factors {
                    prod = prod.mul(f.evaluations[idx]);
                }
                acc = acc.add(prod);
            }
        }
        acc
    }

    /// Evaluate `g` at an arbitrary field point — used by the verifier's
    /// final polynomial-bind step.
    pub fn evaluate_at(&self, point: &[F]) -> HcResult<F> {
        let mut acc = F::ZERO;
        for term in &self.terms {
            let mut prod = term.coefficient;
            for f in &term.factors {
                prod = prod.mul(f.evaluate_at(point)?);
            }
            acc = acc.add(prod);
        }
        Ok(acc)
    }
}

// ── Prover ──────────────────────────────────────────────────────────────

/// Prove a sumcheck claim about a [`LinearProductPoly`].
pub fn prove(
    poly: &LinearProductPoly,
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
    transcript.append_message(
        b"sumcheck.num_vars",
        &(poly.num_vars() as u64).to_le_bytes(),
    );
    transcript.append_message(b"sumcheck.degree", &(poly.degree() as u64).to_le_bytes());
    transcript.append_message(b"sumcheck.claim", &claim.claimed_sum.to_le_bytes());

    // For each term, hold parallel folded tables (one Vec<F> per factor).
    let mut tables: Vec<Vec<Vec<F>>> = poly
        .terms
        .iter()
        .map(|t| t.factors.iter().map(|f| f.evaluations.clone()).collect())
        .collect();
    let degree = poly.degree();
    let t_points: Vec<F> = (0..=degree).map(|i| F::new(i as u64)).collect();
    let mut rounds = Vec::with_capacity(poly.num_vars());
    let mut challenges = Vec::with_capacity(poly.num_vars());

    for _round in 0..poly.num_vars() {
        let half = tables[0][0].len() / 2;
        let mut s_evals = vec![F::ZERO; degree + 1];

        let tile_pairs = 1usize << config.tile_log_size;
        let mut j = 0;
        while j < half {
            let end = (j + tile_pairs).min(half);
            for jj in j..end {
                for (ti, &t) in t_points.iter().enumerate() {
                    let mut row = F::ZERO;
                    for (term_idx, term) in poly.terms.iter().enumerate() {
                        let mut prod = term.coefficient;
                        for f_table in &tables[term_idx] {
                            let low = f_table[2 * jj];
                            let high = f_table[2 * jj + 1];
                            let v = low.add(t.mul(high.sub(low)));
                            prod = prod.mul(v);
                        }
                        row = row.add(prod);
                    }
                    s_evals[ti] = s_evals[ti].add(row);
                }
            }
            j = end;
        }

        let coefficients: Vec<u64> = s_evals.iter().map(|e| e.0).collect();
        for (i, e) in s_evals.iter().enumerate() {
            transcript.append_message(
                format!("sumcheck.round.s{}", i).as_bytes(),
                &e.0.to_le_bytes(),
            );
        }
        let r: F = transcript.challenge_field(b"sumcheck.round.challenge");
        challenges.push(r);
        rounds.push(SumcheckRoundMsg { coefficients });

        // Fold every factor of every term by r in lockstep.
        for term_tables in tables.iter_mut() {
            for f_table in term_tables.iter_mut() {
                let mut next = Vec::with_capacity(half);
                for jj in 0..half {
                    let low = f_table[2 * jj];
                    let high = f_table[2 * jj + 1];
                    next.push(low.add(r.mul(high.sub(low))));
                }
                *f_table = next;
            }
        }
    }

    // Final evaluation: combine each term's last entries.
    let mut final_eval = F::ZERO;
    for (term_idx, term) in poly.terms.iter().enumerate() {
        let mut prod = term.coefficient;
        for f_table in &tables[term_idx] {
            prod = prod.mul(f_table[0]);
        }
        final_eval = final_eval.add(prod);
    }
    transcript.append_message(b"sumcheck.final", &final_eval.0.to_le_bytes());

    Ok((
        SumcheckProof {
            version: SumcheckProof::VERSION,
            rounds,
            final_evaluation: final_eval.0,
        },
        challenges,
    ))
}

// ── Verifier ────────────────────────────────────────────────────────────

/// Re-export of the general-degree verifier — Spartan and HyperPlonk-class
/// systems re-use it without modification.
pub fn verify_protocol(
    claim: &SumcheckClaim,
    proof: &SumcheckProof,
    config: &HcSumcheckConfig,
) -> HcResult<Option<VerifierOutcome>> {
    verify_protocol_general(claim, proof, config)
}

/// Full verification including polynomial bind.
pub fn verify_with_poly(
    poly: &LinearProductPoly,
    claim: &SumcheckClaim,
    proof: &SumcheckProof,
    config: &HcSumcheckConfig,
) -> HcResult<bool> {
    let outcome = match verify_protocol(claim, proof, config)? {
        Some(o) => o,
        None => return Ok(false),
    };
    let expected = poly.evaluate_at(&outcome.challenges)?;
    Ok(expected == outcome.final_evaluation)
}

// ── Tests ───────────────────────────────────────────────────────────────

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
                F::new(x % (1u64 << 12))
            })
            .collect()
    }

    fn rand_ml(seed: u64, n: usize) -> MultilinearPoly {
        MultilinearPoly::new(n, seeded(seed, 1 << n)).unwrap()
    }

    #[test]
    fn rejects_empty_terms() {
        assert!(LinearProductPoly::new(vec![]).is_err());
    }

    #[test]
    fn rejects_factor_arity_mismatch() {
        let a = rand_ml(1, 3);
        let b = rand_ml(2, 4);
        let t = Term::new(F::ONE, vec![a, b]);
        // Term::new accepts the bad term; LinearProductPoly catches it.
        let term = t.unwrap();
        assert!(LinearProductPoly::new(vec![term]).is_err());
    }

    #[test]
    fn single_term_matches_product_poly() {
        // LinearProductPoly with one term should be equivalent to ProductPoly
        // in its total_sum and evaluate_at semantics.
        let a = rand_ml(11, 3);
        let b = rand_ml(12, 3);
        let term = Term::new(F::ONE, vec![a.clone(), b.clone()]).unwrap();
        let lp = LinearProductPoly::new(vec![term]).unwrap();
        let pp = crate::product::ProductPoly::new(vec![a, b]).unwrap();
        assert_eq!(lp.total_sum(), pp.total_sum());
        assert_eq!(lp.degree(), pp.degree());
    }

    #[test]
    fn prove_and_verify_two_terms_degree_3_and_2() {
        // g(x) = α·a(x)·b(x)·c(x) + β·d(x)·e(x)
        // — exactly the Spartan shape.
        let a = rand_ml(21, 3);
        let b = rand_ml(22, 3);
        let c = rand_ml(23, 3);
        let d = rand_ml(24, 3);
        let e = rand_ml(25, 3);
        let alpha = F::new(7);
        let beta = F::ZERO.sub(F::new(11)); // negative coefficient
        let term1 = Term::new(alpha, vec![a, b, c]).unwrap();
        let term2 = Term::new(beta, vec![d, e]).unwrap();
        let poly = LinearProductPoly::new(vec![term1, term2]).unwrap();

        let total = poly.total_sum().0;
        let claim = SumcheckClaim::new(3, 3, total);
        let cfg = HcSumcheckConfig::default();
        let (proof, _r) = prove(&poly, &claim, &cfg).unwrap();
        // Round-message length is degree+1 = 4.
        for r in &proof.rounds {
            assert_eq!(r.coefficients.len(), 4);
        }
        assert!(verify_with_poly(&poly, &claim, &proof, &cfg).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_round() {
        let a = rand_ml(31, 3);
        let b = rand_ml(32, 3);
        let term = Term::new(F::ONE, vec![a, b]).unwrap();
        let poly = LinearProductPoly::new(vec![term]).unwrap();
        let claim = SumcheckClaim::new(3, 2, poly.total_sum().0);
        let cfg = HcSumcheckConfig::default();
        let (mut proof, _) = prove(&poly, &claim, &cfg).unwrap();
        proof.rounds[0].coefficients[1] = proof.rounds[0].coefficients[1].wrapping_add(1);
        let outcome = verify_protocol(&claim, &proof, &cfg).unwrap();
        assert!(outcome.is_none());
    }

    #[test]
    fn prover_rejects_wrong_claim() {
        let a = rand_ml(41, 3);
        let term = Term::new(F::ONE, vec![a]).unwrap();
        let poly = LinearProductPoly::new(vec![term]).unwrap();
        let bogus = SumcheckClaim::new(3, 1, poly.total_sum().0.wrapping_add(1));
        let cfg = HcSumcheckConfig::default();
        let err = prove(&poly, &bogus, &cfg).unwrap_err();
        assert!(format!("{err}").contains("claimed_sum"));
    }

    #[test]
    fn determinism_same_inputs_same_proof() {
        let a = rand_ml(51, 3);
        let b = rand_ml(52, 3);
        let term = Term::new(F::ONE, vec![a, b]).unwrap();
        let poly = LinearProductPoly::new(vec![term]).unwrap();
        let claim = SumcheckClaim::new(3, 2, poly.total_sum().0);
        let cfg = HcSumcheckConfig::default();
        let (pa, _) = prove(&poly, &claim, &cfg).unwrap();
        let (pb, _) = prove(&poly, &claim, &cfg).unwrap();
        assert_eq!(pa.final_evaluation, pb.final_evaluation);
        for (ar, br) in pa.rounds.iter().zip(pb.rounds.iter()) {
            assert_eq!(ar.coefficients, br.coefficients);
        }
    }
}
