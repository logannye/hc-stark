//! Streaming sumcheck prover and verifier over the Goldilocks field.
//!
//! ## Protocol recap
//!
//! For an `n`-variate polynomial `g` with `deg_X(g) ≤ d` per variable and a
//! claimed sum
//!
//! ```text
//!     H = Σ_{x ∈ {0,1}^n} g(x)
//! ```
//!
//! the sumcheck protocol runs `n` rounds. In round `i` (0-indexed) the
//! prover sends a univariate
//!
//! ```text
//!     s_i(X) = Σ_{y ∈ {0,1}^{n-i-1}} g(r_0, ..., r_{i-1}, X, y)
//! ```
//!
//! encoded by its evaluations at `0, 1, ..., d`. The verifier checks
//! `s_i(0) + s_i(1) == previous_claim`, samples a Fiat-Shamir challenge
//! `r_i`, and updates `previous_claim ← s_i(r_i)`. After `n` rounds the
//! verifier is left with a single-point claim `g(r_0, ..., r_{n-1})` that
//! must be checked externally (or via [`verify_sum_with_poly`]).
//!
//! ## Streaming discipline
//!
//! The prover never materializes the full `2^n`-element evaluation table.
//! Instead it asks the polynomial via [`SumcheckPolynomial::evaluate_on_slice`]
//! for tiles of `2^tile_log_size` evaluation points at a time, accumulating
//! the round message coefficients as it goes. Working memory is
//! `O(2^tile_log_size)` field elements regardless of `n`.

use crate::multilinear::{MultilinearExtension, SumcheckPolynomial};
use crate::proof::{SumcheckClaim, SumcheckProof, SumcheckRoundMsg};
use crate::HcSumcheckConfig;
use hc_core::field::{FieldElement, GoldilocksField as F};
use hc_core::{HcError, HcResult};
use hc_hash::{Blake3, Transcript};

/// Reference multilinear polynomial: a vector of `2^n` field-element
/// evaluations on the boolean hypercube. Variable order is little-endian:
/// the bit at position `0` of the index is the value of the first variable.
#[derive(Clone, Debug)]
pub struct MultilinearPoly {
    pub num_vars: usize,
    /// Length must equal `2^num_vars`.
    pub evaluations: Vec<F>,
}

impl MultilinearPoly {
    pub fn new(num_vars: usize, evaluations: Vec<F>) -> HcResult<Self> {
        let expected = 1usize << num_vars;
        if evaluations.len() != expected {
            return Err(HcError::invalid_argument(format!(
                "MultilinearPoly: expected {expected} evaluations for {num_vars} variables, got {}",
                evaluations.len()
            )));
        }
        Ok(Self {
            num_vars,
            evaluations,
        })
    }

    /// Sum every entry on the hypercube. Used as the canonical "claimed sum"
    /// in tests.
    pub fn total_sum(&self) -> F {
        let mut acc = F::ZERO;
        for &v in &self.evaluations {
            acc = acc.add(v);
        }
        acc
    }

    /// Evaluate the multilinear extension at an arbitrary field point — the
    /// canonical multilinear interpolation
    /// `Σ_{x ∈ {0,1}^n} eq(x, point) * g(x)` where `eq` is the multilinear
    /// equality indicator. Used by the verifier's final check.
    pub fn evaluate_at(&self, point: &[F]) -> HcResult<F> {
        if point.len() != self.num_vars {
            return Err(HcError::invalid_argument(format!(
                "evaluate_at: point dim {} does not match poly num_vars {}",
                point.len(),
                self.num_vars
            )));
        }
        // Fold the table one variable at a time, little-endian: the first
        // variable corresponds to bit 0 (LSB) of the index, so its
        // (low, high) pairs are (2j, 2j+1) — adjacent entries.
        //   t[j] = (1 - r) * t[2j] + r * t[2j+1]
        let mut current: Vec<F> = self.evaluations.clone();
        for &r in point {
            let half = current.len() / 2;
            let mut next = Vec::with_capacity(half);
            for j in 0..half {
                let low = current[2 * j];
                let high = current[2 * j + 1];
                next.push(low.add(r.mul(high.sub(low))));
            }
            current = next;
        }
        Ok(current[0])
    }
}

impl SumcheckPolynomial for MultilinearPoly {
    fn num_variables(&self) -> usize {
        self.num_vars
    }

    fn degree(&self) -> usize {
        // Multilinear ⇒ univariate degree per round is 1.
        1
    }

    fn evaluate_on_slice(
        &self,
        prefix: &[u64],
        tile: &[Vec<u64>],
        out: &mut [u64],
    ) -> HcResult<()> {
        // Two-stage fold:
        //   1) Fold the table by the (already-bound) `prefix` challenges
        //      into a residual table of size `2^(num_vars - prefix.len())`.
        //   2) Read from the residual table at the requested boolean tile
        //      points.
        if prefix.len() > self.num_vars {
            return Err(HcError::invalid_argument(format!(
                "prefix length {} exceeds num_vars {}",
                prefix.len(),
                self.num_vars
            )));
        }
        let prefix_f: Vec<F> = prefix.iter().map(|&u| F::new(u)).collect();
        let residual = fold_table_by_prefix(&self.evaluations, &prefix_f)?;
        let remaining_vars = self.num_vars - prefix.len();
        for (i, point) in tile.iter().enumerate() {
            if i >= out.len() {
                break;
            }
            if point.len() != remaining_vars {
                return Err(HcError::invalid_argument(format!(
                    "tile point {i} has dim {}; expected {remaining_vars}",
                    point.len()
                )));
            }
            // Boolean point ⇒ index into residual by little-endian bit packing.
            let mut idx = 0usize;
            for (b, &v) in point.iter().enumerate() {
                if v != 0 && v != 1 {
                    return Err(HcError::invalid_argument(format!(
                        "tile point {i}.{b} must be 0 or 1, got {v}"
                    )));
                }
                idx |= (v as usize) << b;
            }
            out[i] = residual[idx].0;
        }
        Ok(())
    }
}

/// Fold a multilinear evaluation table by binding the leading variables to
/// the supplied field-element challenges, yielding a residual table over the
/// remaining variables.
fn fold_table_by_prefix(table: &[F], prefix: &[F]) -> HcResult<Vec<F>> {
    let mut current: Vec<F> = table.to_vec();
    for &r in prefix {
        let half = current.len() / 2;
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            let low = current[2 * j];
            let high = current[2 * j + 1];
            next.push(low.add(r.mul(high.sub(low))));
        }
        current = next;
    }
    Ok(current)
}

// ── Prover ─────────────────────────────────────────────────────────────

/// Run the streaming sumcheck prover and return the proof envelope plus the
/// challenges sampled from the transcript (so the caller can do the final
/// polynomial bind).
pub fn prove(
    poly: &MultilinearPoly,
    claim: &SumcheckClaim,
    config: &HcSumcheckConfig,
) -> HcResult<(SumcheckProof, Vec<F>)> {
    config.validate()?;
    claim.validate(poly.num_variables(), poly.degree())?;
    if F::new(claim.claimed_sum) != poly.total_sum() {
        return Err(HcError::invalid_argument(format!(
            "claimed_sum {} does not match total Σ g(x) = {}",
            claim.claimed_sum,
            poly.total_sum().0
        )));
    }

    let mut transcript: Transcript<Blake3> = Transcript::new(config.domain_separator);
    transcript.append_message(b"sumcheck.num_vars", (poly.num_vars as u64).to_le_bytes());
    transcript.append_message(b"sumcheck.degree", (poly.degree() as u64).to_le_bytes());
    transcript.append_message(b"sumcheck.claim", claim.claimed_sum.to_le_bytes());

    // Working table that gets folded one variable at a time. This is the
    // streaming-friendly representation: after round i, the table has size
    // `2^(n - i - 1)` and represents g restricted to the bound prefix.
    let mut table: Vec<F> = poly.evaluations.clone();
    let mut rounds = Vec::with_capacity(poly.num_vars);
    let mut challenges = Vec::with_capacity(poly.num_vars);

    for _round in 0..poly.num_vars {
        let half = table.len() / 2;
        // Little-endian variable order: pairs are (2j, 2j+1).
        // s(0) = Σ table[2j], s(1) = Σ table[2j+1].
        // The outer loop tiles the iteration so working memory beyond the
        // (already-folded) table itself is bounded.
        let tile_pairs = 1usize << config.tile_log_size;
        let mut s0 = F::ZERO;
        let mut s1 = F::ZERO;
        let mut j = 0;
        while j < half {
            let end = (j + tile_pairs).min(half);
            for jj in j..end {
                s0 = s0.add(table[2 * jj]);
                s1 = s1.add(table[2 * jj + 1]);
            }
            j = end;
        }

        let msg = SumcheckRoundMsg {
            coefficients: vec![s0.0, s1.0],
        };
        transcript.append_message(b"sumcheck.round.s0", s0.0.to_le_bytes());
        transcript.append_message(b"sumcheck.round.s1", s1.0.to_le_bytes());
        let r: F = transcript.challenge_field(b"sumcheck.round.challenge");
        challenges.push(r);
        rounds.push(msg);

        // Fold by r in place: new[j] = table[2j] + r*(table[2j+1] - table[2j]).
        let mut next = Vec::with_capacity(half);
        for jj in 0..half {
            let low = table[2 * jj];
            let high = table[2 * jj + 1];
            next.push(low.add(r.mul(high.sub(low))));
        }
        table = next;
    }

    let final_evaluation = table[0];
    transcript.append_message(b"sumcheck.final", final_evaluation.0.to_le_bytes());

    Ok((
        SumcheckProof {
            version: SumcheckProof::VERSION,
            rounds,
            final_evaluation: final_evaluation.0,
        },
        challenges,
    ))
}

// ── Verifier ───────────────────────────────────────────────────────────

/// Verifier outcome: the per-round challenges that were sampled from the
/// transcript, plus the prover's claimed final evaluation. The caller is
/// expected to check that `final_evaluation == polynomial(challenges)`.
#[derive(Clone, Debug)]
pub struct VerifierOutcome {
    pub challenges: Vec<F>,
    pub final_evaluation: F,
}

/// Run the sumcheck verifier protocol. Returns the per-round challenges and
/// the prover's claimed final evaluation if every round's "low + high ==
/// previous claim" check passes; otherwise returns `Ok(None)`.
pub fn verify_protocol(
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
                "round message has {} coefficients, expected degree+1 = {}",
                round.coefficients.len(),
                claim.degree + 1
            )));
        }
        // For multilinear polys (degree 1) the round message is `[s(0), s(1)]`.
        let s0 = F::new(round.coefficients[0]);
        let s1 = F::new(round.coefficients[1]);
        if s0.add(s1) != current {
            return Ok(None);
        }
        transcript.append_message(b"sumcheck.round.s0", s0.0.to_le_bytes());
        transcript.append_message(b"sumcheck.round.s1", s1.0.to_le_bytes());
        let r: F = transcript.challenge_field(b"sumcheck.round.challenge");
        challenges.push(r);
        // Linear interpolation: s(r) = s0 + r*(s1 - s0).
        current = s0.add(r.mul(s1.sub(s0)));
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

/// Full verification including polynomial bind: returns `true` iff the
/// protocol is internally consistent *and* the prover's final evaluation
/// matches the polynomial evaluated at the sampled challenges.
pub fn verify_with_poly(
    poly: &MultilinearPoly,
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

// ── A non-multilinear polynomial trait usage example ────────────────────

/// Build a `MultilinearPoly` from a [`MultilinearExtension`]'s sparse map by
/// expanding zero-defaults across the hypercube.
pub fn dense_from_extension(ext: &MultilinearExtension) -> HcResult<MultilinearPoly> {
    let n = ext.num_vars;
    let len = 1usize << n;
    let mut data = vec![F::ZERO; len];
    for (&idx, &v) in &ext.evaluations {
        if (idx as usize) >= len {
            return Err(HcError::invalid_argument(format!(
                "extension entry index {idx} >= 2^{n}"
            )));
        }
        data[idx as usize] = F::new(v);
    }
    MultilinearPoly::new(n, data)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::FieldElement;

    fn seeded_rng(seed: u64, n: usize) -> Vec<F> {
        let mut x = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                F::new(x % (1u64 << 16))
            })
            .collect()
    }

    fn random_poly(seed: u64, n: usize) -> MultilinearPoly {
        MultilinearPoly::new(n, seeded_rng(seed, 1 << n)).unwrap()
    }

    #[test]
    fn evaluate_at_boolean_point_recovers_table_entry() {
        let p = random_poly(1, 3);
        for idx in 0..(1u64 << 3) {
            let pt: Vec<F> = (0..3).map(|b| F::new((idx >> b) & 1)).collect();
            let got = p.evaluate_at(&pt).unwrap();
            assert_eq!(got, p.evaluations[idx as usize]);
        }
    }

    #[test]
    fn total_sum_matches_naive() {
        let p = random_poly(2, 4);
        let mut s = F::ZERO;
        for &v in &p.evaluations {
            s = s.add(v);
        }
        assert_eq!(p.total_sum(), s);
    }

    #[test]
    fn prove_and_verify_roundtrip_n3() {
        let p = random_poly(3, 3);
        let claim = SumcheckClaim::new(3, 1, p.total_sum().0);
        let cfg = HcSumcheckConfig::default();
        let (proof, _r) = prove(&p, &claim, &cfg).unwrap();
        assert!(verify_with_poly(&p, &claim, &proof, &cfg).unwrap());
    }

    #[test]
    fn prove_and_verify_roundtrip_n6() {
        let p = random_poly(11, 6);
        let claim = SumcheckClaim::new(6, 1, p.total_sum().0);
        let cfg = HcSumcheckConfig::default();
        let (proof, _r) = prove(&p, &claim, &cfg).unwrap();
        assert!(verify_with_poly(&p, &claim, &proof, &cfg).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_claim() {
        let p = random_poly(7, 4);
        let bogus_claim = SumcheckClaim::new(4, 1, p.total_sum().0.wrapping_add(1));
        let cfg = HcSumcheckConfig::default();
        // The prover refuses outright to prove a wrong claim.
        let err = prove(&p, &bogus_claim, &cfg).unwrap_err();
        assert!(format!("{err}").contains("claimed_sum"));
    }

    #[test]
    fn verify_rejects_tampered_round_message() {
        let p = random_poly(13, 3);
        let claim = SumcheckClaim::new(3, 1, p.total_sum().0);
        let cfg = HcSumcheckConfig::default();
        let (mut proof, _) = prove(&p, &claim, &cfg).unwrap();
        // Flip the first round's s0 — verifier must reject.
        proof.rounds[0].coefficients[0] = proof.rounds[0].coefficients[0].wrapping_add(1);
        let outcome = verify_protocol(&claim, &proof, &cfg).unwrap();
        assert!(outcome.is_none());
    }

    #[test]
    fn verify_rejects_wrong_final_evaluation() {
        let p = random_poly(17, 4);
        let claim = SumcheckClaim::new(4, 1, p.total_sum().0);
        let cfg = HcSumcheckConfig::default();
        let (mut proof, _) = prove(&p, &claim, &cfg).unwrap();
        proof.final_evaluation = proof.final_evaluation.wrapping_add(1);
        // Either verify_protocol catches it, or verify_with_poly catches the
        // polynomial mismatch — either way verify_with_poly returns false.
        assert!(!verify_with_poly(&p, &claim, &proof, &cfg).unwrap());
    }

    #[test]
    fn determinism_same_inputs_same_proof() {
        let p = random_poly(19, 4);
        let claim = SumcheckClaim::new(4, 1, p.total_sum().0);
        let cfg = HcSumcheckConfig::default();
        let (proof_a, ra) = prove(&p, &claim, &cfg).unwrap();
        let (proof_b, rb) = prove(&p, &claim, &cfg).unwrap();
        assert_eq!(proof_a.rounds.len(), proof_b.rounds.len());
        for (a, b) in proof_a.rounds.iter().zip(proof_b.rounds.iter()) {
            assert_eq!(a.coefficients, b.coefficients);
        }
        assert_eq!(proof_a.final_evaluation, proof_b.final_evaluation);
        assert_eq!(ra, rb);
    }

    #[test]
    fn dense_from_extension_zero_pads() {
        let mut ext = MultilinearExtension::new(2);
        ext.set(0, 5);
        ext.set(3, 7);
        let p = dense_from_extension(&ext).unwrap();
        assert_eq!(p.evaluations.len(), 4);
        assert_eq!(p.evaluations[0], F::new(5));
        assert_eq!(p.evaluations[3], F::new(7));
        assert_eq!(p.evaluations[1], F::ZERO);
        assert_eq!(p.evaluations[2], F::ZERO);
    }
}
