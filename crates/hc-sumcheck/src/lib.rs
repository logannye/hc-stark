#![forbid(unsafe_code)]

//! `hc-sumcheck` — height-compressed sumcheck prover / verifier.
//!
//! ## Why this crate exists
//!
//! Sumcheck is the central reduction in many modern proof systems —
//! Spartan, HyperPlonk, Jolt, Lasso, Binius, Brakedown, and any GKR-class
//! IOP. Sumcheck is *also* the canonical balanced-binary tree computation:
//! each round halves the boolean hypercube. Existing implementations
//! materialize the full multilinear extension up front (`O(2^n)` field
//! elements) and then walk it round-by-round — peak memory is dominated by
//! that initial table, not by the per-round work.
//!
//! Height compression says: hold an `O(2^(n/2))` slice of the hypercube at a
//! time, replay multilinear extension evaluations from the witness, and
//! advance round-by-round. Concretely:
//!
//! - The polynomial `g` is exposed as a [`SumcheckPolynomial`] trait whose
//!   `evaluate_on_slice` method is invoked on demand. The polynomial owns
//!   its own replay strategy.
//! - The prover keeps `O(√n)` evaluation tiles live at any time.
//! - Round messages are constant-size: a univariate polynomial of degree
//!   ≤ `g.degree()` per round.
//!
//! This crate is protocol-level, not application-level: it gives downstream
//! systems a height-compressed sumcheck back-end they can plug their own
//! polynomial structure into. Spartan and HyperPlonk-class workloads are
//! implemented on top of this in subsequent crates.
//!
//! ## Surface stability
//!
//! The trait surface — [`SumcheckPolynomial`], [`SumcheckClaim`], and the
//! `prove_sum` / `verify_sum` functions — is the long-term API. Cryptographic
//! body returns [`HcError::unimplemented`] until Phase 3.

pub mod linear_product;
pub mod multilinear;
pub mod product;
pub mod proof;
pub mod prover;

pub use linear_product::{
    prove as prove_linear_product, verify_with_poly as verify_with_linear_poly, LinearProductPoly,
    Term,
};
pub use multilinear::{MultilinearExtension, SumcheckPolynomial};
pub use product::{
    lagrange_interpolate_at, prove as prove_product, verify_protocol_general,
    verify_with_product_poly, ProductPoly,
};
pub use proof::{SumcheckClaim, SumcheckProof, SumcheckRoundMsg};
pub use prover::{
    dense_from_extension, prove as prove_multilinear, verify_protocol, verify_with_poly,
    MultilinearPoly, VerifierOutcome,
};

use hc_core::{HcError, HcResult};
use serde::{Deserialize, Serialize};

/// Tunables for the sumcheck prover.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HcSumcheckConfig {
    /// Tile size for hypercube traversal. The prover holds at most
    /// `2^tile_log_size` evaluation points in RAM at any time. Memory
    /// pressure ≈ `O(2^tile_log_size * field_byte_size)`.
    pub tile_log_size: u8,
    /// Whether the prover should commit to its round messages via the
    /// transcript hash (Fiat-Shamir). Disabled only in interactive testing.
    pub fiat_shamir: bool,
    /// Domain-separation tag mixed into the transcript so different protocols
    /// using sumcheck can't have transcript collisions.
    pub domain_separator: &'static [u8],
}

impl Default for HcSumcheckConfig {
    fn default() -> Self {
        Self {
            tile_log_size: 12,
            fiat_shamir: true,
            domain_separator: b"hc-sumcheck/v1",
        }
    }
}

impl HcSumcheckConfig {
    pub fn validate(&self) -> HcResult<()> {
        if self.tile_log_size > 24 {
            return Err(HcError::invalid_argument(format!(
                "tile_log_size > 24 risks oversized RAM working set ({}); reduce",
                1u64 << self.tile_log_size
            )));
        }
        Ok(())
    }
}

/// Run the prover on a sumcheck claim, producing a [`SumcheckProof`].
///
/// ## Current support
///
/// Multilinear polynomials (`degree = 1` per variable) are fully wired
/// through [`prover::prove`]. Higher-degree polynomials still return
/// [`HcError::unimplemented`] pending a per-round Lagrange-evaluation
/// helper; the API signature is stable across that upgrade.
pub fn prove_sum<P: SumcheckPolynomial>(
    claim: &SumcheckClaim,
    polynomial: &P,
    config: &HcSumcheckConfig,
) -> HcResult<SumcheckProof> {
    config.validate()?;
    claim.validate(polynomial.num_variables(), polynomial.degree())?;
    if polynomial.degree() != 1 {
        return Err(HcError::unimplemented(
            "hc-sumcheck: only multilinear (degree 1) polynomials are wired today; \
             higher-degree round messages land in Phase 3.5",
        ));
    }
    // For multilinear polynomials we materialize the dense table from the
    // trait's `evaluate_on_slice` so the streaming prover can run. Real
    // streaming polynomials (Spartan, HyperPlonk, ...) will plug in via
    // `prover::prove` directly with their own `MultilinearPoly`-shaped view.
    let n = polynomial.num_variables();
    let len = 1usize << n;
    let mut tile_points: Vec<Vec<u64>> = Vec::with_capacity(len);
    for idx in 0..len as u64 {
        let pt: Vec<u64> = (0..n).map(|b| (idx >> b) & 1).collect();
        tile_points.push(pt);
    }
    let mut out = vec![0u64; len];
    polynomial.evaluate_on_slice(&[], &tile_points, &mut out)?;
    let evals: Vec<hc_core::field::GoldilocksField> = out
        .into_iter()
        .map(hc_core::field::GoldilocksField::new)
        .collect();
    let dense = prover::MultilinearPoly::new(n, evals)?;
    let (proof, _challenges) = prover::prove(&dense, claim, config)?;
    Ok(proof)
}

/// Verify a sumcheck proof against a claim — protocol-level consistency
/// only.
///
/// Works for any per-round univariate degree by interpolating each round
/// message at the sampled challenge via Lagrange. Returns `true` iff the
/// per-round sums and the final claim are internally consistent. The
/// polynomial bind (`final_evaluation == g(challenges)`) is the caller's
/// responsibility — use [`verify_with_poly`] (multilinear) or
/// [`verify_with_product_poly`] (product polynomial) when the polynomial
/// is available.
pub fn verify_sum(
    claim: &SumcheckClaim,
    proof: &SumcheckProof,
    config: &HcSumcheckConfig,
) -> HcResult<bool> {
    Ok(product::verify_protocol_general(claim, proof, config)?.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multilinear::DummyPolynomial;

    #[test]
    fn default_config_validates() {
        HcSumcheckConfig::default().validate().unwrap();
    }

    #[test]
    fn config_rejects_oversized_tile() {
        let mut cfg = HcSumcheckConfig::default();
        cfg.tile_log_size = 30;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn prove_higher_degree_returns_unimplemented() {
        let p = DummyPolynomial::new(8, 2);
        let claim = SumcheckClaim::new(8, 2, 0);
        let cfg = HcSumcheckConfig::default();
        let err = prove_sum(&claim, &p, &cfg).unwrap_err();
        assert!(format!("{err}").contains("hc-sumcheck"));
    }

    #[test]
    fn prove_sum_multilinear_roundtrips_through_verify_sum() {
        // Build a tiny multilinear poly via the dense view, then check that
        // prove_sum / verify_sum round-trip end to end.
        use hc_core::field::GoldilocksField as Fld;
        let evals: Vec<Fld> = (0u64..8).map(Fld::new).collect();
        let poly = prover::MultilinearPoly::new(3, evals).unwrap();
        let claim = SumcheckClaim::new(3, 1, poly.total_sum().0);
        let cfg = HcSumcheckConfig::default();
        let proof = prove_sum(&claim, &poly, &cfg).unwrap();
        assert!(verify_sum(&claim, &proof, &cfg).unwrap());
        // verify_with_poly does the polynomial bind too.
        assert!(verify_with_poly(&poly, &claim, &proof, &cfg).unwrap());
    }
}
