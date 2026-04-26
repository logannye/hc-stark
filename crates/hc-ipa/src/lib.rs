#![forbid(unsafe_code)]

//! `hc-ipa` — height-compressed Bulletproofs-style Inner Product Argument.
//!
//! ## Why this crate exists
//!
//! Bulletproofs and other IPA-based systems already enjoy a logarithmic
//! interaction round count — each round halves the witness vectors `a` and
//! `b`. What they don't enjoy is a logarithmic *prover memory*: round zero
//! still requires the full vectors materialized in RAM. For confidential
//! transactions, range proofs over very wide values, or aggregated batch
//! proofs over thousands of inputs, that round-zero peak dominates.
//!
//! Height compression makes the IPA prover stream:
//!
//! - The vectors `a` and `b` are exposed via an [`IpaVectorSource`] trait
//!   that yields entries on demand. The implementation owns its own replay
//!   strategy (e.g., re-derive `a_i` from a witness commitment + index).
//! - Round folding is performed in tiles of size `O(√n)`, with the folded
//!   results written back into the source for the next round.
//! - Working memory is `O(√n)` group elements instead of `O(n)`.
//!
//! Verification is unchanged from standard Bulletproofs — the round
//! structure is identical, so existing curve choices, transcript schemes,
//! and aggregation tricks all carry over.
//!
//! ## Surface stability
//!
//! Trait surface and the `prove_inner_product`, `verify_inner_product`, and
//! `prove_range` signatures are the long-term contract. Cryptographic body
//! returns [`HcError::unimplemented`] until Phase 4.

pub mod proof;
pub mod source;

pub use proof::{IpaProof, IpaStatement, RangeProof};
pub use source::IpaVectorSource;

use hc_core::{HcError, HcResult};
use serde::{Deserialize, Serialize};

/// Tunables for the IPA prover.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HcIpaConfig {
    /// Tile size for streaming folds. Working memory ≈
    /// `O(tile_size * group_element_byte_size)`.
    pub tile_size: usize,
    /// Whether to enable proof aggregation (multiple statements share rounds).
    pub aggregate: bool,
    /// Domain-separation tag for the transcript.
    pub domain_separator: &'static [u8],
}

impl Default for HcIpaConfig {
    fn default() -> Self {
        Self {
            tile_size: 1024,
            aggregate: false,
            domain_separator: b"hc-ipa/v1",
        }
    }
}

impl HcIpaConfig {
    pub fn validate(&self) -> HcResult<()> {
        if !self.tile_size.is_power_of_two() {
            return Err(HcError::invalid_argument(format!(
                "tile_size must be a power of two, got {}",
                self.tile_size
            )));
        }
        if self.tile_size < 16 {
            return Err(HcError::invalid_argument(format!(
                "tile_size must be at least 16, got {}",
                self.tile_size
            )));
        }
        Ok(())
    }
}

/// Prove the inner product relation `<a, b> = c` for vectors of length `n`.
pub fn prove_inner_product<S: IpaVectorSource>(
    statement: &IpaStatement,
    source: &S,
    config: &HcIpaConfig,
) -> HcResult<IpaProof> {
    config.validate()?;
    statement.validate(source.length())?;
    Err(HcError::unimplemented(
        "hc-ipa: streaming fold prover (Phase 4, see ROADMAP_EXTENSIONS.md)",
    ))
}

/// Verify an IPA proof against a public statement.
pub fn verify_inner_product(
    statement: &IpaStatement,
    proof: &IpaProof,
    config: &HcIpaConfig,
) -> HcResult<bool> {
    let _ = (statement, proof, config);
    Err(HcError::unimplemented(
        "hc-ipa: streaming verifier (Phase 4, see ROADMAP_EXTENSIONS.md)",
    ))
}

/// Convenience: prove that a value lies in `[0, 2^bits)` (Bulletproofs-style
/// range proof, with the IPA replaced by the height-compressed variant).
pub fn prove_range(
    value: u64,
    bits: u8,
    blinding: [u8; 32],
    config: &HcIpaConfig,
) -> HcResult<RangeProof> {
    config.validate()?;
    if !(1..=64).contains(&bits) {
        return Err(HcError::invalid_argument(format!(
            "range proof bits must be in 1..=64, got {bits}"
        )));
    }
    if bits < 64 && value >= (1u64 << bits) {
        return Err(HcError::invalid_argument(format!(
            "value {value} exceeds 2^{bits}"
        )));
    }
    let _ = blinding;
    Err(HcError::unimplemented(
        "hc-ipa: range-proof wrapper (Phase 4, see ROADMAP_EXTENSIONS.md)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::DummyVectorSource;

    #[test]
    fn default_config_validates() {
        HcIpaConfig::default().validate().unwrap();
    }

    #[test]
    fn config_rejects_non_power_of_two_tile() {
        let cfg = HcIpaConfig {
            tile_size: 1000,
            ..HcIpaConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn range_proof_rejects_oversized_value() {
        let cfg = HcIpaConfig::default();
        let err = prove_range(1024, 10, [0u8; 32], &cfg).unwrap_err();
        assert!(format!("{err}").contains("exceeds 2^10"));
    }

    #[test]
    fn prove_inner_product_returns_unimplemented_not_panic() {
        let src = DummyVectorSource::new(64);
        let stmt = IpaStatement::new(64, [0u8; 32], 0);
        let cfg = HcIpaConfig::default();
        let err = prove_inner_product(&stmt, &src, &cfg).unwrap_err();
        assert!(format!("{err}").contains("hc-ipa"));
    }
}
