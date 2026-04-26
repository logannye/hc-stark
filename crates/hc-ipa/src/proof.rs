//! IPA statement and proof envelope types.

use hc_core::{HcError, HcResult};
use serde::{Deserialize, Serialize};

/// Public statement for an inner product argument: the vector length, a
/// commitment to `(a, b)`, and the claimed inner product `c`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpaStatement {
    pub length: usize,
    /// Pedersen-style commitment digest. The exact group / serialization is
    /// owned by the implementation.
    pub commitment: [u8; 32],
    pub claimed_inner_product: u64,
}

impl IpaStatement {
    pub fn new(length: usize, commitment: [u8; 32], claimed_inner_product: u64) -> Self {
        Self {
            length,
            commitment,
            claimed_inner_product,
        }
    }

    /// Cross-check the statement's `length` against the vector source.
    pub fn validate(&self, source_length: usize) -> HcResult<()> {
        if self.length != source_length {
            return Err(HcError::invalid_argument(format!(
                "statement length {} != source length {}",
                self.length, source_length
            )));
        }
        if !self.length.is_power_of_two() {
            return Err(HcError::invalid_argument(format!(
                "IPA length must be a power of two, got {}",
                self.length
            )));
        }
        Ok(())
    }
}

/// Opaque IPA proof envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpaProof {
    pub version: u8,
    /// Concatenated `L` and `R` round messages plus final scalars.
    pub bytes: Vec<u8>,
}

impl IpaProof {
    pub const VERSION: u8 = 1;
}

/// Bulletproofs-style range proof envelope (a thin wrapper around
/// [`IpaProof`] that records the bit-width of the proven range).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProof {
    pub bits: u8,
    pub ipa: IpaProof,
}
