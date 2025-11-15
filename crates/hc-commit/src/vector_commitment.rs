use hc_core::error::{HcError, HcResult};
use hc_hash::hash::HashDigest;

/// Trait implemented by commitment schemes that expose Merkle-like semantics.
pub trait VectorCommitment {
    type Proof;

    fn commit(leaves: &[HashDigest]) -> HcResult<HashDigest>;
    fn open(leaves: &[HashDigest], index: usize) -> HcResult<(HashDigest, Self::Proof)>;
    fn verify(root: HashDigest, leaf: HashDigest, proof: &Self::Proof) -> bool;
}

/// Convenience helper to enforce non-empty commitment inputs.
pub(crate) fn ensure_non_empty(leaves: &[HashDigest]) -> HcResult<()> {
    if leaves.is_empty() {
        return Err(HcError::invalid_argument(
            "vector commitment needs at least one leaf",
        ));
    }
    Ok(())
}
