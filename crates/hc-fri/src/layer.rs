use std::sync::Arc;

use hc_commit::merkle::{height_dfs::StreamingMerkle, reconstruct_path_from_replay, MerklePath};
use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};
use hc_hash::{hash::HashDigest, Blake3, HashFunction};

/// Hash function for committing to FRI layer evaluations.
///
/// Note: this is not meant to be cryptographically “special”; it just needs to
/// bind values to Merkle leaves deterministically.
pub fn hash_value<F: FieldElement>(value: &F) -> HashDigest {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&value.to_u64().to_le_bytes());
    bytes[8..].copy_from_slice(&value.square().to_u64().to_le_bytes());
    Blake3::hash(&bytes)
}

pub fn compute_leaf_hashes<F: FieldElement>(values: &[F]) -> Vec<HashDigest> {
    values.iter().map(hash_value::<F>).collect()
}

pub fn merkle_root_from_hashes(hashes: &[HashDigest]) -> HcResult<HashDigest> {
    if hashes.is_empty() {
        return Err(HcError::invalid_argument(
            "cannot build Merkle root from empty hash list",
        ));
    }
    let mut builder = StreamingMerkle::<Blake3>::new();
    for hash in hashes {
        builder.push(*hash);
    }
    builder
        .finalize()
        .ok_or_else(|| HcError::message("failed to finalize merkle tree"))
}

pub fn merkle_path_from_hashes(hashes: Arc<Vec<HashDigest>>, index: usize) -> HcResult<MerklePath> {
    reconstruct_path_from_replay::<Blake3, _>(index, hashes.len(), 2, &|idx| hashes[idx])
}

pub fn fold_layer<F: FieldElement>(values: &[F], beta: F) -> HcResult<Vec<F>> {
    if values.len() % 2 != 0 {
        return Err(HcError::invalid_argument(
            "FRI layer size must be even for folding",
        ));
    }
    let mut next = Vec::with_capacity(values.len() / 2);
    for pair in values.chunks(2) {
        next.push(pair[0].add(beta.mul(pair[1])));
    }
    Ok(next)
}
