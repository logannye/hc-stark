use hc_commit::MerkleTree;
use hc_core::field::FieldElement;
use hc_hash::{Blake3, HashFunction};

use crate::TraceRow;

pub fn commit_trace<F: FieldElement>(
    rows: &[TraceRow<F>],
) -> hc_core::error::HcResult<hc_hash::hash::HashDigest> {
    let leaves: Vec<_> = rows
        .iter()
        .map(|row| {
            let mut bytes = Vec::with_capacity(16);
            bytes.extend_from_slice(&row[0].to_u64().to_le_bytes());
            bytes.extend_from_slice(&row[1].to_u64().to_le_bytes());
            Blake3::hash(&bytes)
        })
        .collect();
    let tree = MerkleTree::<Blake3>::from_leaves(&leaves)?;
    Ok(tree.root())
}
