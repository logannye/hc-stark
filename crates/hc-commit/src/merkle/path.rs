use hc_hash::hash::{HashDigest, HashFunction};
use hc_core::error::HcResult;

use super::hash_pair;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathNode {
    pub sibling: HashDigest,
    pub sibling_is_left: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MerklePath {
    nodes: Vec<PathNode>,
}

impl MerklePath {
    pub fn new(nodes: Vec<PathNode>) -> Self {
        Self { nodes }
    }

    pub fn nodes(&self) -> &[PathNode] {
        &self.nodes
    }

    pub fn verify<H>(&self, root: HashDigest, leaf: HashDigest) -> bool
    where
        H: hc_hash::hash::HashFunction,
    {
        let mut acc = leaf;
        for node in &self.nodes {
            acc = if node.sibling_is_left {
                hash_pair::<H>(&node.sibling, &acc)
            } else {
                hash_pair::<H>(&acc, &node.sibling)
            };
        }
        acc == root
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// Reconstruct a Merkle path by replaying leaf production up to the target index.
/// This is used when the full Merkle tree is not stored in memory.
pub fn reconstruct_path_from_replay<H, P>(
    leaf_index: usize,
    leaf_count: usize,
    producer: &P,
) -> HcResult<MerklePath>
where
    H: HashFunction,
    P: Fn(usize) -> HashDigest,
{
    if leaf_index >= leaf_count {
        return Err(hc_core::error::HcError::invalid_argument(
            "leaf index out of range",
        ));
    }

    // Build a temporary full tree to extract the path
    // This is not ideal for memory usage, but correct for now
    // TODO: Implement truly streaming path extraction
    use crate::merkle::standard::MerkleTree;

    let leaves: Vec<HashDigest> = (0..leaf_count).map(|i| producer(i)).collect();
    let tree = MerkleTree::<H>::from_leaves(&leaves)?;
    let path = tree.open(leaf_index)?;

    Ok(path)
}
