use hc_hash::hash::{HashDigest, HashFunction};

use super::{hash_pair, MerklePath};

/// Streaming Merkle builder that maintains at most `log2(n)` nodes in memory.
pub struct StreamingMerkle<H: HashFunction> {
    stack: Vec<Option<HashDigest>>,
    leaf_count: usize,
    _marker: core::marker::PhantomData<H>,
}

impl<H: HashFunction> StreamingMerkle<H> {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            leaf_count: 0,
            _marker: core::marker::PhantomData,
        }
    }

    pub fn push(&mut self, leaf: HashDigest) {
        self.leaf_count += 1;
        let mut current = leaf;
        let mut level = 0;
        loop {
            if self.stack.len() <= level {
                self.stack.push(Some(current));
                break;
            }
            if let Some(existing) = self.stack[level].take() {
                current = hash_pair::<H>(&existing, &current);
                level += 1;
            } else {
                self.stack[level] = Some(current);
                break;
            }
        }
    }

    pub fn finalize(mut self) -> Option<HashDigest> {
        let mut acc: Option<HashDigest> = None;
        for entry in self.stack.drain(..) {
            if let Some(node) = entry {
                acc = Some(match acc {
                    Some(acc_node) => hash_pair::<H>(&node, &acc_node),
                    None => node,
                });
            }
        }
        acc
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Extract the Merkle path for a given leaf index using replay-based reconstruction.
    /// This rebuilds the path by simulating tree construction up to the target leaf.
    pub fn extract_path<P>(&self, leaf_index: usize, producer: &P) -> Option<MerklePath>
    where
        P: Fn(usize) -> HashDigest,
    {
        if leaf_index >= self.leaf_count {
            return None;
        }

        // Use the standalone function for path reconstruction
        use super::reconstruct_path_from_replay;
        match reconstruct_path_from_replay::<H, P>(leaf_index, self.leaf_count, producer) {
            Ok(path) => Some(path),
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::standard::MerkleTree;
    use hc_hash::blake3::Blake3;

    #[test]
    fn streaming_matches_standard_root() {
        let leaves: Vec<_> = (0u8..8).map(|i| Blake3::hash(&[i])).collect();
        let tree = MerkleTree::<Blake3>::from_leaves(&leaves).unwrap();
        let mut streaming = StreamingMerkle::<Blake3>::new();
        for leaf in &leaves {
            streaming.push(*leaf);
        }
        assert_eq!(streaming.leaf_count(), leaves.len());
        assert_eq!(streaming.finalize().unwrap(), tree.root());
    }

    #[test]
    fn streaming_path_extraction_matches_standard() {
        let leaves: Vec<_> = (0u8..8).map(|i| Blake3::hash(&[i])).collect();
        let tree = MerkleTree::<Blake3>::from_leaves(&leaves).unwrap();
        let mut streaming = StreamingMerkle::<Blake3>::new();
        for leaf in &leaves {
            streaming.push(*leaf);
        }

        // Test path extraction for a specific index
        let test_index = 3;
        let producer = |idx: usize| leaves[idx];

        let streaming_path = streaming.extract_path(test_index, &producer).unwrap();
        let standard_path = tree.open(test_index).unwrap();
        let leaf = leaves[test_index];

        // Verify both paths lead to the same root
        let root = tree.root();
        assert!(streaming_path.verify::<Blake3>(root, leaf));
        assert!(standard_path.verify::<Blake3>(root, leaf));
    }
}
