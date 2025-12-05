use hc_hash::hash::{HashDigest, HashFunction};

use super::{hash_pair, MerklePath};

/// Streaming Merkle builder that maintains at most `log_f(n)` nodes in memory,
/// where `f` is the configurable fanout. Leaves are absorbed left-to-right, and
/// partial groups are hashed deterministically without padding, which matches
/// the height-compressed layout used by the prover.
pub struct StreamingMerkle<H: HashFunction> {
    stack: Vec<Vec<HashDigest>>,
    leaf_count: usize,
    fanout: usize,
    _marker: core::marker::PhantomData<H>,
}

impl<H: HashFunction> Default for StreamingMerkle<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: HashFunction> StreamingMerkle<H> {
    pub fn new() -> Self {
        Self::with_fanout(2)
    }

    pub fn with_fanout(fanout: usize) -> Self {
        assert!(fanout >= 2, "merkle fanout must be at least 2");
        Self {
            stack: Vec::new(),
            leaf_count: 0,
            fanout,
            _marker: core::marker::PhantomData,
        }
    }

    pub fn push(&mut self, leaf: HashDigest) {
        self.leaf_count += 1;
        self.push_to_level(0, leaf);
    }

    pub fn finalize(mut self) -> Option<HashDigest> {
        let mut carry: Option<HashDigest> = None;
        let total_levels = self.stack.len();
        for (idx, mut level_nodes) in self.stack.drain(..).enumerate() {
            if let Some(acc_node) = carry.take() {
                level_nodes.push(acc_node);
            }
            if level_nodes.is_empty() {
                continue;
            }
            let is_top_level = idx + 1 == total_levels;
            let duplicate_single = !(is_top_level && level_nodes.len() == 1);
            let combined = Self::combine_nodes::<H>(&mut level_nodes, duplicate_single);
            carry = Some(combined);
        }
        carry
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub fn fanout(&self) -> usize {
        self.fanout
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
        reconstruct_path_from_replay::<H, P>(
            leaf_index,
            self.leaf_count,
            self.fanout,
            producer,
        )
        .ok()
    }

    fn push_to_level(&mut self, level: usize, node: HashDigest) {
        if self.stack.len() <= level {
            self.stack.push(Vec::new());
        }
        self.stack[level].push(node);
        if self.stack[level].len() == self.fanout {
            let mut nodes = self.stack[level].split_off(0);
            let parent = Self::combine_nodes::<H>(&mut nodes, true);
            self.push_to_level(level + 1, parent);
        }
    }

    fn combine_nodes<Hfn: HashFunction>(
        nodes: &mut Vec<HashDigest>,
        duplicate_single: bool,
    ) -> HashDigest {
        match nodes.len() {
            0 => panic!("attempted to combine empty node list for merkle level"),
            1 if duplicate_single => {
                let only = nodes.drain(..).next().unwrap();
                hash_pair::<Hfn>(&only, &only)
            }
            1 => nodes.drain(..).next().unwrap(),
            _ => {
                let mut iter = nodes.drain(..);
                let mut acc = iter.next().unwrap();
                for node in iter {
                    acc = hash_pair::<Hfn>(&acc, &node);
                }
                acc
            }
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

    #[test]
    fn streaming_supports_custom_fanout() {
        let leaves: Vec<_> = (0u8..10).map(|i| Blake3::hash(&[i])).collect();
        let mut streaming = StreamingMerkle::<Blake3>::with_fanout(3);
        for leaf in &leaves {
            streaming.push(*leaf);
        }
        let test_index = 7;
        let producer = |idx: usize| leaves[idx];
        let streaming_path = streaming.extract_path(test_index, &producer).unwrap();

        let mut streaming_for_root = StreamingMerkle::<Blake3>::with_fanout(3);
        for leaf in &leaves {
            streaming_for_root.push(*leaf);
        }
        let root = streaming_for_root.finalize().unwrap();

        let reconstructed = super::super::reconstruct_path_from_replay::<Blake3, _>(
            test_index,
            leaves.len(),
            3,
            &producer,
        )
        .unwrap();
        assert!(reconstructed.verify::<Blake3>(root, leaves[7]));
        assert!(streaming_path.verify::<Blake3>(root, leaves[test_index]));
    }
}
