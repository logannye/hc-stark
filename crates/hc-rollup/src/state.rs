//! Sparse Merkle tree (SMT) for rollup state management.
//!
//! The SMT provides O(log N) membership proofs for key-value pairs where
//! the key space is 2^32. Empty subtrees are represented by a single
//! precomputed hash at each level, making storage proportional to the
//! number of occupied leaves.
//!
//! Root computation is O(K * H) where K = number of occupied leaves and
//! H = tree height, since we only traverse paths containing leaves.

use hc_hash::{HashDigest, DIGEST_LEN};
use std::collections::HashMap;

/// Height of the Merkle tree. 32 levels gives 2^32 slots.
pub const TREE_HEIGHT: usize = 32;

/// Precomputed "empty" hash at each level of the tree.
/// `EMPTY_HASHES[0]` = hash of empty leaf, `EMPTY_HASHES[i]` = hash(EMPTY[i-1], EMPTY[i-1]).
fn empty_hashes() -> [HashDigest; TREE_HEIGHT + 1] {
    let mut hashes = [HashDigest::new([0u8; DIGEST_LEN]); TREE_HEIGHT + 1];
    hashes[0] = hash_leaf(&[0u8; 32]);
    for i in 1..=TREE_HEIGHT {
        hashes[i] = hash_pair(&hashes[i - 1], &hashes[i - 1]);
    }
    hashes
}

/// Sparse Merkle Tree with key-value storage.
///
/// Uses a node-level HashMap to store only non-empty internal nodes.
/// Root computation walks only paths containing occupied leaves.
#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    /// Occupied leaves: key (as u32 index) -> value (32 bytes).
    leaves: HashMap<u32, [u8; 32]>,
    /// Internal node storage: (level, index) -> hash.
    /// Only non-empty nodes are stored.
    nodes: HashMap<(usize, u32), HashDigest>,
    /// Precomputed empty hashes per level.
    empty: [HashDigest; TREE_HEIGHT + 1],
}

/// Inclusion/exclusion proof for a key in the SMT.
#[derive(Clone, Debug)]
pub struct SmtProof {
    pub key: u32,
    pub value: Option<[u8; 32]>,
    /// Sibling hashes from leaf to root (length = TREE_HEIGHT).
    pub siblings: Vec<HashDigest>,
}

impl SparseMerkleTree {
    /// Create a new empty sparse Merkle tree.
    pub fn new() -> Self {
        Self {
            leaves: HashMap::new(),
            nodes: HashMap::new(),
            empty: empty_hashes(),
        }
    }

    /// Get the root hash.
    pub fn root(&self) -> HashDigest {
        self.get_node(TREE_HEIGHT, 0)
    }

    /// Insert or update a key-value pair. Recomputes affected path.
    pub fn insert(&mut self, key: u32, value: [u8; 32]) {
        self.leaves.insert(key, value);
        self.recompute_path(key);
    }

    /// Remove a key from the tree (set to empty). Recomputes affected path.
    pub fn remove(&mut self, key: u32) {
        self.leaves.remove(&key);
        self.recompute_path(key);
    }

    /// Get the value at a key, if present.
    pub fn get(&self, key: u32) -> Option<&[u8; 32]> {
        self.leaves.get(&key)
    }

    /// Generate a membership proof for a key.
    pub fn prove(&self, key: u32) -> SmtProof {
        let value = self.leaves.get(&key).copied();
        let mut siblings = Vec::with_capacity(TREE_HEIGHT);
        let mut idx = key;

        for level in 0..TREE_HEIGHT {
            let sibling_idx = idx ^ 1;
            siblings.push(self.get_node(level, sibling_idx));
            idx /= 2;
        }

        SmtProof {
            key,
            value,
            siblings,
        }
    }

    /// Verify a membership proof against a given root.
    pub fn verify_proof(proof: &SmtProof, root: &HashDigest) -> bool {
        if proof.siblings.len() != TREE_HEIGHT {
            return false;
        }

        let empty = empty_hashes();
        let leaf_hash = match &proof.value {
            Some(val) => hash_leaf(val),
            None => empty[0],
        };

        let mut current = leaf_hash;
        let mut idx = proof.key;

        for sibling in &proof.siblings {
            if idx & 1 == 0 {
                current = hash_pair(&current, sibling);
            } else {
                current = hash_pair(sibling, &current);
            }
            idx /= 2;
        }

        current == *root
    }

    /// Get the hash of a node. Returns empty hash if not stored.
    fn get_node(&self, level: usize, index: u32) -> HashDigest {
        if level == 0 {
            match self.leaves.get(&index) {
                Some(value) => hash_leaf(value),
                None => self.empty[0],
            }
        } else {
            self.nodes
                .get(&(level, index))
                .copied()
                .unwrap_or(self.empty[level])
        }
    }

    /// Recompute internal nodes along the path from a leaf to the root.
    fn recompute_path(&mut self, key: u32) {
        let mut idx = key;

        for level in 1..=TREE_HEIGHT {
            let parent_idx = idx / 2;
            let left_child = idx & !1; // Even sibling.
            let right_child = left_child | 1; // Odd sibling.

            let left_hash = self.get_node(level - 1, left_child);
            let right_hash = self.get_node(level - 1, right_child);

            // If both children are empty, the parent is the precomputed empty hash.
            if left_hash == self.empty[level - 1] && right_hash == self.empty[level - 1] {
                self.nodes.remove(&(level, parent_idx));
            } else {
                let parent_hash = hash_pair(&left_hash, &right_hash);
                self.nodes.insert((level, parent_idx), parent_hash);
            }

            idx = parent_idx;
        }
    }

    /// Number of occupied leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

fn hash_leaf(value: &[u8; 32]) -> HashDigest {
    let mut hasher = ::blake3::Hasher::new();
    hasher.update(b"hc-smt-leaf");
    hasher.update(value);
    let hash = hasher.finalize();
    let bytes: [u8; DIGEST_LEN] = hash.as_bytes()[..DIGEST_LEN].try_into().unwrap();
    HashDigest::from(bytes)
}

fn hash_pair(left: &HashDigest, right: &HashDigest) -> HashDigest {
    let mut hasher = ::blake3::Hasher::new();
    hasher.update(b"hc-smt-node");
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    let hash = hasher.finalize();
    let bytes: [u8; DIGEST_LEN] = hash.as_bytes()[..DIGEST_LEN].try_into().unwrap();
    HashDigest::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_has_consistent_root() {
        let tree = SparseMerkleTree::new();
        let root = tree.root();
        // Root should equal the precomputed empty hash at top level.
        assert_eq!(root, empty_hashes()[TREE_HEIGHT]);
    }

    #[test]
    fn insert_changes_root() {
        let mut tree = SparseMerkleTree::new();
        let root_before = tree.root();
        tree.insert(0, [1u8; 32]);
        let root_after = tree.root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn get_returns_inserted_value() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(42, [0xAB; 32]);
        assert_eq!(tree.get(42), Some(&[0xAB; 32]));
        assert_eq!(tree.get(43), None);
    }

    #[test]
    fn remove_restores_empty_root() {
        let mut tree = SparseMerkleTree::new();
        let empty_root = tree.root();
        tree.insert(0, [1u8; 32]);
        tree.remove(0);
        assert_eq!(tree.root(), empty_root);
    }

    #[test]
    fn proof_verifies_for_existing_key() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(100, [0xCC; 32]);
        let root = tree.root();
        let proof = tree.prove(100);
        assert!(SparseMerkleTree::verify_proof(&proof, &root));
        assert_eq!(proof.value, Some([0xCC; 32]));
    }

    #[test]
    fn proof_verifies_for_missing_key() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(100, [0xCC; 32]);
        let root = tree.root();
        let proof = tree.prove(200);
        assert!(SparseMerkleTree::verify_proof(&proof, &root));
        assert_eq!(proof.value, None);
    }

    #[test]
    fn proof_rejects_wrong_root() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(100, [0xCC; 32]);
        let proof = tree.prove(100);
        let wrong_root = HashDigest::from([0xFF; 32]);
        assert!(!SparseMerkleTree::verify_proof(&proof, &wrong_root));
    }

    #[test]
    fn multiple_inserts_independent() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(0, [1; 32]);
        let root1 = tree.root();
        tree.insert(1, [2; 32]);
        let root2 = tree.root();
        assert_ne!(root1, root2);

        // Both proofs should verify against root2.
        let proof0 = tree.prove(0);
        let proof1 = tree.prove(1);
        assert!(SparseMerkleTree::verify_proof(&proof0, &root2));
        assert!(SparseMerkleTree::verify_proof(&proof1, &root2));
    }

    #[test]
    fn large_key_works() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(u32::MAX, [0xFF; 32]);
        let root = tree.root();
        let proof = tree.prove(u32::MAX);
        assert!(SparseMerkleTree::verify_proof(&proof, &root));
    }
}
