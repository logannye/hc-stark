use core::marker::PhantomData;

use hc_core::error::{HcError, HcResult};
use hc_hash::hash::{HashDigest, HashFunction};

use super::{hash_pair, MerklePath, PathNode};
use crate::vector_commitment::{ensure_non_empty, VectorCommitment};

pub struct MerkleTree<H: HashFunction> {
    layers: Vec<Vec<HashDigest>>,
    _marker: PhantomData<H>,
}

impl<H: HashFunction> MerkleTree<H> {
    pub fn from_leaves(leaves: &[HashDigest]) -> HcResult<Self> {
        ensure_non_empty(leaves)?;
        let mut layers = Vec::new();
        layers.push(leaves.to_vec());
        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let mut next = Vec::with_capacity((prev.len() + 1) / 2);
            for chunk in prev.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
                next.push(hash_pair::<H>(&left, &right));
            }
            layers.push(next);
        }
        Ok(Self {
            layers,
            _marker: PhantomData,
        })
    }

    pub fn root(&self) -> HashDigest {
        self.layers.last().unwrap()[0]
    }

    pub fn open(&self, index: usize) -> HcResult<MerklePath> {
        if index >= self.layers[0].len() {
            return Err(HcError::invalid_argument("leaf index out of range"));
        }
        let mut path = Vec::with_capacity(self.layers.len().saturating_sub(1));
        let mut idx = index;
        for level in &self.layers[..self.layers.len() - 1] {
            let is_left = idx % 2 == 1;
            let sibling_idx = if is_left {
                idx - 1
            } else {
                (idx + 1).min(level.len() - 1)
            };
            let sibling_is_left = sibling_idx < idx;
            path.push(PathNode {
                sibling: level[sibling_idx],
                sibling_is_left,
            });
            idx /= 2;
        }
        Ok(MerklePath::new(path))
    }

    pub fn leaf(&self, index: usize) -> HcResult<HashDigest> {
        self.layers
            .first()
            .and_then(|layer| layer.get(index))
            .copied()
            .ok_or_else(|| HcError::invalid_argument("leaf index out of range"))
    }
}

impl<H: HashFunction> VectorCommitment for MerkleTree<H> {
    type Proof = MerklePath;

    fn commit(leaves: &[HashDigest]) -> HcResult<HashDigest> {
        Ok(Self::from_leaves(leaves)?.root())
    }

    fn open(leaves: &[HashDigest], index: usize) -> HcResult<(HashDigest, Self::Proof)> {
        let tree = Self::from_leaves(leaves)?;
        let leaf = tree.leaf(index)?;
        let path = tree.open(index)?;
        Ok((leaf, path))
    }

    fn verify(root: HashDigest, leaf: HashDigest, proof: &Self::Proof) -> bool {
        proof.verify::<H>(root, leaf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector_commitment::VectorCommitment;
    use hc_hash::blake3::Blake3;

    #[test]
    fn path_verifies() {
        let leaves: Vec<_> = (0u8..4).map(|i| Blake3::hash(&[i])).collect();
        let tree = MerkleTree::<Blake3>::from_leaves(&leaves).unwrap();
        let leaf = tree.leaf(2).unwrap();
        let proof = tree.open(2).unwrap();
        assert!(proof.verify::<Blake3>(tree.root(), leaf));

        let (leaf_trait, proof_trait) =
            <MerkleTree<Blake3> as VectorCommitment>::open(&leaves, 2).unwrap();
        assert_eq!(leaf_trait, leaf);
        assert!(MerkleTree::<Blake3>::verify(
            tree.root(),
            leaf_trait,
            &proof_trait
        ));
    }
}
