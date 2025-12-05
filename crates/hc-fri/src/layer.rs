use std::sync::Arc;

use hc_commit::merkle::{height_dfs::StreamingMerkle, reconstruct_path_from_replay, MerklePath};
use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};
use hc_hash::{hash::HashDigest, Blake3, HashFunction};

use crate::oracles::{FriOracle, InMemoryFriOracle};

#[derive(Clone, Debug)]
pub struct FriLayer<F: FieldElement> {
    pub beta: F,
    pub oracle: InMemoryFriOracle<F>,
    merkle_root: HashDigest,
    leaf_hashes: Arc<Vec<HashDigest>>,
}

impl<F: FieldElement> FriLayer<F> {
    pub fn from_values(beta: F, values: Arc<Vec<F>>) -> HcResult<Self> {
        let hashes: Vec<HashDigest> = values.iter().map(Self::hash_value).collect();
        let mut builder = StreamingMerkle::<Blake3>::new();
        for hash in &hashes {
            builder.push(*hash);
        }
        let root = builder
            .finalize()
            .ok_or_else(|| HcError::message("failed to finalize FRI layer commitment"))?;
        Ok(Self {
            beta,
            oracle: InMemoryFriOracle::new(values),
            merkle_root: root,
            leaf_hashes: Arc::new(hashes),
        })
    }

    pub fn len(&self) -> usize {
        self.oracle.len()
    }

    pub fn is_empty(&self) -> bool {
        self.oracle.is_empty()
    }

    pub fn merkle_root(&self) -> HashDigest {
        self.merkle_root
    }

    pub fn merkle_path(&self, index: usize) -> HcResult<MerklePath> {
        let hashes = Arc::clone(&self.leaf_hashes);
        reconstruct_path_from_replay::<Blake3, _>(index, hashes.len(), 2, &|idx| hashes[idx])
    }

    pub fn hash_value(value: &F) -> HashDigest {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&value.to_u64().to_le_bytes());
        bytes[8..].copy_from_slice(&value.square().to_u64().to_le_bytes());
        Blake3::hash(&bytes)
    }
}

#[derive(Clone, Debug)]
pub struct FriFinalLayer<F: FieldElement> {
    values: Arc<Vec<F>>,
    merkle_root: HashDigest,
    leaf_hashes: Arc<Vec<HashDigest>>,
}

impl<F: FieldElement> FriFinalLayer<F> {
    pub fn from_values(values: Arc<Vec<F>>) -> HcResult<Self> {
        if values.is_empty() {
            return Err(HcError::invalid_argument(
                "final FRI layer must contain at least one evaluation",
            ));
        }
        let hashes: Vec<HashDigest> = values.iter().map(FriLayer::hash_value).collect();
        let mut builder = StreamingMerkle::<Blake3>::new();
        for hash in &hashes {
            builder.push(*hash);
        }
        let root = builder
            .finalize()
            .ok_or_else(|| HcError::message("failed to finalize final layer commitment"))?;
        Ok(Self {
            values,
            merkle_root: root,
            leaf_hashes: Arc::new(hashes),
        })
    }

    pub fn evaluations(&self) -> &[F] {
        &self.values
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn merkle_root(&self) -> HashDigest {
        self.merkle_root
    }

    pub fn merkle_path(&self, index: usize) -> HcResult<MerklePath> {
        let hashes = Arc::clone(&self.leaf_hashes);
        reconstruct_path_from_replay::<Blake3, _>(index, hashes.len(), 2, &|idx| hashes[idx])
    }

    pub fn hash_leaf(value: &F) -> HashDigest {
        FriLayer::hash_value(value)
    }
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
