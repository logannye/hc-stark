use hc_commit::merkle::height_dfs::StreamingMerkle;
use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};
use hc_hash::{hash::HashDigest, Blake3, HashFunction};

use crate::StreamingCommitment;

pub struct StarkMerkleCommitment {
    builder: StreamingMerkle<Blake3>,
}

impl Default for StarkMerkleCommitment {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkMerkleCommitment {
    pub fn new() -> Self {
        Self {
            builder: StreamingMerkle::new(),
        }
    }

    pub fn hash_field<F: FieldElement>(value: &F) -> HashDigest {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&value.to_u64().to_le_bytes());
        bytes[8..].copy_from_slice(&value.square().to_u64().to_le_bytes());
        Blake3::hash(&bytes)
    }
}

impl<F: FieldElement> StreamingCommitment<F> for StarkMerkleCommitment {
    type Output = HashDigest;

    fn absorb_block(&mut self, _block_index: usize, data: &[F]) -> HcResult<()> {
        for value in data {
            self.builder.push(Self::hash_field(value));
        }
        Ok(())
    }

    fn finalize(self) -> HcResult<Self::Output> {
        self.builder
            .finalize()
            .ok_or_else(|| HcError::message("failed to finalize streaming Merkle commitment"))
    }
}
