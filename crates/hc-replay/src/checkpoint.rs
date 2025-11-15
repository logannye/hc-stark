use hc_hash::hash::{HashDigest, HashFunction};

#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub block_index: usize,
    pub digest: HashDigest,
}

impl Checkpoint {
    pub fn new(block_index: usize, digest: HashDigest) -> Self {
        Self {
            block_index,
            digest,
        }
    }

    pub fn from_bytes<H: HashFunction>(block_index: usize, data: &[u8]) -> Self {
        let digest = H::hash(data);
        Self {
            block_index,
            digest,
        }
    }
}
