use hc_hash::hash::{HashDigest, HashFunction, DIGEST_LEN};

pub mod height_dfs;
pub mod path;
pub mod standard;

pub use path::{MerklePath, PathNode, reconstruct_path_from_replay};
pub use standard::MerkleTree;

pub(crate) fn hash_pair<H: HashFunction>(left: &HashDigest, right: &HashDigest) -> HashDigest {
    let mut buffer = [0u8; DIGEST_LEN * 2];
    buffer[..DIGEST_LEN].copy_from_slice(left.as_bytes());
    buffer[DIGEST_LEN..].copy_from_slice(right.as_bytes());
    H::hash(&buffer)
}
