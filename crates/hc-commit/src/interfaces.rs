use hc_hash::hash::HashDigest;

/// Objects that can be converted into leaf digests.
pub trait LeafEncoder {
    fn to_digest(&self) -> HashDigest;
}

impl LeafEncoder for HashDigest {
    fn to_digest(&self) -> HashDigest {
        *self
    }
}
