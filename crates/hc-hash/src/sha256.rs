use sha2::{Digest, Sha256 as Sha2};

use crate::hash::{HashDigest, HashFunction, DIGEST_LEN};

#[derive(Clone, Copy, Debug, Default)]
pub struct Sha256;

impl HashFunction for Sha256 {
    type State = Sha2;

    fn new() -> Self::State {
        Sha2::new()
    }

    fn update(state: &mut Self::State, data: &[u8]) {
        state.update(data);
    }

    fn finalize(state: Self::State) -> HashDigest {
        let bytes = state.finalize();
        let mut array = [0u8; DIGEST_LEN];
        array.copy_from_slice(&bytes);
        HashDigest::from(array)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_reference() {
        let digest = Sha256::hash(b"hc-stark");
        assert_eq!(
            format!("{digest}"),
            "cf53f4c9267a870eb7f4b521f2febfc9b8f879a3e626b9a0dd5b5eb4206b88de"
        );
    }
}
