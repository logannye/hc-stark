use blake3::Hasher;

use crate::hash::{HashDigest, HashFunction, DIGEST_LEN};

#[derive(Clone, Copy, Debug, Default)]
pub struct Blake3;

impl HashFunction for Blake3 {
    type State = Hasher;

    fn new() -> Self::State {
        Hasher::new()
    }

    fn update(state: &mut Self::State, data: &[u8]) {
        state.update(data);
    }

    fn finalize(state: Self::State) -> HashDigest {
        let mut bytes = [0u8; DIGEST_LEN];
        bytes.copy_from_slice(state.finalize().as_bytes());
        HashDigest::from(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_matches_reference() {
        let digest = Blake3::hash(b"hc-stark");
        assert_eq!(
            format!("{digest}"),
            "cab7e0ca09802f58aec16f6c52e545da8fa6e95f3c72877f12113108756d7b93"
        );
    }
}
