use core::fmt;

pub const DIGEST_LEN: usize = 32;

/// Fixed-size hash digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HashDigest(pub(crate) [u8; DIGEST_LEN]);

impl HashDigest {
    pub const fn new(bytes: [u8; DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DIGEST_LEN {
            return None;
        }
        let mut array = [0u8; DIGEST_LEN];
        array.copy_from_slice(bytes);
        Some(Self(array))
    }

    pub fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; DIGEST_LEN] {
        self.0
    }
}

impl fmt::Debug for HashDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Display for HashDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<[u8; DIGEST_LEN]> for HashDigest {
    fn from(value: [u8; DIGEST_LEN]) -> Self {
        HashDigest::new(value)
    }
}

/// Abstract hash function API so the rest of the prover can remain hash-agnostic.
pub trait HashFunction: Send + Sync + 'static {
    type State: Clone;

    fn new() -> Self::State;
    fn update(state: &mut Self::State, data: &[u8]);
    fn finalize(state: Self::State) -> HashDigest;

    fn hash(data: &[u8]) -> HashDigest {
        let mut state = Self::new();
        Self::update(&mut state, data);
        Self::finalize(state)
    }
}
