use crate::profile::{DurableFieldProfile, GoldilocksProfile};
use p3_goldilocks::Goldilocks;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 8] = b"TZCHAL1\0";
const WIDTH: usize = 8;
/// The challenger's sponge RATE.
const RATE: usize = 4;
/// The Merkle digest size in field elements — a DIFFERENT quantity from
/// `RATE` that happens to equal it for both profiles we support (Goldilocks
/// 4, BabyBear 8). `DurableFieldProfile`'s second parameter is the digest
/// size, so passing `RATE` there compiled only by that coincidence. Named
/// separately and pinned below so a future field where the sponge rate and
/// the digest size diverge fails loudly instead of silently mis-shaping the
/// Merkle tree.
const DIGEST_ELEMS: usize = 4;
const _: () = assert!(RATE == DIGEST_ELEMS);
const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
const CHECKSUM_BYTES: usize = 32;

pub type ProfilePermutation =
    <GoldilocksProfile as DurableFieldProfile<WIDTH, DIGEST_ELEMS>>::Permutation;
pub type ProfileChallenger =
    p3_challenger::DuplexChallenger<Goldilocks, ProfilePermutation, WIDTH, RATE>;

#[derive(Debug, thiserror::Error)]
pub enum ChallengerSnapshotError {
    #[error("challenger snapshot is malformed or non-canonical")]
    InvalidEncoding,
    #[error("challenger snapshot checksum mismatch")]
    ChecksumMismatch,
}

pub type Result<T> = std::result::Result<T, ChallengerSnapshotError>;

/// Versioned, permutation-independent representation of the pinned Plonky3
/// challenger. The permutation is reconstructed from the compatibility
/// profile and is deliberately excluded from checkpoint bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChallengerSnapshotV1 {
    pub schema_version: u32,
    pub sponge_state: [u64; WIDTH],
    pub input_buffer: Vec<u64>,
    pub output_buffer: Vec<u64>,
}

impl ChallengerSnapshotV1 {
    pub fn capture(challenger: &ProfileChallenger) -> Self {
        Self {
            schema_version: 1,
            sponge_state: challenger
                .sponge_state
                .map(|value| p3_field::PrimeField64::as_canonical_u64(&value)),
            input_buffer: challenger
                .input_buffer
                .iter()
                .map(p3_field::PrimeField64::as_canonical_u64)
                .collect(),
            output_buffer: challenger
                .output_buffer
                .iter()
                .map(p3_field::PrimeField64::as_canonical_u64)
                .collect(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.input_buffer.len() > RATE
            || self.output_buffer.len() > RATE
            || self
                .sponge_state
                .iter()
                .chain(&self.input_buffer)
                .chain(&self.output_buffer)
                .any(|value| *value >= GOLDILOCKS_MODULUS)
        {
            return Err(ChallengerSnapshotError::InvalidEncoding);
        }
        Ok(())
    }

    pub fn restore(&self) -> Result<ProfileChallenger> {
        self.validate()?;
        Ok(ProfileChallenger {
            sponge_state: self.sponge_state.map(Goldilocks::new),
            input_buffer: self
                .input_buffer
                .iter()
                .copied()
                .map(Goldilocks::new)
                .collect(),
            output_buffer: self
                .output_buffer
                .iter()
                .copied()
                .map(Goldilocks::new)
                .collect(),
            permutation: profile_permutation(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(
            MAGIC.len()
                + WIDTH * 8
                + 2
                + (self.input_buffer.len() + self.output_buffer.len()) * 8
                + CHECKSUM_BYTES,
        );
        bytes.extend_from_slice(MAGIC);
        for value in self.sponge_state {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.push(self.input_buffer.len() as u8);
        for value in &self.input_buffer {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.push(self.output_buffer.len() as u8);
        for value in &self.output_buffer {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        let checksum = blake3::hash(&bytes);
        bytes.extend_from_slice(checksum.as_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MAGIC.len() + WIDTH * 8 + 2 + CHECKSUM_BYTES {
            return Err(ChallengerSnapshotError::InvalidEncoding);
        }
        let (payload, encoded_checksum) = bytes.split_at(bytes.len() - CHECKSUM_BYTES);
        if blake3::hash(payload).as_bytes() != encoded_checksum {
            return Err(ChallengerSnapshotError::ChecksumMismatch);
        }
        let mut cursor = 0usize;
        if take(payload, &mut cursor, MAGIC.len())? != MAGIC {
            return Err(ChallengerSnapshotError::InvalidEncoding);
        }
        let mut sponge_state = [0u64; WIDTH];
        for value in &mut sponge_state {
            *value = decode_u64(take(payload, &mut cursor, 8)?)?;
        }
        let input_len = *take(payload, &mut cursor, 1)?
            .first()
            .ok_or(ChallengerSnapshotError::InvalidEncoding)? as usize;
        if input_len > RATE {
            return Err(ChallengerSnapshotError::InvalidEncoding);
        }
        let mut input_buffer = Vec::with_capacity(input_len);
        for _ in 0..input_len {
            input_buffer.push(decode_u64(take(payload, &mut cursor, 8)?)?);
        }
        let output_len = *take(payload, &mut cursor, 1)?
            .first()
            .ok_or(ChallengerSnapshotError::InvalidEncoding)? as usize;
        if output_len > RATE {
            return Err(ChallengerSnapshotError::InvalidEncoding);
        }
        let mut output_buffer = Vec::with_capacity(output_len);
        for _ in 0..output_len {
            output_buffer.push(decode_u64(take(payload, &mut cursor, 8)?)?);
        }
        if cursor != payload.len() {
            return Err(ChallengerSnapshotError::InvalidEncoding);
        }
        let snapshot = Self {
            schema_version: 1,
            sponge_state,
            input_buffer,
            output_buffer,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
}

pub(crate) fn profile_permutation() -> ProfilePermutation {
    // Delegates to `GoldilocksProfile::profile_permutation()` (`profile.rs`),
    // which is an exact copy of what this function used to compute inline
    // (same seed, same RNG algorithm, same constructor). Every existing
    // caller here (`fri.rs`, `mmcs.rs`, `prover.rs`'s tests, this module's
    // own `restore()`/tests) keeps calling this free function unchanged;
    // only its body is repointed at the new trait impl.
    GoldilocksProfile::profile_permutation()
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(len)
        .ok_or(ChallengerSnapshotError::InvalidEncoding)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ChallengerSnapshotError::InvalidEncoding)?;
    *cursor = end;
    Ok(value)
}

fn decode_u64(bytes: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| ChallengerSnapshotError::InvalidEncoding)?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_challenger::{CanObserve, CanSample};
    use p3_field::PrimeCharacteristicRing;

    fn assert_continuation_matches(mut original: ProfileChallenger) {
        let encoded = ChallengerSnapshotV1::capture(&original).encode().unwrap();
        let mut restored = ChallengerSnapshotV1::decode(&encoded)
            .unwrap()
            .restore()
            .unwrap();
        for _ in 0..32 {
            let expected: Goldilocks = original.sample();
            let actual: Goldilocks = restored.sample();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn resumes_with_pending_input() {
        let mut challenger = ProfileChallenger::new(profile_permutation());
        challenger.observe(Goldilocks::from_u64(7));
        challenger.observe(Goldilocks::from_u64(11));
        assert_continuation_matches(challenger);
    }

    #[test]
    fn resumes_with_pending_output() {
        let mut challenger = ProfileChallenger::new(profile_permutation());
        challenger.observe(Goldilocks::from_u64(7));
        let _: Goldilocks = challenger.sample();
        assert_continuation_matches(challenger);
    }

    #[test]
    fn rejects_mutated_and_non_canonical_snapshots() {
        let challenger = ProfileChallenger::new(profile_permutation());
        let mut encoded = ChallengerSnapshotV1::capture(&challenger).encode().unwrap();
        encoded[10] ^= 1;
        assert!(matches!(
            ChallengerSnapshotV1::decode(&encoded),
            Err(ChallengerSnapshotError::ChecksumMismatch)
        ));

        let mut invalid = ChallengerSnapshotV1::capture(&challenger);
        invalid.sponge_state[0] = GOLDILOCKS_MODULUS;
        assert!(matches!(
            invalid.encode(),
            Err(ChallengerSnapshotError::InvalidEncoding)
        ));
    }
}
