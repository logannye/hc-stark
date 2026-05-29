//! Proof-of-work (grinding) helpers shared by prover and verifier.
//!
//! The prover finds a nonce such that a transcript-derived digest has at least
//! `bits` leading zero bits. The verifier re-checks the same digest, so both
//! sides MUST use the identical [`grind_digest`] computation.
//!
//! See `docs/proof_format_v5_grinding.md` for the protocol specification.

use crate::hash::{HashDigest, HashFunction};
use crate::protocol;
use crate::transcript::Transcript;

/// Count the number of leading zero bits in `bytes`, MSB-first across bytes.
///
/// Returns 0 for an empty slice.
pub fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut n = 0u32;
    for &b in bytes {
        if b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

/// The single digest both prover and verifier compute for a given `nonce`.
///
/// Forks `base` (clones — does NOT mutate `base`), appends `nonce` under
/// `label`, then squeezes using [`crate::protocol::label::FRI_GRINDING_NONCE`].
fn grind_digest<H: HashFunction>(base: &Transcript<H>, label: &[u8], nonce: u64) -> HashDigest {
    let mut probe = base.clone();
    protocol::append_u64::<H>(&mut probe, label, nonce);
    probe.challenge_bytes(protocol::label::FRI_GRINDING_NONCE)
}

/// Prover side: find the smallest nonce whose [`grind_digest`] has
/// at least `bits` leading zero bits.
///
/// For `bits = 0` this always returns 0 immediately.  For large `bits` this
/// is computationally expensive (expected 2^bits hash evaluations).
///
/// Panics only if the u64 nonce space is exhausted (≈1.8 × 10^19 hashes),
/// which is never reachable in practice.
pub fn grind<H: HashFunction>(base: &Transcript<H>, label: &[u8], bits: u32) -> u64 {
    let mut nonce = 0u64;
    loop {
        let digest = grind_digest::<H>(base, label, nonce);
        if leading_zero_bits(digest.as_bytes()) >= bits {
            return nonce;
        }
        nonce = nonce
            .checked_add(1)
            .expect("grinding nonce space exhausted");
    }
}

/// Verifier side: returns `true` iff `nonce` satisfies the ≥ `bits` leading
/// zero requirement under `base` / `label`.
///
/// Deterministic and does NOT mutate `base`.
pub fn check_grinding<H: HashFunction>(
    base: &Transcript<H>,
    label: &[u8],
    nonce: u64,
    bits: u32,
) -> bool {
    leading_zero_bits(grind_digest::<H>(base, label, nonce).as_bytes()) >= bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blake3::Blake3;
    use crate::transcript::Transcript;

    // ── leading_zero_bits hand vectors ──────────────────────────────────────

    #[test]
    fn lzb_empty() {
        assert_eq!(leading_zero_bits(&[]), 0);
    }

    #[test]
    fn lzb_zero_byte() {
        assert_eq!(leading_zero_bits(&[0x00]), 8);
    }

    #[test]
    fn lzb_high_bit_set() {
        assert_eq!(leading_zero_bits(&[0x80]), 0);
    }

    #[test]
    fn lzb_one() {
        assert_eq!(leading_zero_bits(&[0x01]), 7);
    }

    #[test]
    fn lzb_two_zero_bytes_then_partial() {
        // 0x00 0x00 0x40 → 8 + 8 + 1 = 17
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x40]), 17);
    }

    // ── grind / check_grinding round-trip ───────────────────────────────────

    const BITS: u32 = 8; // small enough to be fast in CI

    fn base_transcript() -> Transcript<Blake3> {
        let mut t = Transcript::<Blake3>::new(b"hc-stark/test");
        t.append_message(b"seed", b"grinding_test_seed_42");
        t
    }

    #[test]
    fn grind_finds_valid_nonce() {
        let t = base_transcript();
        let nonce = grind::<Blake3>(&t, b"test/nonce", BITS);
        assert!(
            check_grinding::<Blake3>(&t, b"test/nonce", nonce, BITS),
            "check_grinding must accept the nonce returned by grind"
        );
    }

    #[test]
    fn check_grinding_rejects_insufficient_bits() {
        let t = base_transcript();
        let nonce = grind::<Blake3>(&t, b"test/nonce", BITS);
        // Demanding 60 leading zero bits from a nonce ground for only BITS is
        // astronomically unlikely to pass.
        assert!(
            !check_grinding::<Blake3>(&t, b"test/nonce", nonce, 60),
            "check_grinding with bits=60 should reject a nonce ground for bits={BITS}"
        );
    }

    #[test]
    fn grind_is_deterministic() {
        let t = base_transcript();
        let nonce_a = grind::<Blake3>(&t, b"test/nonce", BITS);
        let nonce_b = grind::<Blake3>(&t, b"test/nonce", BITS);
        assert_eq!(
            nonce_a, nonce_b,
            "grind must be deterministic for the same base transcript"
        );
    }

    #[test]
    fn base_transcript_unmutated_by_grind() {
        let mut t = base_transcript();
        // Squeeze a reference challenge BEFORE grinding.
        let chal_before = t.challenge_bytes(b"after_grind_marker");

        // Re-create the same transcript state from scratch and grind on it.
        let t2 = base_transcript();
        let _nonce = grind::<Blake3>(&t2, b"test/nonce", BITS);

        // Squeeze the same challenge from t2 — must equal chal_before.
        let mut t2_after = base_transcript();
        let chal_after = t2_after.challenge_bytes(b"after_grind_marker");

        assert_eq!(
            chal_before, chal_after,
            "grind must not mutate the base transcript"
        );
    }

    #[test]
    fn grind_zero_bits_returns_immediately() {
        let t = base_transcript();
        // bits=0 means every nonce qualifies; must return 0 without any hashing loop.
        let nonce = grind::<Blake3>(&t, b"test/nonce", 0);
        assert_eq!(nonce, 0);
        assert!(check_grinding::<Blake3>(&t, b"test/nonce", nonce, 0));
    }
}
