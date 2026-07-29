//! Field-relative security accounting for the frozen FRI profile.
//!
//! `prover.rs` builds its FRI parameters with `FriParameters::new_benchmark`,
//! which is **field-blind**: same blowup, same query count, same grinding bits
//! regardless of which field the proof is over. That is fine as long as the
//! resulting security level is actually checked per profile, because the two
//! inputs that DO vary by field are
//!
//! * the **extension-field size**, which caps FRI soundness — Goldilocks is
//!   `2 x 64 = 128` bits, BabyBear `4 x 31 = 124`; and
//! * the **digest size**, which caps collision resistance at half the digest —
//!   Goldilocks `4 x 64 = 256` bits of digest, BabyBear `8 x 31 = 248`.
//!
//! Phase 3A's product claim is soundness of the stock `p3_uni_stark` verifier,
//! so shipping a second field without a security number attached would be
//! claiming something unmeasured. This module computes the number with
//! upstream's own estimator (`p3_uni_stark::ConjecturedSecurity`),
//! not a local reimplementation, and pins a floor.

/// log2 of the FRI blowup, from `FriParameters::new_benchmark`
/// (`p3-fri-0.6.1/src/config.rs:78`). `make_config` re-sets this to the same
/// value explicitly; `make_config_with_log_blowup` can raise it, which only
/// increases security, so this is the conservative case.
pub const FROZEN_FRI_LOG_BLOWUP: usize = 1;
/// `p3-fri-0.6.1/src/config.rs:81`.
pub const FROZEN_FRI_NUM_QUERIES: usize = 100;
/// `p3-fri-0.6.1/src/config.rs:83`.
pub const FROZEN_FRI_QUERY_POW_BITS: usize = 16;

/// The floor every shipped profile must clear. 100 bits is the conventional
/// bar for a production STARK; both currently supported profiles clear it with
/// room to spare, so this is a regression guard rather than a tight bound.
pub const MINIMUM_CONJECTURED_SECURITY_BITS: usize = 100;

/// Conjectured security bits for a profile, using upstream's estimator.
///
/// `collision_resistance` is half the digest, and the digest is
/// `DIGEST_ELEMS` base-field elements wide. `num_modulus_bits` is the size of
/// the *extension* field, which is where FRI actually operates.
pub fn conjectured_security_bits(
    base_field_bits: usize,
    extension_degree: usize,
    digest_elems: usize,
) -> usize {
    let num_modulus_bits = base_field_bits * extension_degree;
    let collision_resistance = (base_field_bits * digest_elems) / 2;
    p3_uni_stark::ConjecturedSecurity::compute(
        FROZEN_FRI_LOG_BLOWUP,
        FROZEN_FRI_NUM_QUERIES,
        FROZEN_FRI_QUERY_POW_BITS,
        collision_resistance,
        num_modulus_bits,
    )
    .security_bits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Goldilocks: 64-bit base, degree-2 extension, 4-element digest.
    const GOLDILOCKS: (usize, usize, usize) = (64, 2, 4);
    /// BabyBear: 31-bit base, degree-4 extension, 8-element digest. The
    /// 8-element digest is not cosmetic — a 4-element BabyBear digest would be
    /// ~62-bit collision resistance and would fail the floor below.
    const BABYBEAR: (usize, usize, usize) = (31, 4, 8);

    #[test]
    fn every_shipped_profile_clears_the_security_floor() {
        for (name, (base, degree, digest)) in [("goldilocks", GOLDILOCKS), ("babybear", BABYBEAR)] {
            let bits = conjectured_security_bits(base, degree, digest);
            assert!(
                bits >= MINIMUM_CONJECTURED_SECURITY_BITS,
                "{name} conjectured security is {bits} bits, below the \
                 {MINIMUM_CONJECTURED_SECURITY_BITS}-bit floor; do NOT publish \
                 a benchmark for it until the FRI parameters are raised"
            );
        }
    }

    /// The load-bearing comparison: adding BabyBear must not quietly ship a
    /// weaker proof system than the field the product was built on. BabyBear's
    /// extension field is 124 bits against Goldilocks' 128, so it CAN be
    /// lower — but only marginally, and never below the floor.
    #[test]
    fn babybear_is_not_materially_weaker_than_goldilocks() {
        let goldilocks = conjectured_security_bits(GOLDILOCKS.0, GOLDILOCKS.1, GOLDILOCKS.2);
        let babybear = conjectured_security_bits(BABYBEAR.0, BABYBEAR.1, BABYBEAR.2);
        assert!(
            babybear + 8 >= goldilocks,
            "babybear ({babybear} bits) is more than 8 bits weaker than \
             goldilocks ({goldilocks} bits); the frozen field-blind FRI \
             parameters are no longer adequate for both profiles"
        );
    }

    /// Guards the reason the floor passes. If a future profile shrinks the
    /// digest, collision resistance — not the FRI query count — becomes the
    /// binding constraint, and this catches it as a distinct failure.
    #[test]
    fn a_four_element_babybear_digest_would_fail_the_floor() {
        let bits = conjectured_security_bits(BABYBEAR.0, BABYBEAR.1, 4);
        assert!(
            bits < MINIMUM_CONJECTURED_SECURITY_BITS,
            "expected a 4-element BabyBear digest (~62-bit collision \
             resistance) to fall below the floor, got {bits} bits -- if this \
             fails the floor is not actually binding on digest size"
        );
    }
}
