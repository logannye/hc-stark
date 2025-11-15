//! Randomness helpers used across the workspace.

use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::field::FieldElement;

/// Deterministic RNG seeded from a 32-byte array.
pub fn seeded_rng(seed: [u8; 32]) -> StdRng {
    StdRng::from_seed(seed)
}

/// Sample `count` random field elements.
pub fn sample_field_elements<F: FieldElement>(rng: &mut impl Rng, count: usize) -> Vec<F> {
    (0..count).map(|_| F::random(rng)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::field::prime_field::GoldilocksField;
    use rand::RngCore;

    #[test]
    fn seeded_rng_is_deterministic() {
        let mut rng_a = seeded_rng([42u8; 32]);
        let mut rng_b = seeded_rng([42u8; 32]);
        assert_eq!(rng_a.next_u64(), rng_b.next_u64());
    }

    #[test]
    fn samples_have_requested_length() {
        let mut rng = seeded_rng([7u8; 32]);
        let samples: Vec<GoldilocksField> = sample_field_elements(&mut rng, 8);
        assert_eq!(samples.len(), 8);
    }
}
