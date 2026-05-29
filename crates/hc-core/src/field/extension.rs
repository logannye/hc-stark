//! Lightweight quadratic extension field implementation.
//!
//! # Fold operation availability
//!
//! `QuadExtension<F>` implements `FieldElement` and therefore exposes all
//! arithmetic needed by FRI folding in the extension field K = F[u]/(u²-7):
//! - `add`, `sub`, `neg`, `mul`, `square`, `inverse`, `pow`
//! - `from_u64`, `ONE`, `ZERO`
//!
//! Nothing is missing; Tasks 7/8 can run the FRI fold natively in K.

use rand::Rng;

use super::FieldElement;

/// Quadratic extension element `c0 + c1 * u` where `u^2 = NON_RESIDUE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct QuadExtension<F: FieldElement> {
    pub c0: F,
    pub c1: F,
}

impl<F: FieldElement> QuadExtension<F> {
    const NON_RESIDUE: u64 = 7;

    #[inline]
    pub fn new(c0: F, c1: F) -> Self {
        Self { c0, c1 }
    }

    /// Embed a base-field element into the extension as `c0 + 0·u`.
    ///
    /// This is a ring homomorphism: `from_base(a+b) == from_base(a)+from_base(b)`
    /// and `from_base(a·b) == from_base(a)·from_base(b)`.  Call sites that
    /// need clarity about the embedding should prefer this over `new(c0, F::ZERO)`
    /// or `from_u64`.
    #[inline]
    pub fn from_base(c0: F) -> Self {
        Self { c0, c1: F::ZERO }
    }
}

/// Deterministic 16-byte little-endian encoding for `QuadExtension<GoldilocksField>`.
///
/// Layout: `[c0.to_u64().to_le_bytes() (8 bytes) || c1.to_u64().to_le_bytes() (8 bytes)]`.
/// Both coefficients are bound by the encoding; two elements that differ in c1
/// (but share c0) produce different byte strings.
impl QuadExtension<super::prime_field::GoldilocksField> {
    /// Serialize to 16 bytes: 8-byte LE c0 followed by 8-byte LE c1.
    #[inline]
    pub fn to_le_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.c0.to_u64().to_le_bytes());
        out[8..].copy_from_slice(&self.c1.to_u64().to_le_bytes());
        out
    }

    /// Deserialize from 16 bytes produced by `to_le_bytes`.
    #[inline]
    pub fn from_le_bytes(bytes: &[u8; 16]) -> Self {
        use super::prime_field::GoldilocksField;
        let c0 = GoldilocksField::from_u64(u64::from_le_bytes(bytes[..8].try_into().unwrap()));
        let c1 = GoldilocksField::from_u64(u64::from_le_bytes(bytes[8..].try_into().unwrap()));
        Self { c0, c1 }
    }
}

impl<F: FieldElement> FieldElement for QuadExtension<F> {
    const ZERO: Self = Self {
        c0: F::ZERO,
        c1: F::ZERO,
    };
    const ONE: Self = Self {
        c0: F::ONE,
        c1: F::ZERO,
    };

    fn is_zero(self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.add(rhs.c0),
            c1: self.c1.add(rhs.c1),
        }
    }

    fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.sub(rhs.c0),
            c1: self.c1.sub(rhs.c1),
        }
    }

    fn mul(self, rhs: Self) -> Self {
        let a = self.c0.mul(rhs.c0);
        let b = self.c1.mul(rhs.c1);
        let non_residue = F::from_u64(Self::NON_RESIDUE);
        Self {
            c0: a.add(b.mul(non_residue)),
            c1: self.c0.mul(rhs.c1).add(self.c1.mul(rhs.c0)),
        }
    }

    fn neg(self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    fn inverse(self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        let non_residue = F::from_u64(Self::NON_RESIDUE);
        let t0 = self.c0.square().sub(self.c1.square().mul(non_residue));
        let inv = t0.inverse()?;
        Some(Self {
            c0: self.c0.mul(inv),
            c1: self.c1.neg().mul(inv),
        })
    }

    fn pow(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut acc = Self::ONE;
        while exp != 0 {
            if exp & 1 == 1 {
                acc = acc.mul(base);
            }
            base = base.square();
            exp >>= 1;
        }
        acc
    }

    fn square(self) -> Self {
        self.mul(self)
    }

    fn from_u64(value: u64) -> Self {
        Self {
            c0: F::from_u64(value),
            c1: F::ZERO,
        }
    }

    fn to_u64(self) -> u64 {
        self.c0.to_u64()
    }

    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Self {
            c0: F::random(rng),
            c1: F::random(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::{field::prime_field::GoldilocksField, random::seeded_rng};

    type K = QuadExtension<GoldilocksField>;

    #[test]
    fn inverse_roundtrip() {
        let mut rng = seeded_rng([9u8; 32]);
        let element: K = QuadExtension::random(&mut rng);
        let inv = element.inverse().unwrap();
        assert_eq!(element.mul(inv), K::ONE);
    }

    #[test]
    fn pow_matches_repeated_mul() {
        let mut rng = StdRng::from_seed([3u8; 32]);
        let element: K = QuadExtension::random(&mut rng);
        let mut manual = K::ONE;
        for _ in 0..13 {
            manual = manual.mul(element);
        }
        assert_eq!(element.pow(13), manual);
    }

    // --- from_base ---

    /// `from_base(F::ONE)` must equal `K::ONE`.
    #[test]
    fn from_base_one() {
        assert_eq!(K::from_base(GoldilocksField::ONE), K::ONE);
    }

    /// `from_base(F::ZERO)` must equal `K::ZERO`.
    #[test]
    fn from_base_zero() {
        assert_eq!(K::from_base(GoldilocksField::ZERO), K::ZERO);
    }

    /// Ring-homomorphism: additive.
    #[test]
    fn from_base_ring_hom_add() {
        let mut rng = seeded_rng([11u8; 32]);
        let a = GoldilocksField::random(&mut rng);
        let b = GoldilocksField::random(&mut rng);
        assert_eq!(
            K::from_base(a).add(K::from_base(b)),
            K::from_base(a.add(b)),
            "from_base must be additive"
        );
    }

    /// Ring-homomorphism: multiplicative.
    #[test]
    fn from_base_ring_hom_mul() {
        let mut rng = seeded_rng([13u8; 32]);
        let a = GoldilocksField::random(&mut rng);
        let b = GoldilocksField::random(&mut rng);
        assert_eq!(
            K::from_base(a).mul(K::from_base(b)),
            K::from_base(a.mul(b)),
            "from_base must be multiplicative"
        );
    }

    /// `from_base` sets c1 = 0.
    #[test]
    fn from_base_c1_is_zero() {
        let mut rng = seeded_rng([17u8; 32]);
        let a = GoldilocksField::random(&mut rng);
        let k = K::from_base(a);
        assert_eq!(k.c0, a);
        assert_eq!(k.c1, GoldilocksField::ZERO);
    }

    // --- to_le_bytes / from_le_bytes ---

    /// Round-trip: ZERO.
    #[test]
    fn le_bytes_roundtrip_zero() {
        let x = K::ZERO;
        assert_eq!(K::from_le_bytes(&x.to_le_bytes()), x);
    }

    /// Round-trip: ONE.
    #[test]
    fn le_bytes_roundtrip_one() {
        let x = K::ONE;
        assert_eq!(K::from_le_bytes(&x.to_le_bytes()), x);
    }

    /// Round-trip: element with nonzero c1.
    #[test]
    fn le_bytes_roundtrip_nonzero_c1() {
        let x = K::new(
            GoldilocksField::from_u64(123_456_789),
            GoldilocksField::from_u64(987_654_321),
        );
        assert_eq!(K::from_le_bytes(&x.to_le_bytes()), x);
    }

    /// Round-trip: random elements.
    #[test]
    fn le_bytes_roundtrip_random() {
        let mut rng = seeded_rng([19u8; 32]);
        for _ in 0..32 {
            let x = K::random(&mut rng);
            assert_eq!(K::from_le_bytes(&x.to_le_bytes()), x);
        }
    }

    /// c1-binding: two elements identical in c0 but differing in c1 must
    /// produce different byte encodings.  A c0-only encoding would be a
    /// commitment weakness.
    #[test]
    fn le_bytes_binds_c1() {
        let c0 = GoldilocksField::from_u64(42);
        let x = K::new(c0, GoldilocksField::from_u64(0));
        let y = K::new(c0, GoldilocksField::from_u64(1));
        assert_ne!(
            x.to_le_bytes(),
            y.to_le_bytes(),
            "encoding must differ when c1 differs"
        );
    }

    /// c0-binding: two elements identical in c1 but differing in c0 must
    /// produce different byte encodings.
    #[test]
    fn le_bytes_binds_c0() {
        let c1 = GoldilocksField::from_u64(7);
        let x = K::new(GoldilocksField::from_u64(0), c1);
        let y = K::new(GoldilocksField::from_u64(1), c1);
        assert_ne!(
            x.to_le_bytes(),
            y.to_le_bytes(),
            "encoding must differ when c0 differs"
        );
    }

    /// Equal values encode identically.
    #[test]
    fn le_bytes_equal_values_equal_bytes() {
        let mut rng = seeded_rng([23u8; 32]);
        let x = K::random(&mut rng);
        assert_eq!(x.to_le_bytes(), x.to_le_bytes());
    }

    /// Layout check: the first 8 bytes encode c0, the last 8 encode c1.
    #[test]
    fn le_bytes_layout() {
        let c0_val = 0x0102_0304_0506_0708u64;
        let c1_val = 0xDEAD_BEEF_1234_5678u64;
        let x = K::new(
            GoldilocksField::from_u64(c0_val),
            GoldilocksField::from_u64(c1_val),
        );
        let bytes = x.to_le_bytes();
        let c0_got = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let c1_got = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        assert_eq!(c0_got, c0_val % hc_core_prime_field_modulus(), "c0 layout");
        assert_eq!(c1_got, c1_val % hc_core_prime_field_modulus(), "c1 layout");
    }

    /// Helper: Goldilocks modulus for the layout test.
    fn hc_core_prime_field_modulus() -> u64 {
        use crate::field::GOLDILOCKS_MODULUS;
        GOLDILOCKS_MODULUS
    }
}
