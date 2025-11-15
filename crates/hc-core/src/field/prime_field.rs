//! Implementation of the 64-bit Goldilocks prime field.

use core::fmt;

use rand::Rng;

use super::{FieldElement, TwoAdicField};

/// Prime modulus `p = 2^64 - 2^32 + 1`.
pub const GOLDILOCKS_MODULUS: u64 = 0xFFFFFFFF00000001;
const MODULUS_U128: u128 = GOLDILOCKS_MODULUS as u128;
const MODULUS_MINUS_TWO: u64 = GOLDILOCKS_MODULUS - 2;

/// Canonical generator for the multiplicative subgroup of size `2^32`.
pub const GOLDILOCKS_PRIMITIVE_ROOT: u64 = 7;
/// Two-adicity of the Goldilocks field (`2^32 | p-1`).
pub const GOLDILOCKS_TWO_ADICITY: u32 = 32;

/// Field element in the Goldilocks prime field.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct GoldilocksField(pub u64);

impl GoldilocksField {
    /// Returns a new field element reduced modulo the prime.
    pub const fn new(value: u64) -> Self {
        Self(value % GOLDILOCKS_MODULUS)
    }

    #[inline]
    fn montgomery_reduce(value: u128) -> u64 {
        (value % MODULUS_U128) as u64
    }
}

impl fmt::Debug for GoldilocksField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GoldilocksField({})", self.0)
    }
}

impl FieldElement for GoldilocksField {
    const ZERO: Self = GoldilocksField(0);
    const ONE: Self = GoldilocksField(1);

    fn add(self, rhs: Self) -> Self {
        let (value, carry) = self.0.overflowing_add(rhs.0);
        let value = if carry || value >= GOLDILOCKS_MODULUS {
            value.wrapping_sub(GOLDILOCKS_MODULUS)
        } else {
            value
        };
        GoldilocksField(value)
    }

    fn sub(self, rhs: Self) -> Self {
        let (value, borrow) = self.0.overflowing_sub(rhs.0);
        if borrow {
            GoldilocksField(value.wrapping_add(GOLDILOCKS_MODULUS))
        } else {
            GoldilocksField(value)
        }
    }

    fn neg(self) -> Self {
        if self.0 == 0 {
            self
        } else {
            GoldilocksField(GOLDILOCKS_MODULUS - self.0)
        }
    }

    fn mul(self, rhs: Self) -> Self {
        GoldilocksField(Self::montgomery_reduce(self.0 as u128 * rhs.0 as u128))
    }

    fn inverse(self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            Some(self.pow(MODULUS_MINUS_TWO))
        }
    }

    fn pow(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut acc = Self::ONE;
        while exp != 0 {
            if exp & 1 == 1 {
                acc = acc.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        acc
    }

    fn square(self) -> Self {
        self.mul(self)
    }

    fn from_u64(value: u64) -> Self {
        GoldilocksField::new(value)
    }

    fn to_u64(self) -> u64 {
        self.0
    }

    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        loop {
            let value: u64 = rng.gen();
            if value < GOLDILOCKS_MODULUS {
                return GoldilocksField(value);
            }
        }
    }

    fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::Add for GoldilocksField {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        FieldElement::add(self, rhs)
    }
}

impl core::ops::Sub for GoldilocksField {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        FieldElement::sub(self, rhs)
    }
}

impl core::ops::Mul for GoldilocksField {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        FieldElement::mul(self, rhs)
    }
}

impl core::ops::Neg for GoldilocksField {
    type Output = Self;
    fn neg(self) -> Self::Output {
        FieldElement::neg(self)
    }
}

impl TwoAdicField for GoldilocksField {
    const TWO_ADICITY: u32 = GOLDILOCKS_TWO_ADICITY;

    fn primitive_root_of_unity() -> Self {
        let generator = GoldilocksField::new(GOLDILOCKS_PRIMITIVE_ROOT);
        generator.pow((GOLDILOCKS_MODULUS - 1) >> Self::TWO_ADICITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addition_wraps_correctly() {
        let a = GoldilocksField::new(GOLDILOCKS_MODULUS - 1);
        let b = GoldilocksField::new(2);
        assert_eq!(a.add(b).0, 1);
    }

    #[test]
    fn multiplication_matches_naive() {
        let a = GoldilocksField::new(123456789);
        let b = GoldilocksField::new(987654321);
        let expected = ((a.0 as u128 * b.0 as u128) % MODULUS_U128) as u64;
        assert_eq!(a.mul(b).0, expected);
    }

    #[test]
    fn inversion_roundtrip() {
        let element = GoldilocksField::new(42);
        let inv = element.inverse().unwrap();
        assert_eq!(element.mul(inv), GoldilocksField::ONE);
    }
}
