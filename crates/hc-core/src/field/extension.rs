//! Lightweight quadratic extension field implementation.

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

    #[test]
    fn inverse_roundtrip() {
        let mut rng = seeded_rng([9u8; 32]);
        let element: QuadExtension<GoldilocksField> = QuadExtension::random(&mut rng);
        let inv = element.inverse().unwrap();
        assert_eq!(element.mul(inv), QuadExtension::ONE);
    }

    #[test]
    fn pow_matches_repeated_mul() {
        let mut rng = StdRng::from_seed([3u8; 32]);
        let element: QuadExtension<GoldilocksField> = QuadExtension::random(&mut rng);
        let mut manual = QuadExtension::ONE;
        for _ in 0..13 {
            manual = manual.mul(element);
        }
        assert_eq!(element.pow(13), manual);
    }
}
