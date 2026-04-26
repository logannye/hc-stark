//! Portable 4-wide "packed" Goldilocks using plain scalar operations.
//!
//! This is the fallback when neither AVX2 nor NEON features are enabled. It
//! provides the same `PackedField` API so that generic code compiles on all
//! platforms. The compiler may still auto-vectorize some of these loops.

use hc_core::field::{prime_field::GoldilocksField, FieldElement as _, PackedField};

#[derive(Clone, Copy, Debug)]
pub struct Scalar4Goldilocks(pub [GoldilocksField; 4]);

impl PackedField for Scalar4Goldilocks {
    type Scalar = GoldilocksField;
    const WIDTH: usize = 4;

    #[inline(always)]
    fn broadcast(value: GoldilocksField) -> Self {
        Scalar4Goldilocks([value; 4])
    }

    #[inline(always)]
    fn from_slice(slice: &[GoldilocksField]) -> Self {
        Scalar4Goldilocks([slice[0], slice[1], slice[2], slice[3]])
    }

    #[inline(always)]
    fn to_slice(self, slice: &mut [GoldilocksField]) {
        slice[0] = self.0[0];
        slice[1] = self.0[1];
        slice[2] = self.0[2];
        slice[3] = self.0[3];
    }

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Scalar4Goldilocks([
            self.0[0].add(rhs.0[0]),
            self.0[1].add(rhs.0[1]),
            self.0[2].add(rhs.0[2]),
            self.0[3].add(rhs.0[3]),
        ])
    }

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        Scalar4Goldilocks([
            self.0[0].sub(rhs.0[0]),
            self.0[1].sub(rhs.0[1]),
            self.0[2].sub(rhs.0[2]),
            self.0[3].sub(rhs.0[3]),
        ])
    }

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        Scalar4Goldilocks([
            self.0[0].mul(rhs.0[0]),
            self.0[1].mul(rhs.0[1]),
            self.0[2].mul(rhs.0[2]),
            self.0[3].mul(rhs.0[3]),
        ])
    }

    #[inline(always)]
    fn neg(self) -> Self {
        Scalar4Goldilocks([
            self.0[0].neg(),
            self.0[1].neg(),
            self.0[2].neg(),
            self.0[3].neg(),
        ])
    }

    #[inline(always)]
    fn extract(self, index: usize) -> GoldilocksField {
        self.0[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::FieldElement;

    #[test]
    fn broadcast_sets_all_lanes() {
        let v = Scalar4Goldilocks::broadcast(GoldilocksField::from_u64(42));
        for i in 0..4 {
            assert_eq!(v.extract(i), GoldilocksField::from_u64(42));
        }
    }

    #[test]
    fn add_mul_correctness() {
        let a = Scalar4Goldilocks::from_slice(&[
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(4),
        ]);
        let b = Scalar4Goldilocks::from_slice(&[
            GoldilocksField::from_u64(10),
            GoldilocksField::from_u64(20),
            GoldilocksField::from_u64(30),
            GoldilocksField::from_u64(40),
        ]);

        let sum = PackedField::add(a, b);
        assert_eq!(sum.extract(0), GoldilocksField::from_u64(11));
        assert_eq!(sum.extract(1), GoldilocksField::from_u64(22));
        assert_eq!(sum.extract(2), GoldilocksField::from_u64(33));
        assert_eq!(sum.extract(3), GoldilocksField::from_u64(44));

        let prod = PackedField::mul(a, b);
        assert_eq!(prod.extract(0), GoldilocksField::from_u64(10));
        assert_eq!(prod.extract(1), GoldilocksField::from_u64(40));
        assert_eq!(prod.extract(2), GoldilocksField::from_u64(90));
        assert_eq!(prod.extract(3), GoldilocksField::from_u64(160));
    }

    #[test]
    fn roundtrip_through_slice() {
        let original = [
            GoldilocksField::from_u64(100),
            GoldilocksField::from_u64(200),
            GoldilocksField::from_u64(300),
            GoldilocksField::from_u64(400),
        ];
        let packed = Scalar4Goldilocks::from_slice(&original);
        let mut out = [GoldilocksField::ZERO; 4];
        packed.to_slice(&mut out);
        assert_eq!(original, out);
    }
}
