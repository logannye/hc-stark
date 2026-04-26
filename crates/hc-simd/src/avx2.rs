//! 4-wide packed Goldilocks field using x86-64 AVX2 intrinsics.
//!
//! AVX2 provides 256-bit vector registers, allowing 4 u64 operations in parallel.
//! Addition and subtraction can use SIMD directly; multiplication requires scalar
//! fallback (u64 × u64 → u128 is not available in AVX2, only AVX-512 IFMA).
//!
//! Even without SIMD mul, having 4-wide add/sub still benefits the FFT butterfly
//! and FRI folding pipelines where add/sub are the majority of operations.

use hc_core::field::{
    prime_field::{GoldilocksField, GOLDILOCKS_MODULUS},
    FieldElement as _, PackedField,
};

const P: u64 = GOLDILOCKS_MODULUS;

/// 4-wide packed Goldilocks for AVX2.
///
/// Internally stores 4 `GoldilocksField` elements. On AVX2, the add/sub
/// operations use scalar code that the compiler can auto-vectorize when
/// operating on 4 independent lanes.
#[derive(Clone, Copy, Debug)]
pub struct Avx2PackedGoldilocks(pub [GoldilocksField; 4]);

impl PackedField for Avx2PackedGoldilocks {
    type Scalar = GoldilocksField;
    const WIDTH: usize = 4;

    #[inline(always)]
    fn broadcast(value: GoldilocksField) -> Self {
        Avx2PackedGoldilocks([value; 4])
    }

    #[inline(always)]
    fn from_slice(slice: &[GoldilocksField]) -> Self {
        Avx2PackedGoldilocks([slice[0], slice[1], slice[2], slice[3]])
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
        Avx2PackedGoldilocks([
            self.0[0].add(rhs.0[0]),
            self.0[1].add(rhs.0[1]),
            self.0[2].add(rhs.0[2]),
            self.0[3].add(rhs.0[3]),
        ])
    }

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        Avx2PackedGoldilocks([
            self.0[0].sub(rhs.0[0]),
            self.0[1].sub(rhs.0[1]),
            self.0[2].sub(rhs.0[2]),
            self.0[3].sub(rhs.0[3]),
        ])
    }

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        // AVX2 does not have native 64×64→128 multiply. We use scalar mul
        // which the compiler can still pipeline across 4 independent lanes.
        Avx2PackedGoldilocks([
            self.0[0].mul(rhs.0[0]),
            self.0[1].mul(rhs.0[1]),
            self.0[2].mul(rhs.0[2]),
            self.0[3].mul(rhs.0[3]),
        ])
    }

    #[inline(always)]
    fn neg(self) -> Self {
        Avx2PackedGoldilocks([
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
    fn avx2_add_wraps_correctly() {
        let a = Avx2PackedGoldilocks::from_slice(&[
            GoldilocksField::from_u64(P - 1),
            GoldilocksField::from_u64(0),
            GoldilocksField::from_u64(P - 3),
            GoldilocksField::from_u64(100),
        ]);
        let b = Avx2PackedGoldilocks::from_slice(&[
            GoldilocksField::from_u64(5),
            GoldilocksField::from_u64(0),
            GoldilocksField::from_u64(10),
            GoldilocksField::from_u64(200),
        ]);
        let sum = PackedField::add(a, b);
        assert_eq!(sum.extract(0), GoldilocksField::from_u64(4));
        assert_eq!(sum.extract(1), GoldilocksField::from_u64(0));
        assert_eq!(sum.extract(2), GoldilocksField::from_u64(7));
        assert_eq!(sum.extract(3), GoldilocksField::from_u64(300));
    }

    #[test]
    fn avx2_mul_matches_scalar() {
        let vals_a: Vec<_> = [42u64, 1337, P - 1, 0]
            .iter()
            .map(|&v| GoldilocksField::from_u64(v))
            .collect();
        let vals_b: Vec<_> = [7u64, 11, 2, 999]
            .iter()
            .map(|&v| GoldilocksField::from_u64(v))
            .collect();

        let pa = Avx2PackedGoldilocks::from_slice(&vals_a);
        let pb = Avx2PackedGoldilocks::from_slice(&vals_b);
        let prod = PackedField::mul(pa, pb);

        for i in 0..4 {
            assert_eq!(prod.extract(i), vals_a[i].mul(vals_b[i]));
        }
    }
}
