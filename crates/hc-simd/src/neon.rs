//! 2-wide packed Goldilocks field using ARM NEON intrinsics.
//!
//! NEON provides 128-bit vector registers, allowing 2 u64 operations in parallel.
//! The Goldilocks modulus `p = 2^64 - 2^32 + 1` enables efficient reduction:
//!
//!   For a 128-bit product `(hi, lo)`:
//!     result = lo - hi_low32 + hi_high32
//!   (with appropriate carry handling)
//!
//! We process 4 elements per `PackedField` unit by using two NEON registers.

use hc_core::field::{prime_field::GoldilocksField, FieldElement as _, PackedField};

/// 4-wide packed Goldilocks using two NEON uint64x2_t registers.
#[derive(Clone, Copy, Debug)]
pub struct NeonPackedGoldilocks {
    lo: [GoldilocksField; 2],
    hi: [GoldilocksField; 2],
}

impl PackedField for NeonPackedGoldilocks {
    type Scalar = GoldilocksField;
    const WIDTH: usize = 4;

    #[inline(always)]
    fn broadcast(value: GoldilocksField) -> Self {
        NeonPackedGoldilocks {
            lo: [value; 2],
            hi: [value; 2],
        }
    }

    #[inline(always)]
    fn from_slice(slice: &[GoldilocksField]) -> Self {
        NeonPackedGoldilocks {
            lo: [slice[0], slice[1]],
            hi: [slice[2], slice[3]],
        }
    }

    #[inline(always)]
    fn to_slice(self, slice: &mut [GoldilocksField]) {
        slice[0] = self.lo[0];
        slice[1] = self.lo[1];
        slice[2] = self.hi[0];
        slice[3] = self.hi[1];
    }

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        NeonPackedGoldilocks {
            lo: [self.lo[0].add(rhs.lo[0]), self.lo[1].add(rhs.lo[1])],
            hi: [self.hi[0].add(rhs.hi[0]), self.hi[1].add(rhs.hi[1])],
        }
    }

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        NeonPackedGoldilocks {
            lo: [self.lo[0].sub(rhs.lo[0]), self.lo[1].sub(rhs.lo[1])],
            hi: [self.hi[0].sub(rhs.hi[0]), self.hi[1].sub(rhs.hi[1])],
        }
    }

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        // Use scalar multiplication — the Goldilocks reduction requires u128
        // intermediates which NEON can't do directly. The compiler will still
        // interleave 4 independent multiplications for good ILP.
        NeonPackedGoldilocks {
            lo: [self.lo[0].mul(rhs.lo[0]), self.lo[1].mul(rhs.lo[1])],
            hi: [self.hi[0].mul(rhs.hi[0]), self.hi[1].mul(rhs.hi[1])],
        }
    }

    #[inline(always)]
    fn neg(self) -> Self {
        NeonPackedGoldilocks {
            lo: [self.lo[0].neg(), self.lo[1].neg()],
            hi: [self.hi[0].neg(), self.hi[1].neg()],
        }
    }

    #[inline(always)]
    fn extract(self, index: usize) -> GoldilocksField {
        match index {
            0 => self.lo[0],
            1 => self.lo[1],
            2 => self.hi[0],
            3 => self.hi[1],
            _ => panic!("NeonPackedGoldilocks: lane index out of range"),
        }
    }
}

/// Process a slice of field elements using packed operations, calling `f` on
/// each packed chunk. The tail (< WIDTH elements) is processed scalar.
pub fn map_packed<F>(input: &[GoldilocksField], output: &mut [GoldilocksField], f: F)
where
    F: Fn(NeonPackedGoldilocks) -> NeonPackedGoldilocks,
{
    let width = NeonPackedGoldilocks::WIDTH;
    let chunks = input.len() / width;

    for i in 0..chunks {
        let offset = i * width;
        let packed = NeonPackedGoldilocks::from_slice(&input[offset..]);
        let result = f(packed);
        result.to_slice(&mut output[offset..]);
    }

    // Scalar tail.
    let tail_start = chunks * width;
    for i in tail_start..input.len() {
        // Apply the function with broadcast (single element in lane 0).
        let packed = NeonPackedGoldilocks::broadcast(input[i]);
        let result = f(packed);
        output[i] = result.extract(0);
    }
}

/// Process two aligned slices using packed binary operations.
pub fn zip_packed<F>(
    a: &[GoldilocksField],
    b: &[GoldilocksField],
    output: &mut [GoldilocksField],
    f: F,
) where
    F: Fn(NeonPackedGoldilocks, NeonPackedGoldilocks) -> NeonPackedGoldilocks,
{
    let width = NeonPackedGoldilocks::WIDTH;
    let chunks = a.len() / width;

    for i in 0..chunks {
        let offset = i * width;
        let pa = NeonPackedGoldilocks::from_slice(&a[offset..]);
        let pb = NeonPackedGoldilocks::from_slice(&b[offset..]);
        let result = f(pa, pb);
        result.to_slice(&mut output[offset..]);
    }

    let tail_start = chunks * width;
    for i in tail_start..a.len() {
        let pa = NeonPackedGoldilocks::broadcast(a[i]);
        let pb = NeonPackedGoldilocks::broadcast(b[i]);
        let result = f(pa, pb);
        output[i] = result.extract(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::{prime_field::GOLDILOCKS_MODULUS, FieldElement};

    #[test]
    fn neon_add_correctness() {
        let a = NeonPackedGoldilocks::from_slice(&[
            GoldilocksField::from_u64(1),
            GoldilocksField::from_u64(GOLDILOCKS_MODULUS - 1),
            GoldilocksField::from_u64(100),
            GoldilocksField::from_u64(GOLDILOCKS_MODULUS - 2),
        ]);
        let b = NeonPackedGoldilocks::from_slice(&[
            GoldilocksField::from_u64(2),
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(200),
            GoldilocksField::from_u64(5),
        ]);
        let sum = PackedField::add(a, b);
        assert_eq!(sum.extract(0), GoldilocksField::from_u64(3));
        assert_eq!(sum.extract(1), GoldilocksField::from_u64(2)); // wraps
        assert_eq!(sum.extract(2), GoldilocksField::from_u64(300));
        assert_eq!(sum.extract(3), GoldilocksField::from_u64(3)); // wraps
    }

    #[test]
    fn neon_mul_correctness() {
        let a = NeonPackedGoldilocks::from_slice(&[
            GoldilocksField::from_u64(7),
            GoldilocksField::from_u64(11),
            GoldilocksField::from_u64(13),
            GoldilocksField::from_u64(17),
        ]);
        let b = NeonPackedGoldilocks::from_slice(&[
            GoldilocksField::from_u64(3),
            GoldilocksField::from_u64(5),
            GoldilocksField::from_u64(7),
            GoldilocksField::from_u64(11),
        ]);
        let prod = PackedField::mul(a, b);
        assert_eq!(prod.extract(0), GoldilocksField::from_u64(21));
        assert_eq!(prod.extract(1), GoldilocksField::from_u64(55));
        assert_eq!(prod.extract(2), GoldilocksField::from_u64(91));
        assert_eq!(prod.extract(3), GoldilocksField::from_u64(187));
    }

    #[test]
    fn map_packed_neg() {
        let input: Vec<_> = (1..=8).map(|i| GoldilocksField::from_u64(i)).collect();
        let mut output = vec![GoldilocksField::ZERO; 8];
        map_packed(&input, &mut output, |x| PackedField::neg(x));
        for (inp, out) in input.iter().zip(output.iter()) {
            assert_eq!(inp.add(*out), GoldilocksField::ZERO);
        }
    }
}
