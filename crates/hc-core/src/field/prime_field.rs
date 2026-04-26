//! Implementation of the 64-bit Goldilocks prime field.

use core::fmt;

use rand::Rng;

use super::{FieldElement, TwoAdicField};

/// Prime modulus `p = 2^64 - 2^32 + 1`.
pub const GOLDILOCKS_MODULUS: u64 = 0xFFFFFFFF00000001;
/// 128-bit form of the modulus. Only the test oracle uses it now (fast
/// reduction lives entirely in u64 register-wide arithmetic). Kept
/// available as a documented constant; gated to test builds to silence
/// dead_code under `clippy -D warnings`.
#[cfg(test)]
const MODULUS_U128: u128 = GOLDILOCKS_MODULUS as u128;
const MODULUS_MINUS_TWO: u64 = GOLDILOCKS_MODULUS - 2;
/// `EPSILON = 2^32 - 1 = p mod 2^64`. Equivalent to `2^64 mod p`. Used as
/// the wrap-around correction in the fast reduction.
const EPSILON: u64 = 0xFFFF_FFFF;

/// Canonical generator for the multiplicative subgroup of size `2^32`.
pub const GOLDILOCKS_PRIMITIVE_ROOT: u64 = 7;
/// Two-adicity of the Goldilocks field (`2^32 | p-1`).
pub const GOLDILOCKS_TWO_ADICITY: u32 = 32;

/// Convert a boolean condition into a constant-time mask.
///
/// Returns `u64::MAX` (all 1s) if `condition` is true, `0` if false.
/// The compiler is encouraged *not* to branch on the result.
#[inline(always)]
fn ct_mask(condition: bool) -> u64 {
    // Negate via wrapping arithmetic: 0u64.wrapping_sub(b) where b is 0 or 1.
    0u64.wrapping_sub(condition as u64)
}

/// Field element in the Goldilocks prime field.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct GoldilocksField(pub u64);

impl GoldilocksField {
    /// Returns a new field element reduced modulo the prime.
    pub const fn new(value: u64) -> Self {
        Self(value % GOLDILOCKS_MODULUS)
    }

    /// Reduce a 128-bit product modulo `p = 2^64 - 2^32 + 1`.
    ///
    /// Replaces the previous `value % MODULUS_U128` body, which compiled to
    /// a 128-bit hardware divide on every multiplication. The structure of
    /// the Goldilocks prime admits a much faster algorithm:
    ///
    /// Decompose `t = lo + (mid << 64) + (hi << 96)` where `mid, hi < 2^32`.
    /// Using the identities
    ///     2^64 ≡ 2^32 - 1   (mod p)   (i.e. EPSILON)
    ///     2^96 ≡ -1         (mod p)
    /// we get
    ///     t ≡ lo + (2^32 - 1) * mid - hi   (mod p)
    ///       = lo + (mid << 32) - mid - hi
    ///
    /// We compute this in two reductions, each shaving roughly 32 bits and
    /// using EPSILON = 2^32 - 1 as the carry/borrow correction (since
    /// 2^64 ≡ EPSILON mod p, every wrap of the u64 register is offset by
    /// adding/subtracting EPSILON).
    ///
    /// The algorithm is constant-time in the same sense as the rest of this
    /// file: the conditional adjustments use simple arithmetic predicates
    /// rather than data-dependent branches that could affect the optimized
    /// codegen on common targets. (Strict CT guarantees would require
    /// `subtle::ConstantTimeEq` or similar; we match the existing add/sub
    /// style.)
    ///
    /// Note: the function is still named `montgomery_reduce` for now to
    /// avoid breaking any external callers; the name is a misnomer kept
    /// for source compatibility. The body is plain Goldilocks fast
    /// reduction, not Montgomery form. See follow-up task for renaming.
    #[inline(always)]
    fn montgomery_reduce(t: u128) -> u64 {
        let lo = t as u64; // bits 0..64 of t
        let hi_word = (t >> 64) as u64; // bits 64..128
        let hi = hi_word >> 32; // bits 96..128 of t, in [0, 2^32)
        let mid = hi_word & EPSILON; // bits 64..96 of t, in [0, 2^32)

        // Step 1: t1 ≡ lo - hi (mod p).
        // If `lo < hi` we underflow the u64; the wrapped value represents
        // `lo - hi + 2^64`. Subtracting EPSILON = 2^32 - 1 corrects:
        // (lo - hi + 2^64) ≡ (lo - hi + EPSILON) (mod p), so we want to
        // subtract EPSILON from the wrapped value to land in the right
        // residue class.
        let (t1, borrow) = lo.overflowing_sub(hi);
        let t1 = if borrow { t1.wrapping_sub(EPSILON) } else { t1 };

        // Step 2: t2 ≡ t1 + mid * (2^32 - 1) (mod p).
        // mid * EPSILON = (mid << 32) - mid; since mid < 2^32, this fits
        // in u64 with no overflow.
        let mid_term = (mid << 32).wrapping_sub(mid);
        let (t2, carry) = t1.overflowing_add(mid_term);
        // If carry: the true sum is t2 + 2^64 ≡ t2 + EPSILON (mod p).
        let t2 = if carry { t2.wrapping_add(EPSILON) } else { t2 };

        // Final canonical reduction: t2 may still be in [p, 2p).
        let reduced = t2.wrapping_sub(GOLDILOCKS_MODULUS);
        if t2 >= GOLDILOCKS_MODULUS { reduced } else { t2 }
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
        // Constant-time: compute the reduced value unconditionally, then
        // select it when carry is set or when the unreduced sum >= MODULUS.
        let (value, carry) = self.0.overflowing_add(rhs.0);
        let reduced = value.wrapping_sub(GOLDILOCKS_MODULUS);
        // `carry` means the 64-bit addition overflowed, so the true sum is
        // >= 2^64 > MODULUS and `reduced` is the correct canonical result.
        // If `value >= MODULUS` (no carry), `reduced` also gives the right
        // answer and `reduced < MODULUS` (no underflow).  We detect the case
        // where subtraction underflows (value < MODULUS, no carry) via the
        // borrow bit.
        let (_, borrow) = value.overflowing_sub(GOLDILOCKS_MODULUS);
        // Select: if carry is set OR borrow is clear, use `reduced`.
        // `need_reduce = carry || !borrow`, mask = 0 if we keep value, !0 if
        // we use reduced.
        let need_reduce = carry | (!borrow);
        let mask = ct_mask(need_reduce);
        // result = (reduced & mask) | (value & !mask)
        GoldilocksField((reduced & mask) | (value & !mask))
    }

    fn sub(self, rhs: Self) -> Self {
        // Constant-time: always compute both branches, select via mask.
        let (value, borrow) = self.0.overflowing_sub(rhs.0);
        let adjusted = value.wrapping_add(GOLDILOCKS_MODULUS);
        let mask = ct_mask(borrow);
        GoldilocksField((adjusted & mask) | (value & !mask))
    }

    fn neg(self) -> Self {
        // Constant-time: compute (MODULUS - self) then mask to zero if self
        // is zero.  `MODULUS - 0 = MODULUS` which is non-canonical, so we
        // need to zero it out.
        let result = GOLDILOCKS_MODULUS.wrapping_sub(self.0);
        let is_nonzero = ct_mask(self.0 != 0);
        GoldilocksField(result & is_nonzero)
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

    fn pow_ct(self, exp: u64) -> Self {
        // Montgomery ladder: constant-time exponentiation.
        // Always performs two multiplications per bit regardless of the
        // bit value, preventing side-channel leakage.
        let mut r0 = Self::ONE;
        let mut r1 = self;
        for i in (0..64).rev() {
            let bit = (exp >> i) & 1;
            let mask = ct_mask(bit == 1);
            // If bit == 1: r0 = r0 * r1, r1 = r1^2
            // If bit == 0: r1 = r0 * r1, r0 = r0^2
            let product = r0.mul(r1);
            let r0_sq = r0.mul(r0);
            let r1_sq = r1.mul(r1);
            // Constant-time select:
            // bit=1 → r0 = product, r1 = r1_sq
            // bit=0 → r0 = r0_sq,   r1 = product
            r0 = Self((product.0 & mask) | (r0_sq.0 & !mask));
            r1 = Self((r1_sq.0 & mask) | (product.0 & !mask));
        }
        r0
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

    #[test]
    fn pow_ct_matches_pow() {
        let base = GoldilocksField::new(7);
        for exp in [0, 1, 2, 3, 10, 31, 63, 100, 255, 1023, MODULUS_MINUS_TWO] {
            assert_eq!(
                base.pow(exp),
                base.pow_ct(exp),
                "pow vs pow_ct mismatch for exp={exp}"
            );
        }
    }

    #[test]
    fn constant_time_add_sub_roundtrip() {
        // Verify add/sub roundtrip across modular boundary.
        let a = GoldilocksField::new(GOLDILOCKS_MODULUS - 1);
        let b = GoldilocksField::new(GOLDILOCKS_MODULUS - 1);
        let sum = a.add(b);
        let diff = sum.sub(a);
        assert_eq!(diff, b);
    }

    #[test]
    fn constant_time_neg_zero() {
        let zero = GoldilocksField::ZERO;
        assert_eq!(zero.neg(), zero);
    }

    #[test]
    fn constant_time_neg_nonzero() {
        let a = GoldilocksField::new(42);
        let neg_a = a.neg();
        assert_eq!(a.add(neg_a), GoldilocksField::ZERO);
    }

    /// Reference implementation of u128 reduction modulo Goldilocks p.
    /// Slow but provably correct — the standard library `%` operator on u128.
    /// Used as the oracle for property testing the fast reduction path.
    fn reduce_oracle(t: u128) -> u64 {
        (t % MODULUS_U128) as u64
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 4096,  // ~4k random u128 values per property
            ..Default::default()
        })]

        /// The internal reduction routine called from `mul` must agree with
        /// the slow oracle on all 128-bit inputs. This is the primary
        /// soundness gate: any divergence is a silent miscalculation that
        /// would corrupt every downstream prover/verifier output.
        #[test]
        fn reduction_matches_oracle(t in proptest::prelude::any::<u128>()) {
            let fast = GoldilocksField::montgomery_reduce(t);
            let slow = reduce_oracle(t);
            proptest::prop_assert_eq!(fast, slow, "reduction mismatch on input {}", t);
        }

        /// Multiplication on canonical inputs must agree with naive (a*b)%p.
        #[test]
        fn mul_matches_naive(
            a in 0u64..GOLDILOCKS_MODULUS,
            b in 0u64..GOLDILOCKS_MODULUS,
        ) {
            let af = GoldilocksField(a);
            let bf = GoldilocksField(b);
            let got = af.mul(bf).0;
            let want = ((a as u128 * b as u128) % MODULUS_U128) as u64;
            proptest::prop_assert_eq!(got, want);
        }

        /// Boundary inputs: max canonical value, modulus-adjacent operands,
        /// and any operand vs zero/one.
        #[test]
        fn mul_boundary_invariants(a in 0u64..GOLDILOCKS_MODULUS) {
            let af = GoldilocksField(a);
            // a * 0 = 0
            proptest::prop_assert_eq!(af.mul(GoldilocksField::ZERO).0, 0);
            // a * 1 = a
            proptest::prop_assert_eq!(af.mul(GoldilocksField::ONE).0, a);
            // a * (p-1) ≡ -a (mod p)
            let p_minus_1 = GoldilocksField(GOLDILOCKS_MODULUS - 1);
            let prod = af.mul(p_minus_1).0;
            let neg_a = if a == 0 { 0 } else { GOLDILOCKS_MODULUS - a };
            proptest::prop_assert_eq!(prod, neg_a);
        }

        /// Multiplication is commutative and associative on canonical inputs.
        #[test]
        fn mul_algebra(
            a in 0u64..GOLDILOCKS_MODULUS,
            b in 0u64..GOLDILOCKS_MODULUS,
            c in 0u64..GOLDILOCKS_MODULUS,
        ) {
            let af = GoldilocksField(a);
            let bf = GoldilocksField(b);
            let cf = GoldilocksField(c);
            // commutative
            proptest::prop_assert_eq!(af.mul(bf), bf.mul(af));
            // associative
            proptest::prop_assert_eq!(af.mul(bf).mul(cf), af.mul(bf.mul(cf)));
            // distributive
            proptest::prop_assert_eq!(
                af.mul(bf.add(cf)),
                af.mul(bf).add(af.mul(cf)),
            );
        }
    }

    /// Quick microbenchmark for the reduction inner loop. Not run by
    /// default; invoke explicitly:
    ///     cargo test -p hc-core --release \
    ///       field::prime_field::tests::bench_mul -- --ignored --nocapture
    /// Compares fast reduction (current `mul`) vs the slow `% MODULUS_U128`
    /// oracle. Reports throughput in mul/sec for both.
    #[test]
    #[ignore]
    fn bench_mul() {
        use std::time::Instant;
        const N: usize = 50_000_000;

        // Build a mildly random input pair. Same inputs for both runs.
        let inputs: Vec<(u64, u64)> = (0..N)
            .map(|i| {
                let a = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                let b = ((i as u64) ^ 0xDEAD_BEEF).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                (a % GOLDILOCKS_MODULUS, b % GOLDILOCKS_MODULUS)
            })
            .collect();

        // Fast path (current implementation).
        let t0 = Instant::now();
        let mut acc_fast: u64 = 0;
        for &(a, b) in &inputs {
            let r = GoldilocksField::montgomery_reduce(a as u128 * b as u128);
            acc_fast ^= r;
        }
        let dt_fast = t0.elapsed();

        // Slow oracle.
        let t0 = Instant::now();
        let mut acc_slow: u64 = 0;
        for &(a, b) in &inputs {
            let r = ((a as u128 * b as u128) % MODULUS_U128) as u64;
            acc_slow ^= r;
        }
        let dt_slow = t0.elapsed();

        // Equivalence check (acc_fast must equal acc_slow if the algorithms
        // agree on every reduction).
        assert_eq!(acc_fast, acc_slow);

        let mps_fast = N as f64 / dt_fast.as_secs_f64() / 1e6;
        let mps_slow = N as f64 / dt_slow.as_secs_f64() / 1e6;
        println!(
            "goldilocks reduce x{N}: fast={:.2}ms ({:.1} M/s), slow={:.2}ms ({:.1} M/s), speedup={:.2}x",
            dt_fast.as_secs_f64() * 1000.0,
            mps_fast,
            dt_slow.as_secs_f64() * 1000.0,
            mps_slow,
            mps_fast / mps_slow,
        );
    }

    /// Fixed-input tests at known boundary cases — explicit so a regression
    /// names the failing input rather than printing a random seed.
    #[test]
    fn reduction_boundary_cases() {
        let cases: &[u128] = &[
            0,
            1,
            MODULUS_U128 - 1,
            MODULUS_U128,
            MODULUS_U128 + 1,
            (MODULUS_U128 - 1) * (MODULUS_U128 - 1),  // (p-1)^2
            u128::MAX,
            u128::MAX - 1,
            (1u128 << 64) - 1,
            (1u128 << 64),
            (1u128 << 96) - 1,
            (1u128 << 96),
            (1u128 << 127),
        ];
        for &t in cases {
            let fast = GoldilocksField::montgomery_reduce(t);
            let slow = (t % MODULUS_U128) as u64;
            assert_eq!(fast, slow, "reduction mismatch on boundary {t:#x}");
        }
    }
}
