pub mod batch_ops;
pub mod extension;
pub mod prime_field;

pub use batch_ops::{
    add_assign_slices, add_slices, batch_inverse, batch_inverse_nonzero, butterfly,
    butterfly_slice, dot_product, linear_combination, mul_assign_slices, mul_slices, scale_slice,
    sub_assign_slices, sub_slices,
};
pub use extension::QuadExtension;
pub use prime_field::{
    GoldilocksField, GOLDILOCKS_MODULUS, GOLDILOCKS_PRIMITIVE_ROOT, GOLDILOCKS_TWO_ADICITY,
};

use rand::Rng;

/// Core trait implemented by every field element in the workspace.
pub trait FieldElement:
    Copy + Clone + Send + Sync + core::fmt::Debug + PartialEq + Eq + 'static
{
    /// Additive identity.
    const ZERO: Self;
    /// Multiplicative identity.
    const ONE: Self;

    /// Returns true if the element equals zero.
    fn is_zero(self) -> bool;
    /// Addition.
    fn add(self, rhs: Self) -> Self;
    /// Subtraction.
    fn sub(self, rhs: Self) -> Self;
    /// Multiplication.
    fn mul(self, rhs: Self) -> Self;
    /// Negation.
    fn neg(self) -> Self;
    /// Squaring (optional override for speed).
    fn square(self) -> Self {
        self.mul(self)
    }
    /// Multiplicative inverse, if it exists.
    fn inverse(self) -> Option<Self>;
    /// Exponentiation by square-and-multiply.
    fn pow(self, exp: u64) -> Self;

    /// Constant-time exponentiation via the Montgomery ladder.
    ///
    /// Always performs the same number of multiplications regardless of the
    /// exponent bit pattern, preventing timing side-channel leakage.
    /// Defaults to the variable-time `pow` unless the implementation overrides.
    fn pow_ct(self, exp: u64) -> Self {
        self.pow(exp)
    }

    /// Construct from a canonical `u64`.
    fn from_u64(value: u64) -> Self;
    /// Convert into its canonical `u64` representative.
    fn to_u64(self) -> u64;
    /// Sample a random element.
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self;
}

/// Fields that contain a large two-adic subgroup (powers of two roots of unity).
pub trait TwoAdicField: FieldElement {
    /// Max `k` such that `2^k | p-1`.
    const TWO_ADICITY: u32;
    /// Canonical generator of the two-adic subgroup.
    fn primitive_root_of_unity() -> Self;
}

/// A packed representation of `WIDTH` field elements that can be operated on
/// simultaneously using SIMD instructions.
///
/// Implementations are expected to use platform-specific SIMD intrinsics
/// (AVX2, NEON, etc.) behind the scenes. The scalar fallback wraps individual
/// elements in an array and processes them sequentially.
pub trait PackedField: Copy + Clone + Send + Sync + 'static {
    /// The scalar field element type.
    type Scalar: FieldElement;

    /// Number of elements packed in a single value (e.g. 4 for AVX2 u64s).
    const WIDTH: usize;

    /// Broadcast a single scalar to all lanes.
    fn broadcast(value: Self::Scalar) -> Self;

    /// Load `WIDTH` consecutive elements from a slice. The slice must have at
    /// least `WIDTH` elements.
    fn from_slice(slice: &[Self::Scalar]) -> Self;

    /// Store `WIDTH` elements into a mutable slice.
    fn to_slice(self, slice: &mut [Self::Scalar]);

    /// Element-wise addition.
    fn add(self, rhs: Self) -> Self;

    /// Element-wise subtraction.
    fn sub(self, rhs: Self) -> Self;

    /// Element-wise multiplication.
    fn mul(self, rhs: Self) -> Self;

    /// Element-wise negation.
    fn neg(self) -> Self;

    /// Element-wise squaring.
    fn square(self) -> Self {
        self.mul(self)
    }

    /// Extract the element at the given lane index.
    fn extract(self, index: usize) -> Self::Scalar;
}

/// Scalar "packed" field — a trivial implementation with WIDTH=1 that works
/// as a fallback on any platform. Used when SIMD is not available.
#[derive(Clone, Copy, Debug)]
pub struct ScalarPacked<F: FieldElement>(pub F);

impl<F: FieldElement> PackedField for ScalarPacked<F> {
    type Scalar = F;
    const WIDTH: usize = 1;

    #[inline(always)]
    fn broadcast(value: F) -> Self {
        ScalarPacked(value)
    }

    #[inline(always)]
    fn from_slice(slice: &[F]) -> Self {
        ScalarPacked(slice[0])
    }

    #[inline(always)]
    fn to_slice(self, slice: &mut [F]) {
        slice[0] = self.0;
    }

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        ScalarPacked(self.0.add(rhs.0))
    }

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        ScalarPacked(self.0.sub(rhs.0))
    }

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        ScalarPacked(self.0.mul(rhs.0))
    }

    #[inline(always)]
    fn neg(self) -> Self {
        ScalarPacked(self.0.neg())
    }

    #[inline(always)]
    fn extract(self, _index: usize) -> F {
        self.0
    }
}
