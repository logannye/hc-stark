pub mod extension;
pub mod prime_field;

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
