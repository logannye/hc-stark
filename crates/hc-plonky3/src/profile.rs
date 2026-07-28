//! `DurableFieldProfile` bundles every field-specific type the durable
//! prover needs, so `dft`, `mmcs`, `fri`, `quotient`, `bounded_pcs`, and
//! `bounded_prover` can be written once and instantiated per field.
//! `GoldilocksProfile` (this file) is the extracted, behavior-preserving
//! form of what `prover.rs` previously hardcoded. See task-2-report.md for
//! the exact trait bounds this compiled against, if they differ from the
//! sketch in the plan that introduced this file.

use hc_stream::CanonicalElement;
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_symmetric::{CryptographicHasher, CryptographicPermutation, PseudoCompressionFunction};

/// Every field-specific type and constant the durable prover needs.
/// Implement once per supported field profile.
pub trait DurableFieldProfile: Clone + Send + Sync + 'static {
    /// The base field. Must support two-adic FFT (Plonky3's DFT requires it).
    type Val: Field + TwoAdicField;
    /// The extension field used for FRI challenges.
    type Challenge: ExtensionField<Self::Val>;
    /// The Poseidon2 (or equivalent) permutation over `Val`.
    type Permutation: CryptographicPermutation<[Self::Val; 8]> + Clone;
    /// Sponge hash built from `Permutation`.
    type Hash: CryptographicHasher<Self::Val, [Self::Val; 4]> + Clone;
    /// Merkle compression built from `Permutation`.
    type Compression: PseudoCompressionFunction<[Self::Val; 4], 2> + Clone;
    /// The durable on-SSD scratch word for this field. Bridges `Val` to
    /// `hc_stream::CanonicalElement` — see `dft::GoldilocksWord` for the
    /// existing Goldilocks form Task 4 will generalize.
    type Word: CanonicalElement + From<Self::Val> + Into<Self::Val>;

    /// Machine-readable field name, matching `tinyzkp_contracts::FIELD` /
    /// `canonical_extension_degree` in `estimate_params.rs`. Exactly
    /// `"goldilocks"` or `"babybear"` for the two profiles this plan adds.
    const FIELD_NAME: &'static str;
    const EXTENSION_DEGREE: u8;

    /// Constructs a fresh permutation instance. Profiles differ here only
    /// in which concrete Poseidon2 instantiation they call.
    fn profile_permutation() -> Self::Permutation;

    /// Upper bound (exclusive) on values this profile's workloads may seed
    /// with, so generated fixtures (Fibonacci's `initial_a`/`initial_b`,
    /// etc.) never exceed the field's modulus. Generalizes
    /// `GOLDILOCKS_MODULUS_U64` in `prover.rs`.
    fn modulus_u64() -> u64;
}

use crate::dft::GoldilocksWord;
use p3_field::extension::BinomialExtensionField;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::rngs::Xoshiro256PlusPlus;
use rand::SeedableRng;

#[derive(Clone, Debug, Default)]
pub struct GoldilocksProfile;

impl DurableFieldProfile for GoldilocksProfile {
    type Val = Goldilocks;
    type Challenge = BinomialExtensionField<Goldilocks, 2>;
    type Permutation = Poseidon2Goldilocks<8>;
    type Hash = PaddingFreeSponge<Self::Permutation, 8, 4, 4>;
    type Compression = TruncatedPermutation<Self::Permutation, 2, 4, 8>;
    type Word = GoldilocksWord;

    const FIELD_NAME: &'static str = "goldilocks";
    const EXTENSION_DEGREE: u8 = 2;

    fn profile_permutation() -> Self::Permutation {
        // Copied verbatim from checkpoint.rs::profile_permutation (the
        // function fri.rs/mmcs.rs/prover.rs actually call, via
        // `use crate::checkpoint::profile_permutation` — NOT a same-named
        // function that ever lived in prover.rs). Same seed (1), same RNG
        // algorithm (Xoshiro256PlusPlus, named explicitly so 32-bit WASM
        // reconstructs the identical frozen transcript), same constructor.
        // Byte-identical output depends on this being an exact copy.
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
        Self::Permutation::new_from_rng_128(&mut rng)
    }

    fn modulus_u64() -> u64 {
        crate::prover::GOLDILOCKS_MODULUS_U64
    }
}
