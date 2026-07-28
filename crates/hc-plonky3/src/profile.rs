//! `DurableFieldProfile` bundles every field-specific type the durable
//! prover needs, so `dft`, `mmcs`, `fri`, `quotient`, `bounded_pcs`, and
//! `bounded_prover` can be written once and instantiated per field.
//! `GoldilocksProfile` (this file) is the extracted, behavior-preserving
//! form of what `prover.rs` previously hardcoded.
//!
//! `PERM_WIDTH` (the Poseidon2 permutation width) and `DIGEST_ELEMS` (the sponge
//! rate/output size, which also matches the Merkle compression chunk size
//! and the challenger's rate — see `checkpoint.rs`'s `WIDTH`/`RATE`
//! constants and this module's `babybear_shape_admits_real_dimensions`
//! test) are **const generic parameters on the trait itself**, not fixed
//! literals and not associated `const`s. This was a fix-round-1 correction:
//! Goldilocks uses width 8 / 4-element digests, but BabyBear's Poseidon2
//! only exists at widths 16/24/32 (`InternalLayerParameters` is only
//! implemented for those in `p3-baby-bear`), and Plonky3's own reference
//! BabyBear config (confirmed by reading `uni-stark/tests/mul_fib_pair.rs`
//! from the upstream Plonky3 repo directly, not guessed) uses an 8-element
//! digest, not 4 — forcing BabyBear into Goldilocks' width/digest numbers
//! would have been both a hard compile error (wrong width) and a silent
//! soundness regression (a 4-element BabyBear digest is ~124 bits, roughly
//! half the collision resistance of Goldilocks' 4-element 256-bit digest).
//!
//! NOTE the deliberate name: `hc_stream::CanonicalElement::WIDTH` means
//! BYTES PER SCRATCH ELEMENT (8 for Goldilocks, 4 for BabyBear), which is a
//! completely different quantity that happens to equal 8 for Goldilocks too.
//! Conflating the two would corrupt the durable scratch layout, so the
//! permutation width is spelled `PERM_WIDTH` here and never plain `WIDTH`.
//!
//! Associated `const`s were tried first and rejected: `Self::PERM_WIDTH` used as
//! an array length inside this trait's own associated-type bounds
//! (`[Self::Val; Self::PERM_WIDTH]`) hits `E0770` ("generic parameters may not
//! be used in const operations") on stable Rust, because the trait
//! definition can't assume a concrete value for `Self::PERM_WIDTH` while
//! defining the shape every implementor must satisfy. Const generic
//! parameters on the trait don't have this problem (this is exactly how
//! Plonky3 itself parameterizes `PaddingFreeSponge`, `TruncatedPermutation`,
//! `MerkleTreeMmcs`, and `DuplexChallenger` — const generics, never
//! associated consts, for anything that sizes an array).

use crate::dft::GoldilocksWord;
use hc_stream::CanonicalElement;
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, Field, PrimeField64, TwoAdicField};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::{CryptographicHasher, CryptographicPermutation, PseudoCompressionFunction};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::rngs::Xoshiro256PlusPlus;
use rand::SeedableRng;

/// Every field-specific type and constant the durable prover needs.
/// Implement once per supported field profile.
///
/// `PERM_WIDTH` is the Poseidon2 permutation's width; `DIGEST_ELEMS` is the
/// sponge/compression digest size (see the module doc comment above for
/// why these are const generic parameters rather than associated consts).
pub trait DurableFieldProfile<const PERM_WIDTH: usize, const DIGEST_ELEMS: usize>:
    Clone + Send + Sync + 'static
where
    // `p3_uni_stark::prove` serializes the Merkle roots, which are
    // `[Val; DIGEST_ELEMS]`. serde's array impls are macro-generated for
    // lengths 0..=32, so a *generic* `DIGEST_ELEMS` can't select one; the
    // bound has to be stated explicitly here. Empirically required — see
    // the `generic_prover_guard` module.
    [Self::Val; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    /// The base field. Must support two-adic FFT (Plonky3's DFT requires it).
    /// `PrimeField64` is required by `DuplexChallenger`'s `GrindingChallenger`
    /// impl, which `TwoAdicFriPcs` requires in turn. BabyBear satisfies it via
    /// `impl<FP: FieldParameters> PrimeField64 for MontyField31<FP>`
    /// (`p3-monty-31-0.6.1/src/monty_31.rs:634`), despite being a 31-bit field.
    type Val: Field + TwoAdicField + PrimeField64;
    /// The extension field used for FRI challenges.
    type Challenge: ExtensionField<Self::Val>;
    /// The Poseidon2 (or equivalent) permutation over `Val`.
    ///
    /// The `Packing` variants of these three bounds are what let Plonky3 run
    /// its Merkle commitments over packed SIMD lanes. They are NOT optional
    /// decoration: without them `MerkleTreeMmcs` does not implement `Mmcs`,
    /// and nothing downstream of it compiles.
    type Permutation: CryptographicPermutation<[Self::Val; PERM_WIDTH]>
        + CryptographicPermutation<[<Self::Val as Field>::Packing; PERM_WIDTH]>
        + Clone;
    /// Sponge hash built from `Permutation`.
    type Hash: CryptographicHasher<Self::Val, [Self::Val; DIGEST_ELEMS]>
        + CryptographicHasher<
            <Self::Val as Field>::Packing,
            [<Self::Val as Field>::Packing; DIGEST_ELEMS],
        > + Clone
        + Sync;
    /// Merkle compression built from `Permutation`.
    type Compression: PseudoCompressionFunction<[Self::Val; DIGEST_ELEMS], 2>
        + PseudoCompressionFunction<[<Self::Val as Field>::Packing; DIGEST_ELEMS], 2>
        + Clone
        + Sync;
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

#[derive(Clone, Debug, Default)]
pub struct GoldilocksProfile;

impl DurableFieldProfile<8, 4> for GoldilocksProfile {
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

// Pins the OTHER `WIDTH`: bytes per durable scratch element. Goldilocks is a
// 64-bit field => 8 bytes, which must agree with `canonical_extension_degree`
// in `estimate_params.rs` or the estimator and the real on-SSD footprint
// disagree. Deliberately spelled out rather than inferred, because this
// number and `PERM_WIDTH` are both 8 for Goldilocks and only for Goldilocks.
const _: () = {
    assert!(
        <<GoldilocksProfile as DurableFieldProfile<8, 4>>::Word as CanonicalElement>::WIDTH == 8
    );
};

#[cfg(test)]
mod fix_round_1_sanity_checks {
    //! Fix-round-1 regression guard, NOT `BabyBearProfile` (that's Task 3's
    //! job). This exists solely to prove `DurableFieldProfile`'s bounds, as
    //! reshaped in this fix round, actually admit BabyBear's *real*
    //! dimensions (width 16, 8-element digest — confirmed against
    //! `p3-baby-bear` 0.6.1 and against upstream Plonky3's own
    //! `uni-stark/tests/mul_fib_pair.rs` reference config) rather than only
    //! ever having been checked against Goldilocks. If a future change to
    //! this trait's shape makes it Goldilocks-only again, this test module
    //! fails to compile and says so immediately, instead of that regression
    //! surfacing only when Task 3 starts.
    use super::DurableFieldProfile;
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_field::extension::BinomialExtensionField;
    use p3_field::PrimeField32;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use rand::rngs::Xoshiro256PlusPlus;
    use rand::SeedableRng;

    /// Minimal throwaway `CanonicalElement` wrapper around `BabyBear`, just
    /// so `type Word` has something to point at. Not the real
    /// `BabyBearWord` (Task 4's job) — BabyBear is a 31-bit field, encoded
    /// here as 4 little-endian bytes of its canonical `u32` representative.
    #[derive(Copy, Clone, Debug, Default)]
    struct ThrowawayBabyBearWord(BabyBear);

    impl From<BabyBear> for ThrowawayBabyBearWord {
        fn from(value: BabyBear) -> Self {
            Self(value)
        }
    }
    impl From<ThrowawayBabyBearWord> for BabyBear {
        fn from(value: ThrowawayBabyBearWord) -> Self {
            value.0
        }
    }
    impl hc_stream::CanonicalElement for ThrowawayBabyBearWord {
        const WIDTH: usize = 4;
        fn encode(self, out: &mut [u8]) {
            out.copy_from_slice(&self.0.as_canonical_u32().to_le_bytes());
        }
        fn decode(bytes: &[u8]) -> hc_stream::Result<Self> {
            let bytes: [u8; 4] = bytes
                .try_into()
                .map_err(|_| hc_stream::StreamError::Corrupt("invalid babybear word width"))?;
            Ok(Self(BabyBear::new(u32::from_le_bytes(bytes))))
        }
    }

    #[derive(Clone, Debug, Default)]
    struct BabyBearShapeStub;

    impl DurableFieldProfile<16, 8> for BabyBearShapeStub {
        type Val = BabyBear;
        type Challenge = BinomialExtensionField<BabyBear, 4>;
        type Permutation = Poseidon2BabyBear<16>;
        type Hash = PaddingFreeSponge<Self::Permutation, 16, 8, 8>;
        type Compression = TruncatedPermutation<Self::Permutation, 2, 8, 16>;
        type Word = ThrowawayBabyBearWord;

        const FIELD_NAME: &'static str = "babybear-shape-stub";
        const EXTENSION_DEGREE: u8 = 4;

        fn profile_permutation() -> Self::Permutation {
            let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
            Self::Permutation::new_from_rng_128(&mut rng)
        }

        fn modulus_u64() -> u64 {
            (1u64 << 31) - (1u64 << 27) + 1
        }
    }

    #[test]
    fn babybear_shape_admits_real_dimensions() {
        // If this compiles and runs, DurableFieldProfile<16, 8> is
        // satisfiable with BabyBear's real Poseidon2/digest dimensions —
        // the exact thing fix-round-1 needed to prove that Task 2's
        // original submission had only ever verified against Goldilocks.
        let permutation = BabyBearShapeStub::profile_permutation();
        let _hash =
            <BabyBearShapeStub as DurableFieldProfile<16, 8>>::Hash::new(permutation.clone());
        let _compression =
            <BabyBearShapeStub as DurableFieldProfile<16, 8>>::Compression::new(permutation);
        assert_eq!(BabyBearShapeStub::FIELD_NAME, "babybear-shape-stub");
        assert_eq!(BabyBearShapeStub::EXTENSION_DEGREE, 4);
    }
}
