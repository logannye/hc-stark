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
//! soundness regression: a 4-element BabyBear digest is 124 bits WIDE, which
//! is only ~62 bits of collision resistance, against ~128 for Goldilocks'
//! 4-element 256-bit digest. (Digest width and collision resistance are not
//! the same number -- it is the halved one that disqualifies the shape.)
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

use crate::dft::{BabyBearWord, GoldilocksWord};
use hc_stream::CanonicalElement;
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
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

    /// The sponge hash built from a fresh [`Self::profile_permutation`].
    ///
    /// `Self::Hash` is an opaque associated type, so no downstream module can
    /// call `PaddingFreeSponge::new` on it; without this the MMCS/PCS
    /// constructors stay Goldilocks-pinned. Implementations must construct it
    /// exactly as `prover.rs::profile_components` always has — from a
    /// permutation clone, hash first, compression second — because the
    /// Goldilocks transcript is frozen.
    fn profile_hash() -> Self::Hash;

    /// The Merkle compression built from the same permutation instance
    /// [`Self::profile_hash`] uses. See that method for why this exists.
    fn profile_compression() -> Self::Compression;

    /// Upper bound (exclusive) on values this profile's workloads may seed
    /// with, so generated fixtures (Fibonacci's `initial_a`/`initial_b`,
    /// etc.) never exceed the field's modulus. Generalizes
    /// `GOLDILOCKS_MODULUS_U64` in `prover.rs`.
    fn modulus_u64() -> u64;

    /// Capture a resumable snapshot of this profile's duplex challenger, or
    /// `None` when this profile has no durable checkpoint representation.
    ///
    /// `checkpoint.rs`'s `ChallengerSnapshotV1` is a **frozen, Goldilocks-only
    /// wire format**: a fixed `[u64; 8]` sponge state, a `RATE`-of-4 buffer
    /// bound, and Goldilocks-modulus canonicality validation. It cannot
    /// represent BabyBear's `<16, 8>` challenger, and Phase 3A deliberately
    /// does not widen it (that would change a serialized, release-pinned
    /// format for a field that has no checkpoints to be compatible with yet).
    ///
    /// Returning `None` is therefore not an error: it means "this profile
    /// proves single-shot". `bounded_prover` treats it as a refusal to write
    /// a checkpoint it could never restore, rather than writing one that a
    /// later resume would silently misinterpret.
    fn capture_challenger(
        challenger: &p3_challenger::DuplexChallenger<
            Self::Val,
            Self::Permutation,
            PERM_WIDTH,
            DIGEST_ELEMS,
        >,
    ) -> Option<crate::checkpoint::ChallengerSnapshotV1>;

    /// Rebuild this profile's challenger from a durable snapshot. `None` for
    /// every profile whose [`Self::capture_challenger`] returns `None`, so a
    /// checkpoint that somehow reached a non-checkpointable profile fails
    /// closed instead of resuming from an unrelated transcript.
    fn restore_challenger(
        snapshot: &crate::checkpoint::ChallengerSnapshotV1,
    ) -> Option<
        p3_challenger::DuplexChallenger<Self::Val, Self::Permutation, PERM_WIDTH, DIGEST_ELEMS>,
    >;
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

    // Constructed exactly as `prover.rs::profile_components` always did: one
    // permutation, `Hash::new(permutation.clone())`, then
    // `Compression::new(permutation)`. `Poseidon2Goldilocks` is a value type
    // whose clones are indistinguishable, so building each from its own fresh
    // `profile_permutation()` is byte-equivalent — but the calls are kept in
    // that order and shape so the frozen transcript's provenance stays
    // readable against the pre-generic code.
    fn profile_hash() -> Self::Hash {
        Self::Hash::new(Self::profile_permutation())
    }

    fn profile_compression() -> Self::Compression {
        Self::Compression::new(Self::profile_permutation())
    }

    fn modulus_u64() -> u64 {
        crate::prover::GOLDILOCKS_MODULUS_U64
    }

    /// Goldilocks is the one profile `ChallengerSnapshotV1` can represent:
    /// its `<8, 4>` dimensions are exactly the format's hardcoded `WIDTH`/
    /// `RATE`, and its modulus is the one the format validates against.
    fn capture_challenger(
        challenger: &p3_challenger::DuplexChallenger<Goldilocks, Self::Permutation, 8, 4>,
    ) -> Option<crate::checkpoint::ChallengerSnapshotV1> {
        Some(crate::checkpoint::ChallengerSnapshotV1::capture(challenger))
    }

    fn restore_challenger(
        snapshot: &crate::checkpoint::ChallengerSnapshotV1,
    ) -> Option<p3_challenger::DuplexChallenger<Goldilocks, Self::Permutation, 8, 4>> {
        snapshot.restore().ok()
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

/// The second profile. Not yet reachable from any prover entry point —
/// `dft`/`mmcs`/`fri`/`quotient`/`bounded_pcs`/`bounded_prover` are still
/// Goldilocks-concrete until Tasks 4-8 genericize them, and the admission
/// gate does not accept `"babybear"` until Task 9.
///
/// Dimensions are `<16, 8>`, matching Plonky3's own reference BabyBear
/// config (`p3-uni-stark-0.6.1/tests/mul_fib_pair.rs:171-190`). They are NOT
/// interchangeable with Goldilocks' `<8, 4>`: BabyBear's Poseidon2 only
/// exists at widths 16/24/32 (`InternalLayerParameters` is implemented for
/// exactly those in `p3-baby-bear-0.6.1/src/poseidon2.rs:474-476`), and a
/// 4-element BabyBear digest would be ~62-bit collision resistance against
/// Goldilocks' ~128.
#[derive(Clone, Debug, Default)]
pub struct BabyBearProfile;

impl DurableFieldProfile<16, 8> for BabyBearProfile {
    type Val = BabyBear;
    type Challenge = BinomialExtensionField<BabyBear, 4>;
    type Permutation = Poseidon2BabyBear<16>;
    type Hash = PaddingFreeSponge<Self::Permutation, 16, 8, 8>;
    type Compression = TruncatedPermutation<Self::Permutation, 2, 8, 16>;
    type Word = BabyBearWord;

    const FIELD_NAME: &'static str = "babybear";
    /// Must stay 4. `canonical_extension_degree("babybear")` in
    /// `estimate_params.rs:369` already returns `(4, 4)`, and `/v1/estimate`
    /// is answering BabyBear queries in production against it — degree 2 here
    /// would make the shipped estimator silently disagree with what the
    /// prover actually builds.
    const EXTENSION_DEGREE: u8 = 4;

    fn profile_permutation() -> Self::Permutation {
        // Same seed and RNG as GoldilocksProfile. This is a NEW transcript,
        // not a frozen one — no BabyBear proof has ever been published, so
        // there is nothing to stay byte-compatible with. Matching Goldilocks'
        // construction keeps the two profiles auditable side by side.
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
        Self::Permutation::new_from_rng_128(&mut rng)
    }

    fn profile_hash() -> Self::Hash {
        Self::Hash::new(Self::profile_permutation())
    }

    fn profile_compression() -> Self::Compression {
        Self::Compression::new(Self::profile_permutation())
    }

    fn modulus_u64() -> u64 {
        BABYBEAR_MODULUS_U64
    }

    /// BabyBear has no durable checkpoint format. `ChallengerSnapshotV1`
    /// stores a `[u64; 8]` sponge state and validates against the Goldilocks
    /// modulus; this profile's challenger has a 16-element state over a
    /// 31-bit field, so it is not merely narrower — it is unrepresentable.
    /// Widening that frozen format is explicitly out of scope for Phase 3A,
    /// so BabyBear proves single-shot and the prover writes no checkpoint.
    fn capture_challenger(
        _challenger: &p3_challenger::DuplexChallenger<BabyBear, Self::Permutation, 16, 8>,
    ) -> Option<crate::checkpoint::ChallengerSnapshotV1> {
        None
    }

    fn restore_challenger(
        _snapshot: &crate::checkpoint::ChallengerSnapshotV1,
    ) -> Option<p3_challenger::DuplexChallenger<BabyBear, Self::Permutation, 16, 8>> {
        None
    }
}

/// BabyBear's prime, 2^31 - 2^27 + 1, as `BabyBearParameters::PRIME`
/// (`p3-baby-bear-0.6.1/src/baby_bear.rs:18`) states it.
pub const BABYBEAR_MODULUS_U64: u64 = 0x7800_0001;

/// Everything the JSON contract boundary needs to know about a field it only
/// sees as a **string** (`AirPackageV1::field`, `TraceManifestV1`'s encoding),
/// rather than as a `P: DurableFieldProfile` type parameter.
///
/// This exists because the validators in `contracts.rs`, `declarative.rs`, and
/// `hc-cli` receive user-supplied `u64`s alongside a declared field name and
/// have no type-level profile to consult. Before this table they all compared
/// against **Goldilocks'** modulus unconditionally, which on any other field
/// would admit every value below 2^64 and then let the field constructor
/// silently reduce it — exactly the collapse `prover.rs`'s
/// `GOLDILOCKS_MODULUS_U64` doc comment warns about ("distinct manifests
/// collapse to the same public field element"), and the same defect class that
/// `BabyBearWord::decode` was fixed for.
///
/// Every entry is tied back to its `DurableFieldProfile` impl by the
/// `const _` assertions and the unit tests below, so the two cannot drift.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeclaredFieldProfile {
    /// Matches the profile's `FIELD_NAME`.
    pub name: &'static str,
    /// Exclusive upper bound on a canonical element, as an integer.
    pub modulus_u64: u64,
    /// Bytes one base-field element occupies in the durable/wire encoding.
    /// Matches `<P::Word as CanonicalElement>::WIDTH`.
    pub element_bytes: u64,
    /// The only `TraceManifestV1::field_encoding` value valid for this field.
    pub trace_encoding: &'static str,
    /// Matches the profile's `EXTENSION_DEGREE`.
    pub extension_degree: u8,
}

/// Every field this crate can describe on the contract boundary.
///
/// Membership here means "the validators know how to bound values for this
/// field", NOT "the engine can prove it". Admission is a separate decision
/// made per contract (see `AirPackageV1::validate`), and execution is a third
/// (`declarative.rs` refuses anything but Goldilocks, because its workloads
/// are `ResourceBoundedWorkload<8, 4, GoldilocksProfile>` at the type level).
pub const DECLARED_FIELD_PROFILES: &[DeclaredFieldProfile] = &[
    DeclaredFieldProfile {
        name: <GoldilocksProfile as DurableFieldProfile<8, 4>>::FIELD_NAME,
        modulus_u64: crate::prover::GOLDILOCKS_MODULUS_U64,
        element_bytes: 8,
        trace_encoding: "goldilocks_u64_le",
        extension_degree: <GoldilocksProfile as DurableFieldProfile<8, 4>>::EXTENSION_DEGREE,
    },
    DeclaredFieldProfile {
        name: <BabyBearProfile as DurableFieldProfile<16, 8>>::FIELD_NAME,
        modulus_u64: BABYBEAR_MODULUS_U64,
        element_bytes: 4,
        trace_encoding: "babybear_u32_le",
        extension_degree: <BabyBearProfile as DurableFieldProfile<16, 8>>::EXTENSION_DEGREE,
    },
];

/// Resolve a declared field name. `None` means "this crate has no canonicality
/// rule for that name", which every caller must treat as a refusal — never as
/// a licence to fall back on some other field's bounds.
#[must_use]
pub fn declared_field_profile(field: &str) -> Option<&'static DeclaredFieldProfile> {
    DECLARED_FIELD_PROFILES
        .iter()
        .find(|profile| profile.name == field)
}

// `element_bytes` must equal the durable scratch word width, or the contract
// layer and the on-SSD layout disagree about how many bytes a trace row is.
const _: () = {
    assert!(
        DECLARED_FIELD_PROFILES[0].element_bytes as usize
            == <<GoldilocksProfile as DurableFieldProfile<8, 4>>::Word as CanonicalElement>::WIDTH
    );
    assert!(
        DECLARED_FIELD_PROFILES[1].element_bytes as usize
            == <<BabyBearProfile as DurableFieldProfile<16, 8>>::Word as CanonicalElement>::WIDTH
    );
    assert!(DECLARED_FIELD_PROFILES.len() == 2);
};

// EXTENSION_DEGREE (what contracts, manifests, and the estimator report) and
// Challenge::DIMENSION (what actually sizes the durable on-SSD layout, via
// fri.rs/quotient.rs's extension_degree()) are two independent sources of the
// same number. Nothing else pins them together: a future profile declaring
// EXTENSION_DEGREE = 2 while using BinomialExtensionField<F, 4> would build a
// degree-4 scratch layout while every contract and estimate reported 2, and
// no test would fail. KoalaBear is an expected fast-follow, so pin it now.
const _: () = {
    assert!(
        GoldilocksProfile::EXTENSION_DEGREE as usize
            == <<GoldilocksProfile as DurableFieldProfile<8, 4>>::Challenge
                as p3_field::BasedVectorSpace<Goldilocks>>::DIMENSION
    );
    assert!(
        BabyBearProfile::EXTENSION_DEGREE as usize
            == <<BabyBearProfile as DurableFieldProfile<16, 8>>::Challenge
                as p3_field::BasedVectorSpace<BabyBear>>::DIMENSION
    );
};

// The scratch-word counterpart of the Goldilocks assertion above: BabyBear is
// a 31-bit field, so 4 bytes per element — deliberately NOT 16 (the
// permutation width) and NOT 8 (the digest size). All three numbers appear in
// this impl and only one of them sizes the on-SSD layout.
const _: () = {
    assert!(
        <<BabyBearProfile as DurableFieldProfile<16, 8>>::Word as CanonicalElement>::WIDTH == 4
    );
    assert!(BABYBEAR_MODULUS_U64 == (1u64 << 31) - (1u64 << 27) + 1);
};

#[cfg(test)]
mod tests {
    //! Supersedes the fix-round-1 `BabyBearShapeStub`. That stub existed only
    //! to prove `DurableFieldProfile<16, 8>` was satisfiable with BabyBear's
    //! real dimensions before `BabyBearProfile` existed. It does now, and it
    //! is real (non-test) code, so the stub would be a second, drifting copy
    //! of the same shape — the real profile carries the proof instead.
    use super::{BabyBearProfile, DurableFieldProfile, GoldilocksProfile, BABYBEAR_MODULUS_U64};
    use crate::dft::BabyBearWord;
    use hc_stream::CanonicalElement;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    /// The satisfiability proof the stub used to carry. Merely naming these
    /// associated types forces rustc to check `BabyBearProfile` against every
    /// bound on the trait — including the packed-SIMD `Permutation`/`Hash`/
    /// `Compression` bounds and the serde bound on `[Val; DIGEST_ELEMS]`.
    #[test]
    fn babybear_profile_satisfies_the_trait_at_its_real_dimensions() {
        let permutation = BabyBearProfile::profile_permutation();
        let _hash = <BabyBearProfile as DurableFieldProfile<16, 8>>::Hash::new(permutation.clone());
        let _compression =
            <BabyBearProfile as DurableFieldProfile<16, 8>>::Compression::new(permutation);
        assert_eq!(BabyBearProfile::FIELD_NAME, "babybear");
        assert_eq!(BabyBearProfile::EXTENSION_DEGREE, 4);
        assert_eq!(BabyBearProfile::modulus_u64(), BABYBEAR_MODULUS_U64);
    }

    /// The two profiles must not be confusable: different field names,
    /// different extension degrees, different scratch widths, different
    /// moduli. A copy-paste error in a future profile shows up here.
    #[test]
    fn profiles_are_distinct_in_every_field_specific_constant() {
        assert_ne!(BabyBearProfile::FIELD_NAME, GoldilocksProfile::FIELD_NAME);
        assert_ne!(
            BabyBearProfile::EXTENSION_DEGREE,
            GoldilocksProfile::EXTENSION_DEGREE
        );
        assert_ne!(
            BabyBearProfile::modulus_u64(),
            GoldilocksProfile::modulus_u64()
        );
        assert_eq!(<BabyBearWord as CanonicalElement>::WIDTH, 4);
        assert_eq!(
            <<GoldilocksProfile as DurableFieldProfile<8, 4>>::Word as CanonicalElement>::WIDTH,
            8
        );
    }

    fn roundtrip(value: u32) -> BabyBearWord {
        let word = BabyBearWord(BabyBear::new(value));
        let mut buffer = [0u8; <BabyBearWord as CanonicalElement>::WIDTH];
        word.encode(&mut buffer);
        BabyBearWord::decode(&buffer).expect("canonical value must decode")
    }

    #[test]
    fn babybear_word_roundtrips_across_the_canonical_range() {
        // Boundaries plus a deterministic sweep. p-1 is the largest legal
        // value; p itself must NOT be reachable through encode.
        for value in [0u32, 1, 2, 1_000_003, (BABYBEAR_MODULUS_U64 as u32) - 1] {
            let decoded = roundtrip(value);
            assert_eq!(
                decoded.0.as_canonical_u32(),
                value,
                "round trip changed {value}"
            );
        }
        let mut value: u64 = 7;
        for _ in 0..2_000 {
            value = (value * 1_103_515_245 + 12_345) % BABYBEAR_MODULUS_U64;
            let decoded = roundtrip(value as u32);
            assert_eq!(decoded.0.as_canonical_u32(), value as u32);
        }
    }

    /// The check the plan's first draft omitted. `BabyBear::new` accepts any
    /// `u32` and reduces mod p, so without an explicit guard `x` and `x + p`
    /// would decode to the same element and the durable scratch layer would
    /// lose its corruption detector. Goldilocks has always rejected these.
    #[test]
    fn babybear_word_rejects_non_canonical_bytes() {
        let modulus = BABYBEAR_MODULUS_U64 as u32;
        for value in [modulus, modulus + 1, u32::MAX] {
            let bytes = value.to_le_bytes();
            assert!(
                BabyBearWord::decode(&bytes).is_err(),
                "decode accepted non-canonical {value}, losing injectivity"
            );
        }
        // And the value just below the modulus is still accepted, so the
        // guard is not off by one.
        assert!(BabyBearWord::decode(&(modulus - 1).to_le_bytes()).is_ok());
    }

    #[test]
    fn babybear_word_rejects_wrong_width_slices() {
        assert!(BabyBearWord::decode(&[0u8; 3]).is_err());
        assert!(BabyBearWord::decode(&[0u8; 8]).is_err());
    }

    /// `modulus_u64` is the one `DeclaredFieldProfile` member that cannot be
    /// const-asserted against its `DurableFieldProfile` impl (`modulus_u64()`
    /// is a plain trait method, not a `const fn`), so it is pinned here
    /// instead. Without this the string-keyed table could drift away from the
    /// type-keyed profile and every contract-layer bound would silently move.
    #[test]
    fn declared_field_table_agrees_with_every_profile_impl() {
        use super::declared_field_profile;

        let goldilocks = declared_field_profile(GoldilocksProfile::FIELD_NAME)
            .expect("goldilocks must be a declarable field");
        assert_eq!(goldilocks.modulus_u64, GoldilocksProfile::modulus_u64());
        assert_eq!(
            goldilocks.extension_degree,
            GoldilocksProfile::EXTENSION_DEGREE
        );

        let babybear = declared_field_profile(BabyBearProfile::FIELD_NAME)
            .expect("babybear must be a declarable field");
        assert_eq!(babybear.modulus_u64, BabyBearProfile::modulus_u64());
        assert_eq!(babybear.extension_degree, BabyBearProfile::EXTENSION_DEGREE);

        // Distinct bounds are the whole point: a validator keyed off this
        // table must reject for BabyBear what it accepts for Goldilocks.
        assert!(babybear.modulus_u64 < goldilocks.modulus_u64);
        assert_ne!(babybear.trace_encoding, goldilocks.trace_encoding);
    }

    #[test]
    fn unknown_field_names_resolve_to_nothing_rather_than_a_default() {
        use super::declared_field_profile;

        for name in ["", "other", "Goldilocks", "koalabear", "mersenne31"] {
            assert!(
                declared_field_profile(name).is_none(),
                "{name} resolved to a canonicality rule it has no claim to"
            );
        }
    }
}
