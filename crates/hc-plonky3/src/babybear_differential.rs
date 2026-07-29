//! Standing regression protection for the BabyBear profile.
//!
//! ## Why this file exists
//!
//! Every byte-equality guarantee this crate makes is pinned for Goldilocks and
//! only Goldilocks: `bounded_prover.rs`'s known-answer test hashes a Goldilocks
//! proof, and the differential tests in `dft`/`mmcs`/`fri`/`quotient` all
//! instantiate `GoldilocksProfile`. That leaves a whole class of regressions
//! invisible — the numbers that differ between the two profiles are
//!
//! | quantity                    | Goldilocks | BabyBear |
//! |-----------------------------|-----------:|---------:|
//! | Poseidon2 permutation width |          8 |       16 |
//! | Merkle digest elements      |          4 |        8 |
//! | extension degree            |          2 |        4 |
//! | durable scratch word bytes  |          8 |        4 |
//!
//! and a Goldilocks test cannot distinguish any of them: three of the four are
//! `8` there, and the fourth (`4`) collides with the digest size. A refactor
//! that conflated the permutation width with the scratch element width, or the
//! extension degree with the Merkle folding arity, would keep every existing
//! test green while silently corrupting BabyBear.
//!
//! Each test below compares a durable component against the **unmodified
//! upstream Plonky3 implementation** at BabyBear's real dimensions, mirroring
//! the Goldilocks differential test of the same name.

#![cfg(test)]

use crate::dft::{BabyBearWord, ResourceBoundedDft};
use crate::fri::{fold_binary_layer, prove_durable_fri_observed_batched, ScratchChallengeVector};
use crate::mmcs::{DurableProfileMmcs, ReferenceMmcs};
use crate::profile::{BabyBearProfile, DurableFieldProfile};
use crate::quotient::{build_quotient_chunk_ldes, stream_quotient_values, EvaluationConfig};
use crate::workloads::{fibonacci_trace, FibonacciAir};
use hc_stream::{
    BlockMatrix, CheckpointPolicy, MatrixStore, ResourceMode, ResourcePolicyV1, ScratchMatrixStore,
};
use p3_air::symbolic::AirLayout;
use p3_air::BaseAir;
use p3_baby_bear::BabyBear;
use p3_commit::{BatchOpening, ExtensionMmcs, Mmcs, Pcs, PolynomialSpace};
use p3_dft::Radix2DitParallel;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_fri::{FriFoldingStrategy, FriParameters, TwoAdicFriFolding, TwoAdicFriFoldingForMmcs};
use p3_matrix::bitrev::BitReversibleMatrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{get_log_num_quotient_chunks, quotient_values, StarkGenericConfig};
use std::path::Path;

/// BabyBear's dimensions, spelled once. These are Plonky3's own reference
/// BabyBear config numbers, not a TinyZKP choice.
const PW: usize = 16;
const DE: usize = 8;
/// Deliberately named apart from `PW`/`DE`: this is
/// `<BabyBearProfile::Challenge as BasedVectorSpace<BabyBear>>::DIMENSION`,
/// the number of durable scratch COLUMNS one FRI/quotient value occupies. It is
/// 4 for BabyBear and 2 for Goldilocks, and is neither the digest size nor the
/// Merkle folding arity (which is 2 for both profiles).
const EXT_DEGREE: usize = 4;

type Profile = BabyBearProfile;
type Challenge = <BabyBearProfile as DurableFieldProfile<PW, DE>>::Challenge;
type Hash = <BabyBearProfile as DurableFieldProfile<PW, DE>>::Hash;
type Compression = <BabyBearProfile as DurableFieldProfile<PW, DE>>::Compression;
type DurableMmcs = DurableProfileMmcs<PW, DE, Profile>;
/// The unmodified upstream `MerkleTreeMmcs` at BabyBear's dimensions —
/// `MerkleTreeMmcs<_, _, _, _, 2, 8>`: arity 2 (unchanged from Goldilocks),
/// digest 8 (changed).
type UpstreamMmcs = ReferenceMmcs<PW, DE, Profile>;

const _: () = {
    assert!(EXT_DEGREE == 4);
    assert!(PW != DE);
};

fn policy(root: &Path) -> ResourcePolicyV1 {
    ResourcePolicyV1 {
        mode: ResourceMode::Scratch,
        max_resident_bytes: 64 * 1024 * 1024,
        max_scratch_bytes: 512 * 1024 * 1024,
        scratch_dir: root.to_path_buf(),
        max_threads: 1,
        checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
    }
}

fn components() -> (Hash, Compression) {
    (Profile::profile_hash(), Profile::profile_compression())
}

fn challenge(seed: u64) -> Challenge {
    Challenge::from_basis_coefficients_fn(|coordinate| BabyBear::from_u64(seed + coordinate as u64))
}

/// The extension degree really is 4 here, so any code that hardcoded 2 is
/// exercised by every test in this file. Stated as an assertion rather than a
/// comment so it cannot silently stop being true.
#[test]
fn babybear_extension_degree_and_digest_size_are_not_goldilocks() {
    assert_eq!(
        <Challenge as BasedVectorSpace<BabyBear>>::DIMENSION,
        EXT_DEGREE
    );
    assert_eq!(<BabyBearWord as hc_stream::CanonicalElement>::WIDTH, 4);
    assert_eq!(
        <crate::dft::GoldilocksWord as hc_stream::CanonicalElement>::WIDTH,
        8
    );
}

/// `fold_binary_layer` vs `p3_fri`'s own `fold_matrix`, at BabyBear.
///
/// The durable fold reads its input as `EXT_DEGREE` base-field columns per
/// value; upstream reads a `RowMajorMatrix<Challenge>` of width 2 (the folding
/// ARITY). Those two 2-vs-4 numbers are the same literal at Goldilocks, which
/// is exactly the confusion this catches.
#[test]
fn babybear_durable_binary_fold_matches_plonky3() {
    let dir = tempfile::tempdir().unwrap();
    let values: Vec<Challenge> = (0..32).map(|index| challenge(index * 19 + 3)).collect();
    let beta = challenge(41);

    let source =
        ScratchChallengeVector::<PW, DE, Profile>::from_values(&policy(dir.path()), &values)
            .unwrap();
    let actual = fold_binary_layer::<PW, DE, Profile>(&source, beta, &policy(dir.path())).unwrap();

    let (hash, compression) = components();
    let upstream_base = UpstreamMmcs::new(hash, compression, 0);
    let folding: TwoAdicFriFoldingForMmcs<BabyBear, UpstreamMmcs> =
        TwoAdicFriFolding(core::marker::PhantomData);
    // Width 2 is the FOLDING ARITY, not the extension degree.
    let expected = <_ as FriFoldingStrategy<BabyBear, Challenge>>::fold_matrix(
        &folding,
        beta,
        1,
        RowMajorMatrix::new(values, 2),
    );
    assert_eq!(actual.try_read(0, actual.len()).unwrap(), expected);
    let _ = upstream_base;
}

/// `DurableProfileMmcs` roots and openings vs the unmodified
/// `MerkleTreeMmcs<_, _, _, _, 2, 8>`, at BabyBear.
///
/// An 8-element digest is the change from Goldilocks; a 4-element BabyBear
/// digest would be roughly half the collision resistance and would still pass
/// every Goldilocks test in the crate.
#[test]
fn babybear_durable_mmcs_roots_and_openings_match_upstream() {
    let dir = tempfile::tempdir().unwrap();
    let (hash, compression) = components();
    let durable = DurableMmcs::new(hash.clone(), compression.clone(), policy(dir.path())).unwrap();
    let upstream = UpstreamMmcs::new(hash, compression, 0);

    let first = RowMajorMatrix::new((0..64).map(BabyBear::from_u64).collect::<Vec<_>>(), 4);
    let second = RowMajorMatrix::new((64..96).map(BabyBear::from_u64).collect::<Vec<_>>(), 2);
    let (expected_root, expected_data) = upstream.commit(vec![first.clone(), second.clone()]);
    let (actual_root, actual_data) = durable.commit(vec![first, second]);
    assert_eq!(
        actual_root, expected_root,
        "durable BabyBear Merkle root diverged from unmodified Plonky3"
    );
    assert_eq!(actual_root.roots()[0].len(), DE);

    for index in 0..16 {
        let expected = upstream.open_batch(index, &expected_data);
        let actual = durable.open_batch(index, &actual_data);
        assert_eq!(actual.opened_values, expected.opened_values);
        assert_eq!(actual.opening_proof, expected.opening_proof);
    }

    let indices = [0usize, 1, 3, 7, 12, 15];
    let batched = durable.open_batches_sorted(&indices, &actual_data).unwrap();
    for (index, batched_opening) in indices.into_iter().zip(batched) {
        let individual = durable.open_batch(index, &actual_data);
        assert_eq!(batched_opening.opened_values, individual.opened_values);
        assert_eq!(batched_opening.opening_proof, individual.opening_proof);
    }
}

/// `prove_durable_fri_observed_batched` vs `p3_fri::prover::prove_fri`, at
/// BabyBear, compared as POSTCARD BYTES — the serialized form is what a
/// verifier consumes, so byte equality is the claim that matters.
#[test]
#[allow(clippy::type_complexity)]
fn babybear_durable_fri_proof_bytes_match_plonky3_reference() {
    let dir = tempfile::tempdir().unwrap();
    let values: Vec<Challenge> = (0..32).map(|index| challenge(index * 23 + 5)).collect();
    let (hash, compression) = components();

    let upstream_base = UpstreamMmcs::new(hash.clone(), compression.clone(), 0);
    let upstream_fri =
        ExtensionMmcs::<BabyBear, Challenge, UpstreamMmcs>::new(upstream_base.clone());
    let upstream_params = FriParameters::new_testing(upstream_fri, 0);
    let folding: TwoAdicFriFoldingForMmcs<BabyBear, UpstreamMmcs> =
        TwoAdicFriFolding(core::marker::PhantomData);
    let mut upstream_challenger =
        crate::fri::ProfileChallengerFor::<PW, DE, Profile>::new(Profile::profile_permutation());
    let no_openings: Vec<
        p3_fri::ProverDataWithOpeningPoints<
            '_,
            Challenge,
            <UpstreamMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>,
        >,
    > = vec![];
    let upstream_proof = p3_fri::prover::prove_fri(
        &folding,
        &upstream_params,
        vec![values.clone()],
        &mut upstream_challenger,
        5,
        &no_openings,
        &upstream_base,
    );

    let durable_base = DurableMmcs::new(hash, compression, policy(dir.path())).unwrap();
    let durable_params = FriParameters::new_testing(ExtensionMmcs::new(durable_base.clone()), 0);
    let input =
        ScratchChallengeVector::<PW, DE, Profile>::from_values(&policy(dir.path()), &values)
            .unwrap();
    let mut durable_challenger =
        crate::fri::ProfileChallengerFor::<PW, DE, Profile>::new(Profile::profile_permutation());
    let durable_proof = prove_durable_fri_observed_batched(
        &durable_params,
        &durable_base,
        vec![input],
        &mut durable_challenger,
        5,
        |indices| {
            assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
            Ok(vec![
                Vec::<BatchOpening<BabyBear, DurableMmcs>>::new();
                indices.len()
            ])
        },
        &policy(dir.path()),
        |_, _| Ok(()),
    )
    .unwrap();

    assert_eq!(
        postcard::to_allocvec(&durable_proof).unwrap(),
        postcard::to_allocvec(&upstream_proof).unwrap(),
        "durable BabyBear FRI proof bytes diverged from unmodified Plonky3"
    );
}

/// `stream_quotient_values` / `build_quotient_chunk_ldes` vs `p3_uni_stark`'s
/// `quotient_values` / `get_quotient_ldes`, at BabyBear.
///
/// This is the test that would catch an extension-degree mistake in the durable
/// quotient layout: the scratch store has `EXT_DEGREE` columns per value, and
/// reading it back with the Goldilocks stride of 2 would decode garbage.
#[test]
fn babybear_streamed_quotient_matches_upstream_values_and_ldes() {
    let dir = tempfile::tempdir().unwrap();
    let rows = 16usize;
    let trace = fibonacci_trace::<BabyBear>(0, 1, rows);
    let public = vec![BabyBear::ZERO, BabyBear::ONE, *trace.values.last().unwrap()];

    let config =
        crate::prover::make_config::<PW, DE, Profile, _>(Radix2DitParallel::<BabyBear>::default());
    let pcs = StarkGenericConfig::pcs(&config);
    type EvalConfig = EvaluationConfig<PW, DE, Profile>;
    type EvalPcs = <EvalConfig as StarkGenericConfig>::Pcs;
    type EvalChallenger = <EvalConfig as StarkGenericConfig>::Challenger;

    let trace_domain =
        <EvalPcs as Pcs<Challenge, EvalChallenger>>::natural_domain_for_degree(pcs, rows);
    let (_, trace_data) =
        <EvalPcs as Pcs<Challenge, EvalChallenger>>::commit(pcs, [(trace_domain, trace.clone())]);
    let layout = AirLayout {
        main_width: BaseAir::<BabyBear>::width(&FibonacciAir),
        num_public_values: BaseAir::<BabyBear>::num_public_values(&FibonacciAir),
        ..Default::default()
    };
    let log_chunks = get_log_num_quotient_chunks::<BabyBear, _>(&FibonacciAir, layout, 0);
    let quotient_domain =
        trace_domain.create_disjoint_domain(1 << (rows.trailing_zeros() as usize + log_chunks));
    let trace_on_quotient = <EvalPcs as Pcs<Challenge, EvalChallenger>>::get_evaluations_on_domain(
        pcs,
        &trace_data,
        0,
        quotient_domain,
    );
    let alpha = challenge(7);
    let expected = quotient_values::<EvalConfig, _, _>(
        pcs,
        &FibonacciAir,
        &public,
        layout,
        trace_domain,
        quotient_domain,
        &trace_on_quotient,
        None,
        alpha,
    );

    let mut trace_store = ScratchMatrixStore::<BabyBearWord>::create(
        dir.path(),
        "babybear-trace.bin",
        rows as u64,
        trace.width(),
    )
    .unwrap();
    let words: Vec<_> = trace.values.iter().copied().map(BabyBearWord).collect();
    trace_store.write_rows(0, rows, &words).unwrap();
    trace_store.finalize().unwrap();
    let dft = ResourceBoundedDft::<PW, DE, Profile>::new(policy(dir.path())).unwrap();
    let trace_lde = dft
        .try_coset_lde_block_matrix(&trace_store, 1, BabyBear::GENERATOR)
        .unwrap();

    let actual = stream_quotient_values::<PW, DE, Profile, _, _>(
        &FibonacciAir,
        &public,
        trace_domain,
        quotient_domain,
        &trace_lde,
        alpha,
        &policy(dir.path()),
        dir.path(),
        "babybear-quotient.bin",
    )
    .unwrap();
    assert_eq!(
        actual.columns(),
        EXT_DEGREE,
        "the durable quotient store must hold one column per extension coordinate"
    );

    let mut actual_words = vec![BabyBearWord::default(); expected.len() * EXT_DEGREE];
    actual
        .read_rows(0, expected.len(), &mut actual_words)
        .unwrap();
    let actual_values: Vec<Challenge> = actual_words
        .chunks_exact(EXT_DEGREE)
        .map(|words| {
            let basis: Vec<BabyBear> = words.iter().map(|word| word.0).collect();
            Challenge::from_basis_coefficients_slice(&basis).unwrap()
        })
        .collect();
    assert_eq!(actual_values, expected);

    let num_chunks = 1usize << log_chunks;
    let expected_flat = RowMajorMatrix::new_col(expected.clone()).flatten_to_base();
    let expected_sub_evaluations = quotient_domain.split_evals(num_chunks, expected_flat);
    let expected_sub_domains = quotient_domain.split_domains(num_chunks);
    let expected_ldes = <EvalPcs as Pcs<Challenge, EvalChallenger>>::get_quotient_ldes(
        pcs,
        expected_sub_domains
            .into_iter()
            .zip(expected_sub_evaluations),
        num_chunks,
    );
    let actual_ldes = build_quotient_chunk_ldes::<PW, DE, Profile>(
        quotient_domain,
        &actual,
        num_chunks,
        1,
        &dft,
        &policy(dir.path()),
        dir.path(),
    )
    .unwrap();
    assert_eq!(actual_ldes.len(), expected_ldes.len());
    for (actual_lde, expected_lde) in actual_ldes.iter().zip(expected_ldes) {
        let expected_standard = expected_lde.bit_reverse_rows().to_row_major_matrix();
        assert_eq!(
            actual_lde.try_rows(0, actual_lde.height()).unwrap(),
            expected_standard.values
        );
    }
}

/// `ResourceBoundedDft` vs the unmodified `Radix2DitParallel` coset LDE, at
/// BabyBear. `dft.rs` has one BabyBear test today; this pins the durable
/// scratch path (4-byte words) rather than only the in-memory transform.
#[test]
fn babybear_durable_coset_lde_matches_unmodified_plonky3() {
    let dir = tempfile::tempdir().unwrap();
    let rows = 32usize;
    let width = 3usize;
    let values: Vec<BabyBear> = (0..rows * width)
        .map(|index| BabyBear::from_u64((index * 11 + 2) as u64))
        .collect();

    let mut store = ScratchMatrixStore::<BabyBearWord>::create(
        dir.path(),
        "babybear-dft-input.bin",
        rows as u64,
        width,
    )
    .unwrap();
    let words: Vec<_> = values.iter().copied().map(BabyBearWord).collect();
    store.write_rows(0, rows, &words).unwrap();
    store.finalize().unwrap();

    let dft = ResourceBoundedDft::<PW, DE, Profile>::new(policy(dir.path())).unwrap();
    let actual = dft
        .try_coset_lde_block_matrix(&store, 1, BabyBear::GENERATOR)
        .unwrap();

    let reference = p3_dft::TwoAdicSubgroupDft::coset_lde_batch(
        &Radix2DitParallel::<BabyBear>::default(),
        RowMajorMatrix::new(values, width),
        1,
        BabyBear::GENERATOR,
    )
    .to_row_major_matrix();
    assert_eq!(
        actual.try_rows(0, actual.height()).unwrap(),
        reference.values,
        "durable BabyBear coset LDE diverged from unmodified Plonky3"
    );
}
