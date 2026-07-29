//! The project's first BabyBear proof, produced and verified through the
//! public API only.
//!
//! This is the BabyBear analogue of `bounded_prover.rs`'s
//! `fibonacci_bounded_proof_is_official_and_byte_identical`: the same
//! `FibonacciWorkload`, the same durable scratch pipeline, the same assertion
//! that the durable prover and the conventional in-memory prover agree byte for
//! byte, and the same stock-`p3_uni_stark`-verifier acceptance.
//!
//! **Checkpoint/resume is deliberately absent.** `checkpoint.rs`'s
//! `ChallengerSnapshotV1` is a frozen Goldilocks-only wire format — an
//! `[u64; 8]` sponge state validated against the Goldilocks modulus — which
//! cannot represent BabyBear's `<16, 8>` challenger. `BabyBearProfile` therefore
//! returns `None` from `capture_challenger`, the prover refuses to write a
//! checkpoint it could never restore, and this test runs single-shot with
//! `CheckpointPolicy::DeleteOnSuccess`. Resumable BabyBear checkpoints are a
//! fast-follow, not a requirement of "prove and verify a single-table BabyBear
//! AIR".
//!
//! It lives in `tests/` rather than in a `#[cfg(test)] mod tests` so it can
//! only reach what `lib.rs` actually exports — if the generic entry points were
//! not public, this file would not compile.

use hc_plonky3::{
    prove_resource_bounded_with_profile, prove_resource_reference_with_profile,
    verify_resource_bounded_proof_with_profile, BabyBearProfile, FibonacciWorkload,
    GoldilocksProfile,
};
use hc_stream::{CheckpointPolicy, ResourceMode, ResourcePolicyV1};
use std::path::Path;

/// BabyBear's Poseidon2 permutation width and Merkle digest size, matching
/// Plonky3's own reference BabyBear config. NOT interchangeable with
/// Goldilocks' `<8, 4>`.
const BABYBEAR_PERM_WIDTH: usize = 16;
const BABYBEAR_DIGEST_ELEMS: usize = 8;

fn scratch_policy(root: &Path) -> ResourcePolicyV1 {
    ResourcePolicyV1 {
        mode: ResourceMode::Scratch,
        max_resident_bytes: 128 * 1024 * 1024,
        max_scratch_bytes: 2 * 1024 * 1024 * 1024,
        scratch_dir: root.to_path_buf(),
        max_threads: 1,
        // Single-shot: see the module comment.
        checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
    }
}

fn workload() -> FibonacciWorkload {
    FibonacciWorkload {
        initial_a: 0,
        initial_b: 1,
        logical_rows: 16,
    }
}

#[test]
fn babybear_fibonacci_proves_and_verifies_through_the_bounded_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let workload = workload();

    let bounded = prove_resource_bounded_with_profile::<
        BABYBEAR_PERM_WIDTH,
        BABYBEAR_DIGEST_ELEMS,
        BabyBearProfile,
        _,
    >(&workload, &scratch_policy(dir.path()))
    .expect("BabyBear proof generation through the durable pipeline");
    assert!(!bounded.is_empty(), "BabyBear proof carried no bytes");

    // The stock `p3_uni_stark::verify`, against the unmodified upstream
    // `StarkConfig` for BabyBear. TinyZKP contributes no verifier.
    verify_resource_bounded_proof_with_profile::<
        BABYBEAR_PERM_WIDTH,
        BABYBEAR_DIGEST_ELEMS,
        BabyBearProfile,
        _,
    >(&workload, &bounded)
    .expect("the stock Plonky3 verifier must accept the BabyBear proof");
}

#[test]
fn babybear_durable_and_conventional_provers_agree_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let workload = workload();

    let bounded = prove_resource_bounded_with_profile::<
        BABYBEAR_PERM_WIDTH,
        BABYBEAR_DIGEST_ELEMS,
        BabyBearProfile,
        _,
    >(&workload, &scratch_policy(dir.path()))
    .unwrap();
    let conventional = prove_resource_reference_with_profile::<
        BABYBEAR_PERM_WIDTH,
        BABYBEAR_DIGEST_ELEMS,
        BabyBearProfile,
        _,
    >(&workload)
    .unwrap();

    // The whole claim of the durable pipeline: streaming to SSD changes the
    // memory profile and nothing else about the emitted proof.
    assert_eq!(
        bounded, conventional,
        "durable BabyBear proof diverged from the conventional in-memory one"
    );
}

#[test]
fn babybear_verifier_rejects_a_mutated_proof() {
    let dir = tempfile::tempdir().unwrap();
    let workload = workload();
    let proof = prove_resource_bounded_with_profile::<
        BABYBEAR_PERM_WIDTH,
        BABYBEAR_DIGEST_ELEMS,
        BabyBearProfile,
        _,
    >(&workload, &scratch_policy(dir.path()))
    .unwrap();

    // Without this the acceptance test above would also pass against a
    // verifier that accepted everything.
    let mut mutated = proof.clone();
    let last = mutated.len() - 1;
    mutated[last] ^= 1;
    assert!(
        verify_resource_bounded_proof_with_profile::<
            BABYBEAR_PERM_WIDTH,
            BABYBEAR_DIGEST_ELEMS,
            BabyBearProfile,
            _,
        >(&workload, &mutated)
        .is_err(),
        "the BabyBear verifier accepted a mutated proof"
    );
}

/// The two profiles must produce genuinely different proof systems, not the
/// same transcript under a different name. If a future refactor accidentally
/// routed BabyBear through Goldilocks' permutation, digest size, or extension
/// degree, the byte-equality tests above would all still pass — this is what
/// would catch it.
#[test]
fn babybear_and_goldilocks_proofs_are_not_the_same_bytes() {
    let babybear_dir = tempfile::tempdir().unwrap();
    let goldilocks_dir = tempfile::tempdir().unwrap();
    let workload = workload();

    let babybear = prove_resource_bounded_with_profile::<
        BABYBEAR_PERM_WIDTH,
        BABYBEAR_DIGEST_ELEMS,
        BabyBearProfile,
        _,
    >(&workload, &scratch_policy(babybear_dir.path()))
    .unwrap();
    let goldilocks = prove_resource_bounded_with_profile::<8, 4, GoldilocksProfile, _>(
        &workload,
        &scratch_policy(goldilocks_dir.path()),
    )
    .unwrap();

    assert_ne!(
        babybear, goldilocks,
        "BabyBear and Goldilocks emitted identical proof bytes, so at least one \
         is not proving over the field it claims"
    );
}

/// BabyBear's modulus is ~2^31, so a seed that is perfectly canonical for
/// Goldilocks is not for BabyBear. The seed check now goes through
/// `P::modulus_u64()` rather than the `GOLDILOCKS_MODULUS_U64` literal, and
/// this pins that it actually discriminates.
#[test]
fn babybear_rejects_a_seed_that_is_canonical_only_for_goldilocks() {
    let dir = tempfile::tempdir().unwrap();
    let out_of_range = FibonacciWorkload {
        initial_a: hc_plonky3::BABYBEAR_MODULUS_U64,
        initial_b: 1,
        logical_rows: 16,
    };
    assert!(
        prove_resource_bounded_with_profile::<
            BABYBEAR_PERM_WIDTH,
            BABYBEAR_DIGEST_ELEMS,
            BabyBearProfile,
            _,
        >(&out_of_range, &scratch_policy(dir.path()))
        .is_err(),
        "BabyBear accepted a non-canonical seed at or above its modulus"
    );

    // ...and the largest value that IS canonical for BabyBear still proves, so
    // the bound is not off by one.
    let largest_dir = tempfile::tempdir().unwrap();
    let largest_canonical = FibonacciWorkload {
        initial_a: hc_plonky3::BABYBEAR_MODULUS_U64 - 1,
        initial_b: 0,
        logical_rows: 16,
    };
    let proof = prove_resource_bounded_with_profile::<
        BABYBEAR_PERM_WIDTH,
        BABYBEAR_DIGEST_ELEMS,
        BabyBearProfile,
        _,
    >(&largest_canonical, &scratch_policy(largest_dir.path()))
    .expect("the largest canonical BabyBear seed must prove");
    verify_resource_bounded_proof_with_profile::<
        BABYBEAR_PERM_WIDTH,
        BABYBEAR_DIGEST_ELEMS,
        BabyBearProfile,
        _,
    >(&largest_canonical, &proof)
    .expect("the largest canonical BabyBear seed must verify");
}
