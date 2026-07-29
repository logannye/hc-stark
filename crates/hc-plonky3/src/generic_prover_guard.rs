//! Design guard: proves `DurableFieldProfile` can carry a **fully generic**
//! `prove_to_bytes` — the shape Task 8 must reach — including the
//! higher-ranked bound `for<'a> Air<ProverConstraintFolder<'a, Config>>`
//! with `P::Val` appearing as an unnormalized projection inside it.
//!
//! ## Why this exists
//!
//! Task 2 kept `prover.rs`'s `Val` as a concrete alias and recorded the cause
//! as "rustc cannot normalize the projection inside a higher-ranked bound."
//! That diagnosis was incomplete. This module was written to test it and
//! found the real cause: **eight missing trait bounds**, which are now stated
//! once on `DurableFieldProfile` itself. With them present, a fully generic
//! `prove_to_bytes` compiles and produces real proof bytes (see the test
//! below). The higher-ranked bound was never the obstacle.
//!
//! ## The remaining constraint, which Task 8 must respect
//!
//! Making `prover.rs`'s `Val` alias a projection while its *callers* stay
//! concrete still fails — with a different error (`Dft: TwoAdicSubgroupDft<
//! Goldilocks>` unsatisfied), because rustc will not unify the projection
//! with `Goldilocks` in the bounds of `Dft`/`Air`. So the failure is an
//! artifact of a HALF-generic intermediate state, not of the design.
//! **Task 8 must convert `prove_to_bytes` and its generic parameters to
//! `P::Val` in one step**, rather than flipping `Val` first and fixing
//! fallout — that path does not converge.
//!
//! If a later change breaks the trait's ability to support a generic prover,
//! this module stops compiling and says so immediately, instead of that
//! regression surfacing in Task 8 after six modules have been rewritten.

#![cfg(test)]
#![allow(dead_code)]

use crate::profile::DurableFieldProfile;
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::Field;
use p3_fri::TwoAdicFriPcs;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_uni_stark::{prove, StarkConfig};

// Generic mirrors of prover.rs:85-91, with every Goldilocks literal replaced
// by a profile projection or a const generic parameter.
type GuardValPacking<const W: usize, const D: usize, P> =
    <<P as DurableFieldProfile<W, D>>::Val as Field>::Packing;

type GuardValMmcs<const W: usize, const D: usize, P> = MerkleTreeMmcs<
    GuardValPacking<W, D, P>,
    GuardValPacking<W, D, P>,
    <P as DurableFieldProfile<W, D>>::Hash,
    <P as DurableFieldProfile<W, D>>::Compression,
    2,
    D,
>;

type GuardChallengeMmcs<const W: usize, const D: usize, P> = ExtensionMmcs<
    <P as DurableFieldProfile<W, D>>::Val,
    <P as DurableFieldProfile<W, D>>::Challenge,
    GuardValMmcs<W, D, P>,
>;

type GuardChallenger<const W: usize, const D: usize, P> = DuplexChallenger<
    <P as DurableFieldProfile<W, D>>::Val,
    <P as DurableFieldProfile<W, D>>::Permutation,
    W,
    D,
>;

type GuardPcs<const W: usize, const D: usize, P, Dft> = TwoAdicFriPcs<
    <P as DurableFieldProfile<W, D>>::Val,
    Dft,
    GuardValMmcs<W, D, P>,
    GuardChallengeMmcs<W, D, P>,
>;

type GuardConfig<const W: usize, const D: usize, P, Dft> = StarkConfig<
    GuardPcs<W, D, P, Dft>,
    <P as DurableFieldProfile<W, D>>::Challenge,
    GuardChallenger<W, D, P>,
>;

/// The exact shape Task 8 must produce: `prove_to_bytes` generic over the
/// profile, with `P::Val` (an unnormalized projection) appearing inside a
/// `for<'a>` bound. The body calls `prove` for real, because it was `prove`'s
/// bound-checking that produced the original 15 E0277s.
fn guard_prove_to_bytes<const W: usize, const D: usize, P, Dft, A>(
    config: &GuardConfig<W, D, P, Dft>,
    air: &A,
    trace: RowMajorMatrix<P::Val>,
    public_values: &[P::Val],
) -> Vec<u8>
where
    P: DurableFieldProfile<W, D>,
    Dft: TwoAdicSubgroupDft<P::Val>,
    A: for<'a> p3_air::Air<p3_uni_stark::ProverConstraintFolder<'a, GuardConfig<W, D, P, Dft>>>
        + for<'a> p3_air::Air<p3_air::DebugConstraintBuilder<'a, P::Val>>
        + p3_air::Air<p3_air::SymbolicAirBuilder<P::Val>>
        + p3_air::BaseAir<P::Val>,
    // The 8 bounds rustc demanded are now stated ONCE on
    // `DurableFieldProfile` itself. If this function still compiles with
    // them absent here, the trait carries them for every downstream caller
    // and Tasks 4-8 never have to restate them.
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let proof = prove(config, air, trace, public_values);
    postcard::to_allocvec(&proof).expect("guard serialization")
}

/// Force monomorphization at the real Goldilocks profile, so this proves the
/// bound is satisfiable by an actual profile and not merely well-formed.
#[test]
fn generic_prove_to_bytes_compiles_and_proves_at_goldilocks() {
    use crate::profile::GoldilocksProfile;
    use crate::workloads::{fibonacci_public_values, fibonacci_trace, FibonacciAir};
    use p3_dft::Radix2DitParallel;

    type Val = <GoldilocksProfile as DurableFieldProfile<8, 4>>::Val;
    type Dft = Radix2DitParallel<Val>;

    // Build the config through the generic aliases, not prover.rs's concrete
    // ones, so the alias chain itself is exercised.
    let permutation = GoldilocksProfile::profile_permutation();
    let hash = <GoldilocksProfile as DurableFieldProfile<8, 4>>::Hash::new(permutation.clone());
    let compression =
        <GoldilocksProfile as DurableFieldProfile<8, 4>>::Compression::new(permutation.clone());
    let val_mmcs = GuardValMmcs::<8, 4, GoldilocksProfile>::new(hash, compression, 0);
    let challenge_mmcs = GuardChallengeMmcs::<8, 4, GoldilocksProfile>::new(val_mmcs.clone());
    let fri_parameters = p3_fri::FriParameters::new_benchmark(challenge_mmcs);
    let pcs =
        GuardPcs::<8, 4, GoldilocksProfile, Dft>::new(Dft::default(), val_mmcs, fri_parameters);
    let challenger = GuardChallenger::<8, 4, GoldilocksProfile>::new(permutation);
    let config = GuardConfig::<8, 4, GoldilocksProfile, Dft>::new(pcs, challenger);

    let trace = fibonacci_trace::<Val>(0, 1, 16);
    let public_values = fibonacci_public_values(0, 1, 16);

    let bytes = guard_prove_to_bytes::<8, 4, GoldilocksProfile, Dft, FibonacciAir>(
        &config,
        &FibonacciAir,
        trace,
        &public_values,
    );
    assert!(!bytes.is_empty(), "guard produced no proof bytes");
}
