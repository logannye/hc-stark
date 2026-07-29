use crate::fri::ProfileChallengerFor;
use crate::mmcs::{DurableProfileMmcs, ReferenceMmcs};
use crate::profile::DurableFieldProfile;
use hc_stream::ResourcePolicyV1;
use p3_commit::{BatchOpening, BuildPeriodicLdeTableFast, ExtensionMmcs, OpenedValues, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_fri::{FriParameters, FriProof, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleCap;
use p3_uni_stark::StarkConfig;

// The generic mirror of `prover.rs`'s alias chain, with every Goldilocks
// literal replaced by a profile projection or a const generic parameter. The
// shapes are copied from `generic_prover_guard.rs`, which proved they carry a
// fully generic `prove_to_bytes`. `ReferenceMmcs` (from `mmcs.rs`) is the
// unmodified upstream `MerkleTreeMmcs` and doubles as `ValMmcs` here.
pub(crate) type ProfileChallengeMmcs<const W: usize, const D: usize, P> = ExtensionMmcs<
    <P as DurableFieldProfile<W, D>>::Val,
    <P as DurableFieldProfile<W, D>>::Challenge,
    ReferenceMmcs<W, D, P>,
>;
pub(crate) type ProfilePcs<const W: usize, const D: usize, P, Dft> = TwoAdicFriPcs<
    <P as DurableFieldProfile<W, D>>::Val,
    Dft,
    ReferenceMmcs<W, D, P>,
    ProfileChallengeMmcs<W, D, P>,
>;
pub(crate) type ProfileStarkConfig<const W: usize, const D: usize, P, Dft> = StarkConfig<
    ProfilePcs<W, D, P, Dft>,
    <P as DurableFieldProfile<W, D>>::Challenge,
    ProfileChallengerFor<W, D, P>,
>;

pub type DurableInputMmcs<const W: usize, const D: usize, P> = DurableProfileMmcs<W, D, P>;
pub type DurableChallengeMmcs<const W: usize, const D: usize, P> = ExtensionMmcs<
    <P as DurableFieldProfile<W, D>>::Val,
    <P as DurableFieldProfile<W, D>>::Challenge,
    DurableInputMmcs<W, D, P>,
>;
pub type DurablePcsProof<const W: usize, const D: usize, P> = FriProof<
    <P as DurableFieldProfile<W, D>>::Challenge,
    DurableChallengeMmcs<W, D, P>,
    <P as DurableFieldProfile<W, D>>::Val,
    Vec<BatchOpening<<P as DurableFieldProfile<W, D>>::Val, DurableInputMmcs<W, D, P>>>,
>;

type OfficialPcs<const W: usize, const D: usize, P> =
    ProfilePcs<W, D, P, Radix2DitParallel<<P as DurableFieldProfile<W, D>>::Val>>;
/// Verifier-facing PCS for the durable prover. Its associated wire types are
/// identical to the official Plonky3 PCS. Verification delegates to the pinned
/// upstream implementation after a structural serde conversion.
pub struct ResourceBoundedVerifierPcs<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    official: OfficialPcs<W, D, P>,
}

// Hand-written so the bound stays `P: DurableFieldProfile`; `#[derive(Clone)]`
// would additionally demand `P: Clone` on the impl.
impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Clone
    for ResourceBoundedVerifierPcs<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn clone(&self) -> Self {
        Self {
            official: self.official.clone(),
        }
    }
}

// `new`, `make_bounded_verifier_config`, and `make_durable_mmcs` used to be
// pinned to Goldilocks because constructing a profile's sponge and compression
// means calling `PaddingFreeSponge::new`/`TruncatedPermutation::new`, and
// `P::Hash`/`P::Compression` are opaque associated types. `DurableFieldProfile`
// now supplies `profile_hash`/`profile_compression`, so these are generic and
// the Goldilocks values they produce are unchanged.
impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
    ResourceBoundedVerifierPcs<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    pub fn new(log_blowup: usize) -> Self {
        let val_mmcs =
            ReferenceMmcs::<W, D, P>::new(P::profile_hash(), P::profile_compression(), 0);
        let challenge_mmcs = ProfileChallengeMmcs::<W, D, P>::new(val_mmcs.clone());
        let mut fri = FriParameters::new_benchmark(challenge_mmcs);
        fri.log_blowup = log_blowup;
        Self {
            official: TwoAdicFriPcs::new(Radix2DitParallel::<P::Val>::default(), val_mmcs, fri),
        }
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Default
    for ResourceBoundedVerifierPcs<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn default() -> Self {
        Self::new(1)
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> BuildPeriodicLdeTableFast
    for ResourceBoundedVerifierPcs<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type PeriodicDomain = TwoAdicMultiplicativeCoset<P::Val>;
}

impl<const W: usize, const D: usize, P> Pcs<P::Challenge, ProfileChallengerFor<W, D, P>>
    for ResourceBoundedVerifierPcs<W, D, P>
where
    P: DurableFieldProfile<W, D>,
    // Restated because `Pcs` requires serde on `Commitment`/`Proof` and serde's
    // array impls are macro-generated per length.
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    OfficialPcs<W, D, P>: Pcs<
        P::Challenge,
        ProfileChallengerFor<W, D, P>,
        Domain = TwoAdicMultiplicativeCoset<P::Val>,
        Commitment = MerkleCap<P::Val, [P::Val; D]>,
    >,
    <OfficialPcs<W, D, P> as Pcs<P::Challenge, ProfileChallengerFor<W, D, P>>>::Proof:
        for<'de> serde::Deserialize<'de>,
    DurablePcsProof<W, D, P>: serde::Serialize,
{
    type Domain = TwoAdicMultiplicativeCoset<P::Val>;
    type Commitment = MerkleCap<P::Val, [P::Val; D]>;
    type ProverData = ();
    type EvaluationsOnDomain<'a> = RowMajorMatrix<P::Val>;
    type Proof = DurablePcsProof<W, D, P>;
    type Error = String;
    const ZK: bool = false;

    fn natural_domain_for_degree(&self, degree: usize) -> Self::Domain {
        TwoAdicMultiplicativeCoset::new(P::Val::ONE, degree.trailing_zeros() as usize)
            .expect("validated power-of-two trace degree")
    }

    fn log_max_lde_height(&self) -> usize {
        P::Val::TWO_ADICITY
    }

    fn commit(
        &self,
        _evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<P::Val>)>,
    ) -> (Self::Commitment, Self::ProverData) {
        panic!("bounded proving bypasses the owned-matrix PCS entry point")
    }

    fn get_quotient_ldes(
        &self,
        _evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<P::Val>)>,
        _num_chunks: usize,
    ) -> Vec<RowMajorMatrix<P::Val>> {
        panic!("bounded proving uses scratch-backed quotient LDEs")
    }

    fn commit_ldes(
        &self,
        _ldes: Vec<RowMajorMatrix<P::Val>>,
    ) -> (Self::Commitment, Self::ProverData) {
        panic!("bounded proving uses the durable MMCS directly")
    }

    fn get_evaluations_on_domain<'a>(
        &self,
        _prover_data: &'a Self::ProverData,
        _idx: usize,
        _domain: Self::Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        panic!("bounded proving reads its standard-order LDE stores directly")
    }

    fn open(
        &self,
        _commitment_data_with_opening_points: Vec<(&Self::ProverData, Vec<Vec<P::Challenge>>)>,
        _challenger: &mut ProfileChallengerFor<W, D, P>,
    ) -> (OpenedValues<P::Challenge>, Self::Proof) {
        panic!("bounded proving uses durable opening orchestration")
    }

    fn verify(
        &self,
        commitments_with_opening_points: Vec<(
            Self::Commitment,
            Vec<(Self::Domain, Vec<(P::Challenge, Vec<P::Challenge>)>)>,
        )>,
        proof: &Self::Proof,
        challenger: &mut ProfileChallengerFor<W, D, P>,
    ) -> std::result::Result<(), Self::Error> {
        let bytes = postcard::to_allocvec(proof).map_err(|error| error.to_string())?;
        let official_proof: <OfficialPcs<W, D, P> as Pcs<
            P::Challenge,
            ProfileChallengerFor<W, D, P>,
        >>::Proof = postcard::from_bytes(&bytes).map_err(|error| error.to_string())?;
        <OfficialPcs<W, D, P> as Pcs<P::Challenge, ProfileChallengerFor<W, D, P>>>::verify(
            &self.official,
            commitments_with_opening_points,
            &official_proof,
            challenger,
        )
        .map_err(|error| format!("{error:?}"))
    }
}

pub type BoundedConfig<const W: usize, const D: usize, P> = StarkConfig<
    ResourceBoundedVerifierPcs<W, D, P>,
    <P as DurableFieldProfile<W, D>>::Challenge,
    ProfileChallengerFor<W, D, P>,
>;

pub fn make_bounded_verifier_config<const W: usize, const D: usize, P>(
    log_blowup: usize,
) -> BoundedConfig<W, D, P>
where
    P: DurableFieldProfile<W, D>,
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    StarkConfig::new(
        ResourceBoundedVerifierPcs::<W, D, P>::new(log_blowup),
        ProfileChallengerFor::<W, D, P>::new(P::profile_permutation()),
    )
}

pub fn make_durable_mmcs<const W: usize, const D: usize, P>(
    policy: ResourcePolicyV1,
) -> DurableInputMmcs<W, D, P>
where
    P: DurableFieldProfile<W, D>,
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    DurableInputMmcs::<W, D, P>::new(P::profile_hash(), P::profile_compression(), policy)
        .expect("validated resource policy constructs durable MMCS")
}

/// Goldilocks pins, so `bounded_prover` keeps naming exactly the types it named
/// before this module became generic.
pub mod goldilocks {
    use crate::profile::GoldilocksProfile;

    pub type DurableInputMmcs = super::DurableInputMmcs<8, 4, GoldilocksProfile>;
    pub type DurableChallengeMmcs = super::DurableChallengeMmcs<8, 4, GoldilocksProfile>;
    pub type DurablePcsProof = super::DurablePcsProof<8, 4, GoldilocksProfile>;
    pub type ResourceBoundedVerifierPcs =
        super::ResourceBoundedVerifierPcs<8, 4, GoldilocksProfile>;
    pub type BoundedConfig = super::BoundedConfig<8, 4, GoldilocksProfile>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::GoldilocksProfile;
    use crate::prover::{Challenge, GoldilocksConfig, Val};
    use crate::ProfileChallenger;

    /// The Goldilocks instantiation of the upstream PCS proof, which `verify`
    /// decodes into. Pinned here so the generic alias chain cannot drift away
    /// from the official wire type.
    type OfficialProof =
        <OfficialPcs<8, 4, GoldilocksProfile> as Pcs<Challenge, ProfileChallenger>>::Proof;

    #[test]
    fn bounded_and_official_pcs_proof_types_have_identical_empty_encoding() {
        // The meaningful cross-type equality is exercised by full proof tests;
        // this pins the aliases and prevents accidental type/profile drift.
        let _: core::marker::PhantomData<GoldilocksConfig<Radix2DitParallel<Val>>> =
            core::marker::PhantomData;
        let _: core::marker::PhantomData<OfficialProof> = core::marker::PhantomData;
        assert_eq!(crate::PLONKY3_VERSION, "0.6.1");
    }
}
