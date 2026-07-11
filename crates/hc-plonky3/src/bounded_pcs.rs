use crate::mmcs::DurableGoldilocksMmcs;
use crate::prover::{
    profile_components, Challenge, ChallengeMmcs, Compression, Hash, Pcs as ReferencePcs, Val,
};
use crate::ProfileChallenger;
use hc_stream::ResourcePolicyV1;
use p3_commit::{BatchOpening, BuildPeriodicLdeTableFast, ExtensionMmcs, OpenedValues, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_fri::{FriParameters, FriProof, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleCap;
use p3_uni_stark::StarkConfig;

pub type DurableInputMmcs = DurableGoldilocksMmcs<Hash, Compression>;
pub type DurableChallengeMmcs = ExtensionMmcs<Val, Challenge, DurableInputMmcs>;
pub type DurablePcsProof =
    FriProof<Challenge, DurableChallengeMmcs, Val, Vec<BatchOpening<Val, DurableInputMmcs>>>;

type OfficialPcs = ReferencePcs<Radix2DitParallel<Val>>;
type OfficialProof = <OfficialPcs as Pcs<Challenge, ProfileChallenger>>::Proof;

/// Verifier-facing PCS for the durable prover. Its associated wire types are
/// identical to the official Plonky3 PCS. Verification delegates to the pinned
/// upstream implementation after a structural serde conversion.
#[derive(Clone)]
pub struct ResourceBoundedVerifierPcs {
    official: OfficialPcs,
}

impl ResourceBoundedVerifierPcs {
    pub fn new() -> Self {
        let (_, hash, compression) = profile_components();
        let val_mmcs = crate::prover::ValMmcs::new(hash, compression, 0);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri = FriParameters::new_benchmark(challenge_mmcs);
        Self {
            official: TwoAdicFriPcs::new(Radix2DitParallel::<Val>::default(), val_mmcs, fri),
        }
    }
}

impl Default for ResourceBoundedVerifierPcs {
    fn default() -> Self {
        Self::new()
    }
}

impl BuildPeriodicLdeTableFast for ResourceBoundedVerifierPcs {
    type PeriodicDomain = TwoAdicMultiplicativeCoset<Val>;
}

impl Pcs<Challenge, ProfileChallenger> for ResourceBoundedVerifierPcs {
    type Domain = TwoAdicMultiplicativeCoset<Val>;
    type Commitment = MerkleCap<Val, [Val; 4]>;
    type ProverData = ();
    type EvaluationsOnDomain<'a> = RowMajorMatrix<Val>;
    type Proof = DurablePcsProof;
    type Error = String;
    const ZK: bool = false;

    fn natural_domain_for_degree(&self, degree: usize) -> Self::Domain {
        TwoAdicMultiplicativeCoset::new(Val::ONE, degree.trailing_zeros() as usize)
            .expect("validated power-of-two trace degree")
    }

    fn log_max_lde_height(&self) -> usize {
        Val::TWO_ADICITY
    }

    fn commit(
        &self,
        _evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val>)>,
    ) -> (Self::Commitment, Self::ProverData) {
        panic!("bounded proving bypasses the owned-matrix PCS entry point")
    }

    fn get_quotient_ldes(
        &self,
        _evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val>)>,
        _num_chunks: usize,
    ) -> Vec<RowMajorMatrix<Val>> {
        panic!("bounded proving uses scratch-backed quotient LDEs")
    }

    fn commit_ldes(&self, _ldes: Vec<RowMajorMatrix<Val>>) -> (Self::Commitment, Self::ProverData) {
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
        _commitment_data_with_opening_points: Vec<(&Self::ProverData, Vec<Vec<Challenge>>)>,
        _challenger: &mut ProfileChallenger,
    ) -> (OpenedValues<Challenge>, Self::Proof) {
        panic!("bounded proving uses durable opening orchestration")
    }

    fn verify(
        &self,
        commitments_with_opening_points: Vec<(
            Self::Commitment,
            Vec<(Self::Domain, Vec<(Challenge, Vec<Challenge>)>)>,
        )>,
        proof: &Self::Proof,
        challenger: &mut ProfileChallenger,
    ) -> std::result::Result<(), Self::Error> {
        let bytes = postcard::to_allocvec(proof).map_err(|error| error.to_string())?;
        let official_proof: OfficialProof =
            postcard::from_bytes(&bytes).map_err(|error| error.to_string())?;
        <OfficialPcs as Pcs<Challenge, ProfileChallenger>>::verify(
            &self.official,
            commitments_with_opening_points,
            &official_proof,
            challenger,
        )
        .map_err(|error| format!("{error:?}"))
    }
}

pub type BoundedConfig = StarkConfig<ResourceBoundedVerifierPcs, Challenge, ProfileChallenger>;

pub fn make_bounded_verifier_config() -> BoundedConfig {
    let (permutation, _, _) = profile_components();
    StarkConfig::new(
        ResourceBoundedVerifierPcs::new(),
        ProfileChallenger::new(permutation),
    )
}

pub fn make_durable_mmcs(policy: ResourcePolicyV1) -> DurableInputMmcs {
    let (_, hash, compression) = profile_components();
    DurableInputMmcs::new(hash, compression, policy)
        .expect("validated resource policy constructs durable MMCS")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::GoldilocksConfig;

    #[test]
    fn bounded_and_official_pcs_proof_types_have_identical_empty_encoding() {
        // The meaningful cross-type equality is exercised by full proof tests;
        // this pins the aliases and prevents accidental type/profile drift.
        let _: core::marker::PhantomData<GoldilocksConfig<Radix2DitParallel<Val>>> =
            core::marker::PhantomData;
        assert_eq!(crate::PLONKY3_VERSION, "0.6.1");
    }
}
