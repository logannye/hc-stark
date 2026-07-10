use crate::dft::ResourceBoundedDft;
use crate::workloads::{fibonacci_trace, poseidon2_goldilocks_air, poseidon2_trace, FibonacciAir};
use hc_stream::ResourcePolicyV1;
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, Proof, StarkConfig};
use rand::rngs::SmallRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

pub const PLONKY3_VERSION: &str = "0.6.1";
pub const COMPATIBILITY_PROFILE: &str = "tinyzkp-p3-goldilocks-v1";
const MAX_PACKAGED_PROOF_BYTES: usize = 64 * 1024 * 1024;

type Val = Goldilocks;
type Challenge = BinomialExtensionField<Val, 2>;
type Permutation = Poseidon2Goldilocks<8>;
type Hash = PaddingFreeSponge<Permutation, 8, 4, 4>;
type Compression = TruncatedPermutation<Permutation, 2, 4, 8>;
type ValPacking = <Val as Field>::Packing;
type ValMmcs = MerkleTreeMmcs<ValPacking, ValPacking, Hash, Compression, 2, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Permutation, 8, 4>;
type Pcs<Dft> = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type GoldilocksConfig<Dft> = StarkConfig<Pcs<Dft>, Challenge, Challenger>;

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("unsupported workload or row count")]
    InvalidWorkload,
    #[error("proof bundle exceeds the size limit")]
    ProofTooLarge,
    #[error("proof bundle profile or dependency version mismatch")]
    ProfileMismatch,
    #[error("proof digest mismatch")]
    DigestMismatch,
    #[error("official Plonky3 verifier rejected the proof: {0}")]
    Verification(String),
    #[error("proof serialization failed: {0}")]
    Serialization(String),
    #[error(transparent)]
    Dft(#[from] crate::dft::DftError),
}

pub type Result<T> = std::result::Result<T, BackendError>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "workload", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkloadKind {
    Fibonacci { initial_a: u64, initial_b: u64 },
    Poseidon2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalProofBundle {
    pub schema_version: u32,
    pub compatibility_profile: String,
    pub plonky3_version: String,
    pub workload: WorkloadKind,
    pub logical_rows: u64,
    pub public_values: Vec<u64>,
    pub proof_bytes: Vec<u8>,
    pub proof_digest: [u8; 32],
}

impl InternalProofBundle {
    pub fn validate_envelope(&self) -> Result<()> {
        if self.schema_version != 1
            || self.compatibility_profile != COMPATIBILITY_PROFILE
            || self.plonky3_version != PLONKY3_VERSION
        {
            return Err(BackendError::ProfileMismatch);
        }
        if self.proof_bytes.len() > MAX_PACKAGED_PROOF_BYTES {
            return Err(BackendError::ProofTooLarge);
        }
        if blake3::hash(&self.proof_bytes).as_bytes() != &self.proof_digest {
            return Err(BackendError::DigestMismatch);
        }
        validate_rows(self.logical_rows)?;
        Ok(())
    }
}

/// Prover orchestration that emits the official `p3_uni_stark::Proof` encoding.
/// TinyZKP adds no custom transcript or verifier.
#[derive(Clone, Debug)]
pub struct ResourceBoundedUniStarkProver {
    policy: ResourcePolicyV1,
}

impl ResourceBoundedUniStarkProver {
    pub fn new(policy: ResourcePolicyV1) -> Result<Self> {
        policy.validate().map_err(crate::dft::DftError::from)?;
        Ok(Self { policy })
    }

    pub fn policy(&self) -> &ResourcePolicyV1 {
        &self.policy
    }

    pub fn prove(&self, workload: WorkloadKind, logical_rows: u64) -> Result<InternalProofBundle> {
        let rows = validate_rows(logical_rows)?;
        match workload {
            WorkloadKind::Fibonacci {
                initial_a,
                initial_b,
            } => self.prove_fibonacci(initial_a, initial_b, rows),
            WorkloadKind::Poseidon2 => self.prove_poseidon2(rows),
        }
    }

    pub fn verify(bundle: &InternalProofBundle) -> Result<()> {
        bundle.validate_envelope()?;
        let rows = validate_rows(bundle.logical_rows)?;
        let config = make_config(Radix2DitParallel::<Val>::default());
        match bundle.workload {
            WorkloadKind::Fibonacci {
                initial_a,
                initial_b,
            } => {
                if bundle.public_values.len() != 3 {
                    return Err(BackendError::InvalidWorkload);
                }
                let trace = fibonacci_trace::<Val>(initial_a, initial_b, rows);
                let expected = vec![
                    initial_a,
                    initial_b,
                    trace.values[trace.values.len() - 1].as_canonical_u64(),
                ];
                if bundle.public_values != expected {
                    return Err(BackendError::InvalidWorkload);
                }
                let public: Vec<_> = expected.into_iter().map(Val::from_u64).collect();
                let proof: Proof<GoldilocksConfig<Radix2DitParallel<Val>>> =
                    decode_proof(&bundle.proof_bytes)?;
                verify(&config, &FibonacciAir, &proof, &public)
                    .map_err(|error| BackendError::Verification(format!("{error:?}")))
            }
            WorkloadKind::Poseidon2 => {
                if !bundle.public_values.is_empty() {
                    return Err(BackendError::InvalidWorkload);
                }
                let proof: Proof<GoldilocksConfig<Radix2DitParallel<Val>>> =
                    decode_proof(&bundle.proof_bytes)?;
                verify(&config, &poseidon2_goldilocks_air(), &proof, &[])
                    .map_err(|error| BackendError::Verification(format!("{error:?}")))
            }
        }
    }

    /// Conventional upstream DFT path used only as the benchmark baseline.
    pub fn prove_reference(
        workload: WorkloadKind,
        logical_rows: u64,
    ) -> Result<InternalProofBundle> {
        let rows = validate_rows(logical_rows)?;
        match workload {
            WorkloadKind::Fibonacci {
                initial_a,
                initial_b,
            } => {
                let trace = fibonacci_trace::<Val>(initial_a, initial_b, rows);
                let public = vec![
                    Val::from_u64(initial_a),
                    Val::from_u64(initial_b),
                    trace.values[trace.values.len() - 1],
                ];
                let proof_bytes = prove_to_bytes(
                    Radix2DitParallel::<Val>::default(),
                    &FibonacciAir,
                    trace,
                    &public,
                )?;
                Ok(bundle(
                    WorkloadKind::Fibonacci {
                        initial_a,
                        initial_b,
                    },
                    rows,
                    public
                        .iter()
                        .map(|value| value.as_canonical_u64())
                        .collect(),
                    proof_bytes,
                ))
            }
            WorkloadKind::Poseidon2 => {
                let trace = poseidon2_trace(rows, 0);
                let proof_bytes = prove_to_bytes(
                    Radix2DitParallel::<Val>::default(),
                    &poseidon2_goldilocks_air(),
                    trace,
                    &[],
                )?;
                Ok(bundle(WorkloadKind::Poseidon2, rows, vec![], proof_bytes))
            }
        }
    }

    fn prove_fibonacci(
        &self,
        initial_a: u64,
        initial_b: u64,
        rows: usize,
    ) -> Result<InternalProofBundle> {
        let trace = fibonacci_trace::<Val>(initial_a, initial_b, rows);
        let public = vec![
            Val::from_u64(initial_a),
            Val::from_u64(initial_b),
            trace.values[trace.values.len() - 1],
        ];
        let proof_bytes = prove_to_bytes(
            ResourceBoundedDft::new(self.policy.clone())?,
            &FibonacciAir,
            trace,
            &public,
        )?;
        Ok(bundle(
            WorkloadKind::Fibonacci {
                initial_a,
                initial_b,
            },
            rows,
            public
                .iter()
                .map(|value| value.as_canonical_u64())
                .collect(),
            proof_bytes,
        ))
    }

    fn prove_poseidon2(&self, rows: usize) -> Result<InternalProofBundle> {
        let trace = poseidon2_trace(rows, 0);
        let proof_bytes = prove_to_bytes(
            ResourceBoundedDft::new(self.policy.clone())?,
            &poseidon2_goldilocks_air(),
            trace,
            &[],
        )?;
        Ok(bundle(WorkloadKind::Poseidon2, rows, vec![], proof_bytes))
    }
}

fn validate_rows(rows: u64) -> Result<usize> {
    let rows = usize::try_from(rows).map_err(|_| BackendError::InvalidWorkload)?;
    if rows == 0 || !rows.is_power_of_two() || rows > (1usize << 30) {
        return Err(BackendError::InvalidWorkload);
    }
    Ok(rows)
}

fn bundle(
    workload: WorkloadKind,
    rows: usize,
    public_values: Vec<u64>,
    proof_bytes: Vec<u8>,
) -> InternalProofBundle {
    InternalProofBundle {
        schema_version: 1,
        compatibility_profile: COMPATIBILITY_PROFILE.into(),
        plonky3_version: PLONKY3_VERSION.into(),
        workload,
        logical_rows: rows as u64,
        public_values,
        proof_digest: *blake3::hash(&proof_bytes).as_bytes(),
        proof_bytes,
    }
}

fn make_config<Dft: TwoAdicSubgroupDft<Val>>(dft: Dft) -> GoldilocksConfig<Dft> {
    // Copied without parameter changes from Plonky3 v0.6.1's
    // `prove_goldilocks_poseidon2` example.
    let mut rng = SmallRng::seed_from_u64(1);
    let permutation = Permutation::new_from_rng_128(&mut rng);
    let hash = Hash::new(permutation.clone());
    let compression = Compression::new(permutation.clone());
    let val_mmcs = ValMmcs::new(hash, compression, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_parameters = FriParameters::new_benchmark(challenge_mmcs);
    let pcs = Pcs::new(dft, val_mmcs, fri_parameters);
    let challenger = Challenger::new(permutation);
    GoldilocksConfig::new(pcs, challenger)
}

fn prove_to_bytes<Dft, Air>(
    dft: Dft,
    air: &Air,
    trace: RowMajorMatrix<Val>,
    public_values: &[Val],
) -> Result<Vec<u8>>
where
    Dft: TwoAdicSubgroupDft<Val>,
    Air: for<'a> p3_air::Air<p3_uni_stark::ProverConstraintFolder<'a, GoldilocksConfig<Dft>>>
        + for<'a> p3_air::Air<p3_air::DebugConstraintBuilder<'a, Val>>
        + p3_air::Air<p3_air::SymbolicAirBuilder<Val>>
        + p3_air::BaseAir<Val>,
{
    let config = make_config(dft);
    let proof = prove(&config, air, trace, public_values);
    let bytes = postcard::to_allocvec(&proof)
        .map_err(|error| BackendError::Serialization(error.to_string()))?;
    if bytes.len() > MAX_PACKAGED_PROOF_BYTES {
        return Err(BackendError::ProofTooLarge);
    }
    Ok(bytes)
}

fn decode_proof<Config: p3_uni_stark::StarkGenericConfig>(bytes: &[u8]) -> Result<Proof<Config>> {
    if bytes.len() > MAX_PACKAGED_PROOF_BYTES {
        return Err(BackendError::ProofTooLarge);
    }
    postcard::from_bytes(bytes).map_err(|error| BackendError::Serialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_stream::{CheckpointPolicy, ResourceMode};

    fn policy(root: &std::path::Path) -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 128 * 1024 * 1024,
            max_scratch_bytes: 1024 * 1024 * 1024,
            scratch_dir: root.to_path_buf(),
            max_threads: 1,
            checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
        }
    }

    fn memory_policy(root: &std::path::Path) -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            mode: ResourceMode::Memory,
            ..policy(root)
        }
    }

    #[test]
    fn fibonacci_proof_is_accepted_by_unmodified_plonky3_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let prover = ResourceBoundedUniStarkProver::new(policy(dir.path())).unwrap();
        let bundle = prover
            .prove(
                WorkloadKind::Fibonacci {
                    initial_a: 0,
                    initial_b: 1,
                },
                8,
            )
            .unwrap();
        ResourceBoundedUniStarkProver::verify(&bundle).unwrap();
    }

    #[test]
    fn poseidon2_proof_is_accepted_by_unmodified_plonky3_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let prover = ResourceBoundedUniStarkProver::new(policy(dir.path())).unwrap();
        let bundle = prover.prove(WorkloadKind::Poseidon2, 8).unwrap();
        ResourceBoundedUniStarkProver::verify(&bundle).unwrap();
    }

    #[test]
    fn public_value_and_proof_mutations_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let prover = ResourceBoundedUniStarkProver::new(policy(dir.path())).unwrap();
        let bundle = prover
            .prove(
                WorkloadKind::Fibonacci {
                    initial_a: 0,
                    initial_b: 1,
                },
                8,
            )
            .unwrap();

        let mut public_mutation = bundle.clone();
        public_mutation.public_values[2] ^= 1;
        assert!(ResourceBoundedUniStarkProver::verify(&public_mutation).is_err());

        let mut proof_mutation = bundle;
        proof_mutation.proof_bytes[0] ^= 1;
        assert!(matches!(
            ResourceBoundedUniStarkProver::verify(&proof_mutation),
            Err(BackendError::DigestMismatch)
        ));
    }

    #[test]
    fn scratch_and_reference_dft_emit_identical_fibonacci_proof_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let trace = fibonacci_trace::<Val>(0, 1, 8);
        let public = vec![Val::ZERO, Val::ONE, Val::from_u64(21)];
        let bounded = prove_to_bytes(
            ResourceBoundedDft::new(policy(dir.path())).unwrap(),
            &FibonacciAir,
            trace.clone(),
            &public,
        )
        .unwrap();
        let reference = prove_to_bytes(
            Radix2DitParallel::<Val>::default(),
            &FibonacciAir,
            trace,
            &public,
        )
        .unwrap();
        assert_eq!(bounded, reference);
    }

    #[test]
    fn scratch_and_reference_dft_emit_identical_poseidon2_proof_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let trace = poseidon2_trace(8, 0);
        let bounded = prove_to_bytes(
            ResourceBoundedDft::new(policy(dir.path())).unwrap(),
            &poseidon2_goldilocks_air(),
            trace.clone(),
            &[],
        )
        .unwrap();
        let reference = prove_to_bytes(
            Radix2DitParallel::<Val>::default(),
            &poseidon2_goldilocks_air(),
            trace,
            &[],
        )
        .unwrap();
        assert_eq!(bounded, reference);
    }

    #[test]
    fn memory_and_scratch_modes_emit_identical_official_proofs() {
        let dir = tempfile::tempdir().unwrap();
        let workload = WorkloadKind::Fibonacci {
            initial_a: 0,
            initial_b: 1,
        };
        let memory = ResourceBoundedUniStarkProver::new(memory_policy(dir.path()))
            .unwrap()
            .prove(workload.clone(), 16)
            .unwrap();
        let scratch = ResourceBoundedUniStarkProver::new(policy(dir.path()))
            .unwrap()
            .prove(workload, 16)
            .unwrap();
        assert_eq!(memory, scratch);
    }
}
