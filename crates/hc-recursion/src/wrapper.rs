use crate::{
    aggregator::{aggregate_with_spec, AggregatedProof},
    artifact::{build_recursive_artifact, AggregatedProofArtifact},
    spec::RecursionSpec,
};
use hc_core::{error::HcResult, field::prime_field::GoldilocksField};
use hc_verifier::Proof;

pub fn wrap_proofs(
    proofs: &[Proof<GoldilocksField>],
) -> HcResult<AggregatedProof<GoldilocksField>> {
    wrap_proofs_with_spec(&RecursionSpec::default(), proofs)
}

pub fn wrap_proofs_with_spec(
    spec: &RecursionSpec,
    proofs: &[Proof<GoldilocksField>],
) -> HcResult<AggregatedProof<GoldilocksField>> {
    aggregate_with_spec(spec, proofs)
}

pub fn wrap_recursive_artifact(
    proofs: &[Proof<GoldilocksField>],
) -> HcResult<AggregatedProofArtifact> {
    wrap_recursive_artifact_with_spec(&RecursionSpec::default(), proofs)
}

pub fn wrap_recursive_artifact_with_spec(
    spec: &RecursionSpec,
    proofs: &[Proof<GoldilocksField>],
) -> HcResult<AggregatedProofArtifact> {
    build_recursive_artifact(spec, proofs)
}
