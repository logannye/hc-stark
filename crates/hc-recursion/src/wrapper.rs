use crate::{
    aggregator::{aggregate, AggregatedProof},
    spec::RecursionSpec,
};
use hc_core::{error::HcResult, field::FieldElement};
use hc_verifier::Proof;

pub fn wrap_proofs<F: FieldElement>(proofs: &[Proof<F>]) -> HcResult<AggregatedProof<F>> {
    wrap_proofs_with_spec(&RecursionSpec::default(), proofs)
}

pub fn wrap_proofs_with_spec<F: FieldElement>(
    spec: &RecursionSpec,
    proofs: &[Proof<F>],
) -> HcResult<AggregatedProof<F>> {
    spec.validate_batch(proofs.len())?;
    aggregate(proofs)
}
