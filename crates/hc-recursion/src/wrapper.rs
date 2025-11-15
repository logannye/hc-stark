use crate::aggregator::{aggregate, AggregatedProof};
use hc_verifier::Proof;

pub fn wrap_proofs<F: hc_core::field::FieldElement>(
    proofs: &[Proof<F>],
) -> hc_core::error::HcResult<AggregatedProof> {
    aggregate(proofs)
}
