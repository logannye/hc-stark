use hc_core::error::HcResult;
use hc_verifier::{verify, Proof};

#[derive(Clone, Debug)]
pub struct AggregatedProof {
    pub total_proofs: usize,
    pub final_accumulator: u64,
}

pub fn aggregate<F: hc_core::field::FieldElement>(
    proofs: &[Proof<F>],
) -> HcResult<AggregatedProof> {
    for proof in proofs {
        verify(proof)?;
    }
    Ok(AggregatedProof {
        total_proofs: proofs.len(),
        final_accumulator: proofs
            .last()
            .map(|p| p.final_acc.to_u64())
            .unwrap_or_default(),
    })
}
