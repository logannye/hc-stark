use hc_core::{error::HcResult, field::FieldElement};
use hc_hash::{blake3::Blake3, hash::HashDigest, HashFunction};
use hc_verifier::{verify, Proof};

#[derive(Clone, Debug)]
pub struct ProofSummary<F: FieldElement> {
    pub trace_root: HashDigest,
    pub initial_acc: F,
    pub final_acc: F,
}

#[derive(Clone, Debug)]
pub struct AggregatedProof<F: FieldElement> {
    pub total_proofs: usize,
    pub summaries: Vec<ProofSummary<F>>,
    pub digest: HashDigest,
}

impl<F: FieldElement> AggregatedProof<F> {
    pub fn commitment(&self) -> HashDigest {
        self.digest
    }
}

pub fn aggregate<F: FieldElement>(proofs: &[Proof<F>]) -> HcResult<AggregatedProof<F>> {
    let mut summaries = Vec::with_capacity(proofs.len());
    for proof in proofs {
        verify(proof)?;
        summaries.push(summarize(proof));
    }
    let digest = digest_summaries(&summaries);
    Ok(AggregatedProof {
        total_proofs: proofs.len(),
        summaries,
        digest,
    })
}

pub fn summarize<F: FieldElement>(proof: &Proof<F>) -> ProofSummary<F> {
    ProofSummary {
        trace_root: proof.trace_root,
        initial_acc: proof.initial_acc,
        final_acc: proof.final_acc,
    }
}

fn digest_summaries<F: FieldElement>(summaries: &[ProofSummary<F>]) -> HashDigest {
    let mut bytes = Vec::with_capacity(summaries.len() * (32 + 16));
    for summary in summaries {
        bytes.extend_from_slice(summary.trace_root.as_bytes());
        bytes.extend_from_slice(&summary.initial_acc.to_u64().to_le_bytes());
        bytes.extend_from_slice(&summary.final_acc.to_u64().to_le_bytes());
    }
    Blake3::hash(&bytes)
}
