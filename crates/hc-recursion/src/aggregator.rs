use hc_core::{error::HcResult, field::FieldElement};
use hc_hash::{blake3::Blake3, hash::HashDigest, HashFunction};
use hc_verifier::{verify_with_summary, Proof, QueryCommitments, VerificationSummary};

#[derive(Clone, Debug)]
pub struct ProofSummary<F: FieldElement> {
    pub trace_root: HashDigest,
    pub initial_acc: F,
    pub final_acc: F,
    pub trace_length: usize,
    pub query_commitments: QueryCommitments,
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
        let verification = verify_with_summary(proof)?;
        summaries.push(summarize(&verification));
    }
    let digest = digest_summaries(&summaries);
    Ok(AggregatedProof {
        total_proofs: proofs.len(),
        summaries,
        digest,
    })
}

pub fn summarize<F: FieldElement>(summary: &VerificationSummary<F>) -> ProofSummary<F> {
    ProofSummary {
        trace_root: summary.trace_root,
        initial_acc: summary.initial_acc,
        final_acc: summary.final_acc,
        trace_length: summary.trace_length,
        query_commitments: summary.query_commitments.clone(),
    }
}

fn digest_summaries<F: FieldElement>(summaries: &[ProofSummary<F>]) -> HashDigest {
    let mut bytes = Vec::with_capacity(summaries.len() * (32 + 16 + 8 + 64));
    for summary in summaries {
        bytes.extend_from_slice(summary.trace_root.as_bytes());
        bytes.extend_from_slice(&summary.initial_acc.to_u64().to_le_bytes());
        bytes.extend_from_slice(&summary.final_acc.to_u64().to_le_bytes());
        bytes.extend_from_slice(&(summary.trace_length as u64).to_le_bytes());
        bytes.extend_from_slice(summary.query_commitments.trace_commitment.as_bytes());
        bytes.extend_from_slice(summary.query_commitments.fri_commitment.as_bytes());
    }
    Blake3::hash(&bytes)
}
