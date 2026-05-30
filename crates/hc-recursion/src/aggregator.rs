use hc_core::{
    error::{HcError, HcResult},
    field::{prime_field::GoldilocksField, FieldElement},
};
use hc_hash::{blake3::Blake3, hash::HashDigest, HashFunction, DIGEST_LEN};
use hc_verifier::{verify_with_summary, Proof, QueryCommitments, VerificationSummary};

use crate::{
    circuit::encode_summary,
    spec::{RecursionSchedule, RecursionSpec},
};

#[derive(Clone, Debug)]
pub struct ProofSummary<F: FieldElement> {
    pub trace_commitment_digest: HashDigest,
    pub initial_acc: F,
    pub final_acc: F,
    pub trace_length: usize,
    pub query_commitments: QueryCommitments,
    pub circuit_digest: F,
}

#[derive(Clone, Debug)]
pub struct AggregatedProof<F: FieldElement> {
    pub total_proofs: usize,
    pub spec: RecursionSpec,
    pub schedule: RecursionSchedule,
    pub summaries: Vec<ProofSummary<F>>,
    pub digest: HashDigest,
}

impl<F: FieldElement> AggregatedProof<F> {
    pub fn commitment(&self) -> HashDigest {
        self.digest
    }

    pub fn verify(&self) -> HcResult<()> {
        let computed = compute_root::<F>(&self.schedule, &self.summaries)?;
        if computed != self.digest {
            return Err(HcError::invalid_argument(
                "aggregated proof digest mismatch",
            ));
        }
        Ok(())
    }
}

/// Aggregate proofs using the default [`RecursionSpec`].
///
/// # Soundness warning — audit finding G2
///
/// The in-circuit Halo2 FRI fold in [`crate::circuit::verify_fri`]
/// (`verify_fri.rs:74`) is **vacuous**: it constrains `vnext - (v0 + beta*v1)`
/// (adjacent-pair, no 1/x), so any aggregated proof produced by this function
/// inherits the G2 unsoundness documented in the Phase-1A audit.
///
/// **DO NOT expose this function through a live HTTP/MCP endpoint** until the
/// Phase-1B in-circuit fold fix lands. The `/aggregate` HTTP endpoint is gated
/// off (returns HTTP 410) precisely because of this. This library-level gate is
/// documentation-only; the enforcement happens at the server layer.
pub fn aggregate(proofs: &[Proof<GoldilocksField>]) -> HcResult<AggregatedProof<GoldilocksField>> {
    aggregate_with_spec(&RecursionSpec::default(), proofs)
}

/// Aggregate proofs with an explicit [`RecursionSpec`].
///
/// # Soundness warning — audit finding G2
///
/// See [`aggregate`] for the full warning. The in-circuit FRI fold is unsound;
/// do not expose through live endpoints before the Phase-1B fix.
pub fn aggregate_with_spec(
    spec: &RecursionSpec,
    proofs: &[Proof<GoldilocksField>],
) -> HcResult<AggregatedProof<GoldilocksField>> {
    if proofs.is_empty() {
        return Err(HcError::invalid_argument(
            "cannot aggregate an empty proof set",
        ));
    }
    let mut summaries = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let verification = verify_with_summary(proof)?;
        summaries.push(summarize(&verification));
    }
    let schedule = spec.plan_for(proofs.len())?;
    let digest = compute_root::<GoldilocksField>(&schedule, &summaries)?;
    Ok(AggregatedProof {
        total_proofs: proofs.len(),
        spec: spec.clone(),
        schedule,
        summaries,
        digest,
    })
}

pub fn summarize(summary: &VerificationSummary<GoldilocksField>) -> ProofSummary<GoldilocksField> {
    let mut proof_summary = ProofSummary {
        trace_commitment_digest: summary.trace_commitment_digest,
        initial_acc: summary.initial_acc,
        final_acc: summary.final_acc,
        trace_length: summary.trace_length,
        query_commitments: summary.query_commitments.clone(),
        circuit_digest: GoldilocksField::ZERO,
    };
    proof_summary.circuit_digest = circuit_digest(&proof_summary);
    proof_summary
}

pub(crate) fn digest_summary<F: FieldElement>(summary: &ProofSummary<F>) -> HashDigest {
    let mut bytes = Vec::with_capacity(32 + 3 * 8 + 64);
    bytes.extend_from_slice(summary.trace_commitment_digest.as_bytes());
    bytes.extend_from_slice(&summary.initial_acc.to_u64().to_le_bytes());
    bytes.extend_from_slice(&summary.final_acc.to_u64().to_le_bytes());
    bytes.extend_from_slice(&(summary.trace_length as u64).to_le_bytes());
    bytes.extend_from_slice(summary.query_commitments.trace_commitment.as_bytes());
    bytes.extend_from_slice(summary.query_commitments.fri_commitment.as_bytes());
    Blake3::hash(&bytes)
}

pub(crate) fn circuit_digest(summary: &ProofSummary<GoldilocksField>) -> GoldilocksField {
    let mut acc = 0u64;
    for value in encode_summary(summary).as_fields() {
        acc = add_goldilocks_u64(acc, value.to_u64());
    }
    GoldilocksField::from_u64(acc)
}

fn add_goldilocks_u64(acc: u64, value: u64) -> u64 {
    const MODULUS: u128 = 0xFFFF_FFFF00000001;
    let sum = acc as u128 + value as u128;
    if sum >= MODULUS {
        (sum - MODULUS) as u64
    } else {
        sum as u64
    }
}

pub(crate) fn compute_root<F: FieldElement>(
    schedule: &RecursionSchedule,
    summaries: &[ProofSummary<F>],
) -> HcResult<HashDigest> {
    if summaries.len() != schedule.total_inputs {
        return Err(HcError::invalid_argument(
            "summary count does not match recursion schedule",
        ));
    }
    let total_nodes = schedule.root + 1;
    let mut digests = vec![HashDigest::new([0u8; DIGEST_LEN]); total_nodes];
    for (idx, summary) in summaries.iter().enumerate() {
        digests[idx] = digest_summary(summary);
    }

    for level in &schedule.levels {
        for batch in &level.batches {
            if batch.inputs.is_empty() {
                return Err(HcError::invalid_argument("empty recursion batch"));
            }
            let mut buffer = Vec::with_capacity(batch.inputs.len() * DIGEST_LEN);
            for &input in &batch.inputs {
                buffer.extend_from_slice(digests[input].as_bytes());
            }
            digests[batch.output] = Blake3::hash(&buffer);
        }
    }

    Ok(digests[schedule.root])
}
