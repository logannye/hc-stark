use hc_core::{
    error::HcResult,
    field::{prime_field::GoldilocksField, FieldElement},
};
use hc_hash::{hash::HashDigest, Blake3, Transcript};
use hc_verifier::Proof;

use crate::{
    aggregator::{aggregate_with_spec, AggregatedProof, ProofSummary},
    circuit::{encode_summary, halo2, SummaryEncoding},
    spec::RecursionSpec,
};

#[derive(Clone, Debug)]
pub struct RecursiveWitness {
    encodings: Vec<SummaryEncoding>,
    field_count: usize,
    commitment: HashDigest,
}

impl RecursiveWitness {
    pub fn from_summaries(summaries: &[ProofSummary<GoldilocksField>]) -> Self {
        let encodings = summaries.iter().map(encode_summary).collect::<Vec<_>>();
        Self::new(encodings)
    }

    pub fn new(encodings: Vec<SummaryEncoding>) -> Self {
        let field_count = encodings.iter().map(|enc| enc.as_fields().len()).sum();
        let commitment = commit_encodings(&encodings);
        Self {
            encodings,
            field_count,
            commitment,
        }
    }

    pub fn encodings(&self) -> &[SummaryEncoding] {
        &self.encodings
    }

    pub fn field_count(&self) -> usize {
        self.field_count
    }

    pub fn commitment(&self) -> HashDigest {
        self.commitment
    }

    pub fn flatten(&self) -> Vec<GoldilocksField> {
        self.encodings()
            .iter()
            .flat_map(|enc| enc.as_fields())
            .collect()
    }
}

fn commit_encodings(encodings: &[SummaryEncoding]) -> HashDigest {
    let mut transcript = Transcript::<Blake3>::new(b"recursive_witness");
    for encoding in encodings {
        for value in encoding.as_fields() {
            let bytes = value.to_u64().to_le_bytes();
            transcript.append_message(b"summary", bytes);
        }
    }
    transcript.challenge_bytes(b"recursive_witness_commitment")
}

#[derive(Clone, Debug)]
pub struct AggregatedProofArtifact {
    pub aggregated: AggregatedProof<GoldilocksField>,
    pub witness: RecursiveWitness,
    pub circuit_proof: halo2::Halo2RecursiveProof,
}

impl AggregatedProofArtifact {
    pub fn verify(&self) -> HcResult<()> {
        self.aggregated.verify()?;
        halo2::verify_summaries(&self.circuit_proof, &self.aggregated.summaries)?;
        Ok(())
    }

    pub fn digest(&self) -> HashDigest {
        self.aggregated.digest
    }
}

pub fn build_recursive_artifact(
    spec: &RecursionSpec,
    proofs: &[Proof<GoldilocksField>],
) -> HcResult<AggregatedProofArtifact> {
    let aggregated = aggregate_with_spec(spec, proofs)?;
    let witness = RecursiveWitness::from_summaries(&aggregated.summaries);
    let circuit_proof = halo2::prove_summaries(&aggregated.summaries)?;
    let artifact = AggregatedProofArtifact {
        aggregated,
        witness,
        circuit_proof,
    };
    artifact.verify()?;
    Ok(artifact)
}

#[cfg(test)]
mod tests {
    use hc_core::field::prime_field::GoldilocksField;
    use hc_prover::{config::ProverConfig, prove, PublicInputs};
    use hc_verifier::Proof;
    use hc_vm::{Instruction, Program};

    use super::*;

    fn sample_proof(offset: u64) -> Proof<GoldilocksField> {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5 + offset),
            final_acc: GoldilocksField::new(8 + offset),
        };
        let config = ProverConfig::new(2, 2).unwrap();
        let output = prove(config, program, inputs.clone()).unwrap();
        Proof {
            version: output.version,
            trace_commitment: output.trace_commitment,
            composition_commitment: output.composition_commitment,
            fri_proof: output.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: output.query_response,
            trace_length: output.trace_length,
            params: output.params,
        }
    }

    #[test]
    fn artifact_verifies_witness_commitment() {
        let proofs = vec![sample_proof(0), sample_proof(1)];
        let spec = RecursionSpec::default();
        let artifact = build_recursive_artifact(&spec, &proofs).unwrap();
        assert_eq!(artifact.aggregated.total_proofs, 2);
        assert!(artifact.verify().is_ok());
        assert!(artifact.witness.field_count() > 0);
    }

    #[test]
    fn tampering_witness_fails_verification() {
        let proofs = vec![sample_proof(0), sample_proof(1)];
        let spec = RecursionSpec::default();
        let mut artifact = build_recursive_artifact(&spec, &proofs).unwrap();
        artifact.circuit_proof.proof[0] ^= 0xAA;
        assert!(artifact.verify().is_err());
    }
}
