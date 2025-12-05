#![forbid(unsafe_code)]

pub mod air_check;
pub mod api;
pub mod errors;
pub mod fri_verify;
pub mod merkle;
pub mod queries;
pub mod transcript;

pub use api::{verify, verify_with_summary, Proof, QueryCommitments, VerificationSummary};

#[cfg(test)]
mod tests {
    use hc_core::field::prime_field::GoldilocksField;
    use hc_prover::{
        commitment::CommitmentScheme, config::ProverConfig, prove, queries::TraceWitness,
        PublicInputs,
    };
    use hc_vm::{Instruction, Program};

    use super::*;

    #[test]
    fn verifier_accepts_valid_proof() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap();
        let prover_proof = prove(config, program, inputs.clone()).unwrap();
        let proof = Proof {
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
        };
        verify(&proof).unwrap();
    }

    #[test]
    fn verifier_accepts_kzg_proof() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(3),
            final_acc: GoldilocksField::new(6),
        };
        let config = ProverConfig::new(2, 2)
            .unwrap()
            .with_commitment(CommitmentScheme::Kzg);
        let prover_proof = prove(config, program, inputs.clone()).unwrap();
        let proof = Proof {
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
        };
        verify(&proof).unwrap();
    }

    #[test]
    fn verifier_rejects_tampered_kzg_proof() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(4),
            final_acc: GoldilocksField::new(7),
        };
        let config = ProverConfig::new(2, 2)
            .unwrap()
            .with_commitment(CommitmentScheme::Kzg);
        let prover_proof = prove(config, program, inputs.clone()).unwrap();
        let mut proof = Proof {
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
        };
        // Tamper with one evaluation.
        if let Some(response) = proof.query_response.as_mut() {
            if let Some(first) = response.trace_queries.first_mut() {
                if let TraceWitness::Kzg(witness) = &mut first.witness {
                    if let Some(value) = witness.evaluations.get_mut(0) {
                        value.clear();
                        value.extend_from_slice(&[1u8; 32]);
                    }
                }
            }
        }
        assert!(verify(&proof).is_err(), "tampered KZG proof should fail");
    }
}
