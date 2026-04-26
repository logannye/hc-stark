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
    use hc_core::field::{prime_field::GoldilocksField, FieldElement};
    use hc_hash::HashFunction;
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
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };
        verify(&proof).unwrap();
    }

    #[test]
    fn verifier_accepts_deep_stark_v3_proof() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap().with_protocol_version(3);
        let prover_proof = prove(config, program, inputs.clone()).unwrap();
        assert_eq!(prover_proof.version, 3);
        let proof = Proof {
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };
        verify(&proof).unwrap();
    }

    #[test]
    fn verifier_accepts_zk_v4_proof() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap().with_zk_masking(8);
        let prover_proof = prove(config, program, inputs.clone()).unwrap();
        assert_eq!(prover_proof.version, 4);
        let proof = Proof {
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };
        verify(&proof).unwrap();
    }

    #[test]
    fn zk_v4_proofs_are_nondeterministic_and_still_verify() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap().with_zk_masking(8);
        let prover_a = prove(config, program.clone(), inputs.clone()).unwrap();
        let prover_b = prove(config, program, inputs.clone()).unwrap();
        assert_eq!(prover_a.version, 4);
        assert_eq!(prover_b.version, 4);
        assert_ne!(
            prover_a.trace_commitment.as_root().unwrap(),
            prover_b.trace_commitment.as_root().unwrap(),
            "ZK masking should randomize the committed trace oracle"
        );

        let proof_a = Proof {
            version: prover_a.version,
            trace_commitment: prover_a.trace_commitment,
            composition_commitment: prover_a.composition_commitment,
            fri_proof: prover_a.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_a.query_response,
            trace_length: prover_a.trace_length,
            params: prover_a.params,
        };
        verify(&proof_a).unwrap();

        let proof_b = Proof {
            version: prover_b.version,
            trace_commitment: prover_b.trace_commitment,
            composition_commitment: prover_b.composition_commitment,
            fri_proof: prover_b.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_b.query_response,
            trace_length: prover_b.trace_length,
            params: prover_b.params,
        };
        verify(&proof_b).unwrap();
    }

    #[test]
    fn verifier_rejects_v3_tampered_trace_opening() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap().with_protocol_version(3);
        let prover_proof = prove(config, program, inputs.clone()).unwrap();
        let mut proof = Proof {
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };
        let response = proof.query_response.as_mut().expect("query response");
        // Tamper the *last* occurrence so it is the one used by the verifier's index map even if
        // the query index appears multiple times.
        let last = response.trace_queries.last_mut().expect("trace query");
        last.evaluation[0] = last.evaluation[0].add(GoldilocksField::ONE);
        assert!(verify(&proof).is_err());
    }

    #[test]
    fn verifier_rejects_v3_wrong_shifted_next_index() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap().with_protocol_version(3);
        let prover_proof = prove(config, program, inputs.clone()).unwrap();
        let mut proof = Proof {
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };
        let response = proof.query_response.as_mut().expect("query response");
        // Tamper the *last* occurrence to avoid duplicate-index overwrite in the verifier map.
        let last = response.trace_queries.last_mut().expect("trace query");
        let next = last.next.as_mut().expect("next opening");
        next.index = next.index.wrapping_add(1);
        assert!(verify(&proof).is_err());
    }

    #[test]
    fn verifier_rejects_v3_tampered_params_transcript_binding() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap().with_protocol_version(3);
        let prover_proof = prove(config, program, inputs.clone()).unwrap();
        let mut proof = Proof {
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };
        // Tamper blowup factor which is transcript-bound.
        proof.params.lde_blowup_factor += 1;
        assert!(verify(&proof).is_err());
    }

    #[test]
    fn verifier_rejects_v3_swapped_fri_query_ordering() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap().with_protocol_version(3);
        let prover_proof = prove(config, program, inputs.clone()).unwrap();
        let mut proof = Proof {
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };
        let response = proof.query_response.as_mut().expect("query response");
        if response.fri_queries.len() >= 2 {
            response.fri_queries.swap(0, 1);
        }
        assert!(verify(&proof).is_err());
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
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
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
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
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

    #[test]
    fn verifier_rejects_tampered_composition_opening() {
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
        let mut proof = Proof {
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };

        if let Some(response) = proof.query_response.as_mut() {
            if let Some(first) = response.composition_queries.first_mut() {
                first.value = first.value.add(GoldilocksField::ONE);
            }
        }
        assert!(verify(&proof).is_err());
    }

    #[test]
    fn verifier_rejects_missing_boundary_openings() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap().with_protocol_version(2);
        let prover_proof = prove(config, program, inputs.clone()).unwrap();
        let mut proof = Proof {
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };
        if let Some(response) = proof.query_response.as_mut() {
            response.boundary = None;
        }
        assert!(verify(&proof).is_err());
    }

    #[test]
    fn verifier_rejects_tampered_boundary_openings() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap().with_protocol_version(2);
        let prover_proof = prove(config, program, inputs.clone()).unwrap();
        let mut proof = Proof {
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };

        if let Some(response) = proof.query_response.as_mut() {
            let boundary = response.boundary.as_mut().expect("boundary should exist");
            // Break the boundary constraint directly.
            boundary.first_trace.evaluation[0] =
                boundary.first_trace.evaluation[0].add(GoldilocksField::ONE);
            // Also break a Merkle proof to ensure we fail even if boundary values were correct.
            if let TraceWitness::Merkle(path) = &mut boundary.last_trace.witness {
                *path = Default::default();
            }
        }
        assert!(verify(&proof).is_err());
    }

    #[test]
    fn verifier_rejects_tampered_fri_query_value() {
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
        let mut proof = Proof {
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };

        if let Some(response) = proof.query_response.as_mut() {
            if let Some(first) = response.fri_queries.first_mut() {
                first.values[0] = first.values[0].add(GoldilocksField::ONE);
            }
        }
        assert!(verify(&proof).is_err());
    }

    #[test]
    fn verifier_rejects_missing_fri_queries() {
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
        let mut proof = Proof {
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };
        if let Some(response) = proof.query_response.as_mut() {
            response.fri_queries.clear();
        }
        assert!(verify(&proof).is_err());
    }

    #[test]
    fn verifier_rejects_wrong_final_fri_root() {
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
        let mut proof = Proof {
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment,
            composition_commitment: prover_proof.composition_commitment,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };
        proof.fri_proof.final_root = hc_hash::Blake3::hash(b"wrong");
        assert!(verify(&proof).is_err());
    }
}
