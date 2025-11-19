#![forbid(unsafe_code)]

pub mod aggregator;
pub mod circuit;
pub mod spec;
pub mod wrapper;

pub use aggregator::{aggregate, AggregatedProof, ProofSummary};
pub use spec::{BatchPlan, RecursionLevel, RecursionSchedule, RecursionSpec};
pub use wrapper::{wrap_proofs, wrap_proofs_with_spec};

#[cfg(test)]
mod tests {
    use hc_core::field::prime_field::GoldilocksField;
    use hc_prover::{config::ProverConfig, prove, PublicInputs};
    use hc_verifier::Proof;
    use hc_vm::{Instruction, Program};

    use super::*;

    #[test]
    fn aggregator_checks_proofs() {
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
            trace_root: prover_proof.trace_root,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
        };
        let summary = aggregate(&[proof.clone()]).unwrap();
        assert_eq!(summary.total_proofs, 1);
        assert_eq!(summary.summaries[0].trace_root, prover_proof.trace_root);
        assert_ne!(
            summary.commitment(),
            hc_hash::hash::HashDigest::from([0u8; 32])
        );
    }

    #[test]
    fn spec_enforces_fan_in() {
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
            trace_root: prover_proof.trace_root,
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
        };
        let spec = RecursionSpec {
            max_depth: 1,
            fan_in: 1,
        };
        let err = wrap_proofs_with_spec(&spec, &[proof.clone(), proof]).unwrap_err();
        assert!(err.to_string().contains("recursion fan-in exceeded"));
    }

    #[test]
    fn summaries_capture_query_commitments() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);

        let inputs_a = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        let inputs_b = PublicInputs {
            initial_acc: GoldilocksField::new(7),
            final_acc: GoldilocksField::new(10),
        };

        let config = ProverConfig::new(2, 2).unwrap();
        let prover_a = prove(config.clone(), program.clone(), inputs_a.clone()).unwrap();
        let prover_b = prove(config, program, inputs_b.clone()).unwrap();

        let proof_a = Proof {
            trace_root: prover_a.trace_root,
            fri_proof: prover_a.fri_proof,
            initial_acc: inputs_a.initial_acc,
            final_acc: inputs_a.final_acc,
            query_response: prover_a.query_response,
            trace_length: prover_a.trace_length,
        };
        let proof_b = Proof {
            trace_root: prover_b.trace_root,
            fri_proof: prover_b.fri_proof,
            initial_acc: inputs_b.initial_acc,
            final_acc: inputs_b.final_acc,
            query_response: prover_b.query_response,
            trace_length: prover_b.trace_length,
        };

        let aggregated = wrap_proofs(&[proof_a, proof_b]).unwrap();

        assert_eq!(aggregated.total_proofs, 2);
        assert_eq!(aggregated.summaries.len(), 2);
        assert_ne!(
            aggregated.summaries[0].query_commitments.trace_commitment,
            aggregated.summaries[1].query_commitments.trace_commitment
        );
        assert_ne!(
            aggregated.summaries[0].query_commitments.fri_commitment,
            aggregated.summaries[1].query_commitments.fri_commitment
        );
    }

    #[test]
    fn schedule_drives_deterministic_batches() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let config = ProverConfig::new(2, 2).unwrap();

        let mut proofs = Vec::new();
        for offset in 0..6 {
            let inputs = PublicInputs {
                initial_acc: GoldilocksField::new(5 + offset),
                final_acc: GoldilocksField::new(8 + offset),
            };
            let prover_proof = prove(config.clone(), program.clone(), inputs.clone()).unwrap();
            proofs.push(Proof {
                trace_root: prover_proof.trace_root,
                fri_proof: prover_proof.fri_proof,
                initial_acc: inputs.initial_acc,
                final_acc: inputs.final_acc,
                query_response: prover_proof.query_response,
                trace_length: prover_proof.trace_length,
            });
        }

        let spec = RecursionSpec {
            max_depth: 4,
            fan_in: 2,
        };
        let schedule = spec.plan_for(proofs.len()).unwrap();
        assert_eq!(schedule.total_inputs, proofs.len());
        assert!(schedule.depth() >= 3);

        for batch in &schedule.levels[0].batches {
            let mut chunk = Vec::new();
            for idx in &batch.inputs {
                chunk.push(proofs[*idx].clone());
            }
            let agg_a = aggregate(&chunk).unwrap();
            let agg_b = aggregate(&chunk).unwrap();
            assert_eq!(agg_a.digest, agg_b.digest);
            for summary in &agg_a.summaries {
                assert!(crate::circuit::verify_query_commitments(summary));
            }
        }
    }
}
