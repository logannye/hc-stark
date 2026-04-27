#![forbid(unsafe_code)]

pub mod aggregator;
pub mod aggregator_v2;
pub mod artifact;
pub mod circuit;
pub mod dual_commit;
pub mod ivc;
pub mod poseidon_transcript;
pub mod spec;
pub mod wrapper;

pub use aggregator::{aggregate, aggregate_with_spec, AggregatedProof, ProofSummary};
pub use artifact::{build_recursive_artifact, AggregatedProofArtifact, RecursiveWitness};
pub use circuit::halo2::Halo2RecursiveProof;
pub use spec::{BatchPlan, RecursionLevel, RecursionSchedule, RecursionSpec};
pub use wrapper::{
    wrap_proofs, wrap_proofs_with_spec, wrap_recursive_artifact, wrap_recursive_artifact_with_spec,
};

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
            version: prover_proof.version,
            trace_commitment: prover_proof.trace_commitment.clone(),
            composition_commitment: prover_proof.composition_commitment.clone(),
            fri_proof: prover_proof.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_proof.query_response,
            trace_length: prover_proof.trace_length,
            params: prover_proof.params,
        };
        let summary = aggregate(std::slice::from_ref(&proof)).unwrap();
        assert_eq!(summary.total_proofs, 1);
        summary.verify().unwrap();
        assert_eq!(
            summary.summaries[0].trace_commitment_digest,
            hc_prover::commitment::commitment_digest(&prover_proof.trace_commitment)
        );
        assert_ne!(
            summary.commitment(),
            hc_hash::hash::HashDigest::from([0u8; 32])
        );
    }

    #[test]
    fn spec_limits_depth() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap();
        let prover_proof = prove(config, program.clone(), inputs.clone()).unwrap();
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
        let spec = RecursionSpec {
            max_depth: 1,
            fan_in: 1,
        };
        let err = wrap_proofs_with_spec(&spec, &[proof.clone(), proof.clone(), proof]).unwrap_err();
        assert!(err.to_string().contains("depth exceeded"));
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
        let prover_a = prove(config, program.clone(), inputs_a.clone()).unwrap();
        let prover_b = prove(config, program, inputs_b.clone()).unwrap();

        let proof_a = Proof {
            version: prover_a.version,
            trace_commitment: prover_a.trace_commitment,
            composition_commitment: prover_a.composition_commitment,
            fri_proof: prover_a.fri_proof,
            initial_acc: inputs_a.initial_acc,
            final_acc: inputs_a.final_acc,
            query_response: prover_a.query_response,
            trace_length: prover_a.trace_length,
            params: prover_a.params,
        };
        let proof_b = Proof {
            version: prover_b.version,
            trace_commitment: prover_b.trace_commitment,
            composition_commitment: prover_b.composition_commitment,
            fri_proof: prover_b.fri_proof,
            initial_acc: inputs_b.initial_acc,
            final_acc: inputs_b.final_acc,
            query_response: prover_b.query_response,
            trace_length: prover_b.trace_length,
            params: prover_b.params,
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
            let prover_proof = prove(config, program.clone(), inputs.clone()).unwrap();
            proofs.push(Proof {
                version: prover_proof.version,
                trace_commitment: prover_proof.trace_commitment,
                composition_commitment: prover_proof.composition_commitment,
                fri_proof: prover_proof.fri_proof,
                initial_acc: inputs.initial_acc,
                final_acc: inputs.final_acc,
                query_response: prover_proof.query_response,
                trace_length: prover_proof.trace_length,
                params: prover_proof.params,
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
            agg_a.verify().unwrap();
            agg_b.verify().unwrap();
            assert_eq!(agg_a.digest, agg_b.digest);
            for summary in &agg_a.summaries {
                assert!(crate::circuit::verify_query_commitments(summary));
            }
        }
    }
}
