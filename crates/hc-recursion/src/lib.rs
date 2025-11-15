#![forbid(unsafe_code)]

pub mod aggregator;
pub mod circuit;
pub mod spec;
pub mod wrapper;

pub use aggregator::{aggregate, AggregatedProof, ProofSummary};
pub use spec::RecursionSpec;
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
        };
        let spec = RecursionSpec {
            max_depth: 1,
            fan_in: 1,
        };
        let err = wrap_proofs_with_spec(&spec, &[proof.clone(), proof]).unwrap_err();
        assert!(err.to_string().contains("recursion fan-in exceeded"));
    }
}
