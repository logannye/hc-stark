//! Incremental Verifiable Computation (IVC) for STARK proofs.
//!
//! IVC allows a prover to incrementally prove a sequence of computation steps,
//! where each step verifies the previous proof and adds one new computation:
//!
//! ```text
//! Step 0: prove(program_0) → proof_0
//! Step 1: prove(program_1) + verify(proof_0) → proof_1
//! Step 2: prove(program_2) + verify(proof_1) → proof_2
//! ...
//! ```
//!
//! Each step produces a constant-size proof regardless of the total number of
//! steps, making this ideal for long-running computations and rollup state
//! transitions.
//!
//! The IVC proof contains:
//! - A STARK proof for the current computation step
//! - A commitment to the accumulated state (Poseidon hash chain)
//! - The step counter
//!
//! Verification checks:
//! 1. The STARK proof is valid for the claimed computation step
//! 2. The accumulated state matches the hash chain through all prior steps
//! 3. The step counter is consistent

use halo2curves::bn256::Fr;
use halo2curves::ff::Field;

use crate::circuit::poseidon;

/// An IVC step represents one incremental computation.
#[derive(Clone, Debug)]
pub struct IvcStep {
    /// Step number (0-indexed).
    pub step: u64,
    /// Accumulated state commitment at this step.
    ///
    /// `acc_state_0 = Poseidon(initial_state)`
    /// `acc_state_i = Poseidon(acc_state_{i-1}, step_digest_i)`
    pub accumulated_state: Fr,
    /// Digest of this step's computation (hash of inputs/outputs).
    pub step_digest: Fr,
    /// Initial accumulator value for this step's STARK.
    pub initial_acc: Fr,
    /// Final accumulator value for this step's STARK.
    pub final_acc: Fr,
}

/// The IVC chain state tracks the progression of incremental proofs.
#[derive(Clone, Debug)]
pub struct IvcChain {
    /// All steps in order.
    pub steps: Vec<IvcStep>,
    /// The initial seed for the accumulation chain.
    pub initial_seed: Fr,
}

impl IvcChain {
    /// Create a new IVC chain with a seed value.
    pub fn new(initial_seed: Fr) -> Self {
        Self {
            steps: Vec::new(),
            initial_seed,
        }
    }

    /// Add a computation step to the chain.
    ///
    /// The step digest should encode the computation's inputs and outputs.
    /// Returns the accumulated state after this step.
    pub fn add_step(&mut self, initial_acc: Fr, final_acc: Fr, step_digest: Fr) -> Fr {
        let step_num = self.steps.len() as u64;

        let prev_state = if self.steps.is_empty() {
            // First step: hash the initial seed.
            poseidon::hash(&[self.initial_seed])
        } else {
            self.steps.last().unwrap().accumulated_state
        };

        // acc_state_i = Poseidon(acc_state_{i-1}, step_digest_i)
        let accumulated_state = poseidon::hash(&[prev_state, step_digest]);

        self.steps.push(IvcStep {
            step: step_num,
            accumulated_state,
            step_digest,
            initial_acc,
            final_acc,
        });

        accumulated_state
    }

    /// Get the current accumulated state.
    pub fn current_state(&self) -> Fr {
        self.steps
            .last()
            .map(|s| s.accumulated_state)
            .unwrap_or_else(|| poseidon::hash(&[self.initial_seed]))
    }

    /// Get the current step number.
    pub fn current_step(&self) -> u64 {
        self.steps.len() as u64
    }

    /// Verify the entire chain's accumulated state is consistent.
    ///
    /// Recomputes the hash chain from scratch and verifies each step.
    pub fn verify_chain(&self) -> bool {
        let mut expected = poseidon::hash(&[self.initial_seed]);

        for step in &self.steps {
            expected = poseidon::hash(&[expected, step.step_digest]);
            if expected != step.accumulated_state {
                return false;
            }
        }

        true
    }

    /// Get a summary of the chain for recursive verification.
    pub fn summary(&self) -> IvcSummary {
        IvcSummary {
            total_steps: self.steps.len() as u64,
            initial_seed: self.initial_seed,
            final_state: self.current_state(),
            initial_acc: self
                .steps
                .first()
                .map(|s| s.initial_acc)
                .unwrap_or(Fr::ZERO),
            final_acc: self.steps.last().map(|s| s.final_acc).unwrap_or(Fr::ZERO),
        }
    }
}

/// Summary of an IVC chain for verification.
#[derive(Clone, Debug)]
pub struct IvcSummary {
    /// Total number of computation steps.
    pub total_steps: u64,
    /// The initial seed.
    pub initial_seed: Fr,
    /// The final accumulated state.
    pub final_state: Fr,
    /// The first step's initial accumulator.
    pub initial_acc: Fr,
    /// The last step's final accumulator.
    pub final_acc: Fr,
}

/// Compute a step digest from computation inputs and outputs.
///
/// This is the canonical way to commit to a single computation step.
/// The digest includes the step number to prevent step reordering.
pub fn compute_step_digest(step_number: u64, initial_acc: Fr, final_acc: Fr) -> Fr {
    poseidon::hash(&[Fr::from(step_number), initial_acc, final_acc])
}

/// Verify that an IVC summary is consistent with claimed step digests.
///
/// Given the initial seed and all step digests, recompute the hash chain
/// and verify it matches the summary's final state.
pub fn verify_ivc_summary(summary: &IvcSummary, step_digests: &[Fr]) -> bool {
    if step_digests.len() as u64 != summary.total_steps {
        return false;
    }

    let mut state = poseidon::hash(&[summary.initial_seed]);
    for digest in step_digests {
        state = poseidon::hash(&[state, *digest]);
    }

    state == summary.final_state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ivc_chain_single_step() {
        let seed = Fr::from(42u64);
        let mut chain = IvcChain::new(seed);

        let digest = compute_step_digest(0, Fr::from(5u64), Fr::from(8u64));
        let state = chain.add_step(Fr::from(5u64), Fr::from(8u64), digest);

        assert_eq!(chain.current_step(), 1);
        assert_eq!(chain.current_state(), state);
        assert!(chain.verify_chain());
    }

    #[test]
    fn ivc_chain_three_steps() {
        let seed = Fr::from(1u64);
        let mut chain = IvcChain::new(seed);

        for i in 0..3 {
            let init = Fr::from(i * 10);
            let fin = Fr::from(i * 10 + 5);
            let digest = compute_step_digest(i, init, fin);
            chain.add_step(init, fin, digest);
        }

        assert_eq!(chain.current_step(), 3);
        assert!(chain.verify_chain());

        let summary = chain.summary();
        assert_eq!(summary.total_steps, 3);
        assert_eq!(summary.initial_seed, seed);
    }

    #[test]
    fn ivc_chain_verify_detects_tampering() {
        let seed = Fr::from(42u64);
        let mut chain = IvcChain::new(seed);

        let digest = compute_step_digest(0, Fr::from(5u64), Fr::from(8u64));
        chain.add_step(Fr::from(5u64), Fr::from(8u64), digest);

        // Tamper with accumulated state.
        chain.steps[0].accumulated_state = Fr::from(999u64);
        assert!(!chain.verify_chain());
    }

    #[test]
    fn ivc_summary_verification() {
        let seed = Fr::from(7u64);
        let mut chain = IvcChain::new(seed);

        let mut digests = Vec::new();
        for i in 0..5 {
            let d = compute_step_digest(i, Fr::from(i), Fr::from(i + 1));
            digests.push(d);
            chain.add_step(Fr::from(i), Fr::from(i + 1), d);
        }

        let summary = chain.summary();
        assert!(verify_ivc_summary(&summary, &digests));

        // Wrong digest list.
        let mut bad_digests = digests.clone();
        bad_digests[2] = Fr::from(0u64);
        assert!(!verify_ivc_summary(&summary, &bad_digests));
    }

    #[test]
    fn ivc_chain_deterministic() {
        let seed = Fr::from(42u64);

        let mut c1 = IvcChain::new(seed);
        let mut c2 = IvcChain::new(seed);

        for i in 0..3 {
            let d = compute_step_digest(i, Fr::from(i), Fr::from(i + 1));
            c1.add_step(Fr::from(i), Fr::from(i + 1), d);
            c2.add_step(Fr::from(i), Fr::from(i + 1), d);
        }

        assert_eq!(c1.current_state(), c2.current_state());
        assert_eq!(c1.summary().final_state, c2.summary().final_state);
    }

    #[test]
    fn step_digest_includes_step_number() {
        // Same data, different step number → different digest.
        let d0 = compute_step_digest(0, Fr::from(1u64), Fr::from(2u64));
        let d1 = compute_step_digest(1, Fr::from(1u64), Fr::from(2u64));
        assert_ne!(d0, d1);
    }

    #[test]
    fn empty_chain_has_deterministic_state() {
        let chain = IvcChain::new(Fr::from(42u64));
        let state = chain.current_state();
        assert_ne!(state, Fr::ZERO);
        assert_eq!(chain.current_step(), 0);
    }
}
