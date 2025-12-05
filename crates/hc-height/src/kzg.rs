use ark_bn254::{Fr, G1Projective};
use ark_ec::Group;
use ark_ff::{One, PrimeField, Zero};
use hc_core::error::HcResult;

use crate::StreamingCommitment;

pub struct StreamingKzgCommitment {
    scalar_acc: Fr,
    tau_power: Fr,
    tau: Fr,
    generator: G1Projective,
}

impl Default for StreamingKzgCommitment {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingKzgCommitment {
    pub fn new() -> Self {
        Self::new_with_tau(Fr::from(5u64))
    }

    pub fn new_with_tau(tau: Fr) -> Self {
        Self {
            scalar_acc: Fr::zero(),
            tau_power: Fr::one(),
            tau,
            generator: Self::g1_generator(),
        }
    }

    pub fn g1_generator() -> G1Projective {
        G1Projective::generator()
    }
}

impl StreamingCommitment<Fr> for StreamingKzgCommitment {
    type Output = G1Projective;

    fn absorb_block(&mut self, _block_index: usize, data: &[Fr]) -> HcResult<()> {
        for coeff in data {
            self.scalar_acc += *coeff * self.tau_power;
            self.tau_power *= self.tau;
        }
        Ok(())
    }

    fn finalize(self) -> HcResult<Self::Output> {
        Ok(self.generator.mul_bigint(self.scalar_acc.into_bigint()))
    }
}
