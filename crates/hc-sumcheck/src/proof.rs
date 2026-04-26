//! Sumcheck claim and proof envelope types.

use hc_core::{HcError, HcResult};
use serde::{Deserialize, Serialize};

/// A sumcheck claim: "the polynomial `g` over `{0,1}^n` sums to `claimed_sum`."
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SumcheckClaim {
    pub num_variables: usize,
    pub degree: usize,
    pub claimed_sum: u64,
}

impl SumcheckClaim {
    pub fn new(num_variables: usize, degree: usize, claimed_sum: u64) -> Self {
        Self {
            num_variables,
            degree,
            claimed_sum,
        }
    }

    /// Cross-check the claim's metadata against a polynomial's actual rank.
    pub fn validate(&self, poly_num_vars: usize, poly_degree: usize) -> HcResult<()> {
        if self.num_variables != poly_num_vars {
            return Err(HcError::invalid_argument(format!(
                "claim num_variables {} != polynomial num_variables {}",
                self.num_variables, poly_num_vars
            )));
        }
        if self.degree != poly_degree {
            return Err(HcError::invalid_argument(format!(
                "claim degree {} != polynomial degree {}",
                self.degree, poly_degree
            )));
        }
        Ok(())
    }
}

/// One round of sumcheck: a univariate polynomial sent by the prover.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SumcheckRoundMsg {
    /// Coefficients of the round's univariate polynomial, in increasing-degree
    /// order. Length = `degree + 1`.
    pub coefficients: Vec<u64>,
}

/// Full sumcheck proof: a sequence of round messages plus the prover's claim
/// for the final-point evaluation `g(r_1, ..., r_n)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SumcheckProof {
    pub version: u8,
    pub rounds: Vec<SumcheckRoundMsg>,
    /// Evaluation `g(r_1, ..., r_n)` claimed by the prover; the verifier
    /// reduces the sum check to checking this single evaluation.
    pub final_evaluation: u64,
}

impl SumcheckProof {
    pub const VERSION: u8 = 1;
}
