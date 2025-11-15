use hc_core::field::FieldElement;
use hc_fri::{FriConfig, FriProof};

use crate::pipeline::phase2_fri;

pub fn prove_fri<F: FieldElement>(
    config: FriConfig,
    evaluations: Vec<F>,
) -> hc_core::error::HcResult<FriProof<F>> {
    phase2_fri::run_fri(config, evaluations)
}
