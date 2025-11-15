use hc_core::error::{HcError, HcResult};

#[derive(Clone, Copy, Debug)]
pub struct ProverConfig {
    pub block_size: usize,
    pub fri_final_poly_size: usize,
}

impl ProverConfig {
    pub fn new(block_size: usize, fri_final_poly_size: usize) -> HcResult<Self> {
        if block_size == 0 || fri_final_poly_size == 0 {
            return Err(HcError::invalid_argument("config values must be positive"));
        }
        Ok(Self {
            block_size,
            fri_final_poly_size,
        })
    }
}
