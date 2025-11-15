use hc_core::error::{HcError, HcResult};

#[derive(Clone, Copy, Debug)]
pub struct ProverConfig {
    pub block_size: usize,
    pub fri_final_poly_size: usize,
    pub query_count: usize,
    pub lde_blowup_factor: usize,
}

impl ProverConfig {
    pub fn new(block_size: usize, fri_final_poly_size: usize) -> HcResult<Self> {
        Self::with_lde_blowup(block_size, fri_final_poly_size, 2) // Default to 2x blowup
    }

    pub fn with_lde_blowup(block_size: usize, fri_final_poly_size: usize, lde_blowup_factor: usize) -> HcResult<Self> {
        Self::with_full_config(block_size, fri_final_poly_size, 30, lde_blowup_factor)
    }

    pub fn with_query_count(block_size: usize, fri_final_poly_size: usize, query_count: usize) -> HcResult<Self> {
        Self::with_full_config(block_size, fri_final_poly_size, query_count, 2)
    }

    pub fn with_full_config(
        block_size: usize,
        fri_final_poly_size: usize,
        query_count: usize,
        lde_blowup_factor: usize,
    ) -> HcResult<Self> {
        if block_size == 0 || fri_final_poly_size == 0 || query_count == 0 || lde_blowup_factor == 0 {
            return Err(HcError::invalid_argument("config values must be positive"));
        }
        Ok(Self {
            block_size,
            fri_final_poly_size,
            query_count,
            lde_blowup_factor,
        })
    }
}
