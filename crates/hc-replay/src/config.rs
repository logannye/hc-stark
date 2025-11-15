use hc_core::error::{HcError, HcResult};

#[derive(Clone, Copy, Debug)]
pub struct ReplayConfig {
    pub block_size: usize,
    pub trace_length: usize,
}

impl ReplayConfig {
    pub fn new(block_size: usize, trace_length: usize) -> HcResult<Self> {
        if block_size == 0 {
            return Err(HcError::invalid_argument("block size must be positive"));
        }
        if trace_length == 0 {
            return Err(HcError::invalid_argument("trace length must be positive"));
        }
        Ok(Self {
            block_size,
            trace_length,
        })
    }
}
