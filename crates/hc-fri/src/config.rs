use hc_core::error::{HcError, HcResult};

/// Parameters that control how many reduction rounds the FRI prover executes.
#[derive(Clone, Copy, Debug)]
pub struct FriConfig {
    final_polynomial_size: usize,
}

impl FriConfig {
    pub fn new(final_polynomial_size: usize) -> HcResult<Self> {
        if final_polynomial_size == 0 {
            return Err(HcError::invalid_argument(
                "final polynomial size must be non-zero",
            ));
        }
        if final_polynomial_size & (final_polynomial_size - 1) != 0 {
            return Err(HcError::invalid_argument(
                "final polynomial size must be a power of two",
            ));
        }
        Ok(Self {
            final_polynomial_size,
        })
    }

    pub fn final_polynomial_size(&self) -> usize {
        self.final_polynomial_size
    }

    pub fn validate_trace_length(&self, trace_length: usize) -> HcResult<()> {
        if trace_length < self.final_polynomial_size {
            return Err(HcError::invalid_argument(
                "trace length must exceed final polynomial size",
            ));
        }
        if trace_length & (trace_length - 1) != 0 {
            return Err(HcError::invalid_argument(
                "trace length must be a power of two",
            ));
        }
        Ok(())
    }
}
