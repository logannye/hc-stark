use hc_core::error::{HcError, HcResult};

#[derive(Clone, Debug)]
pub struct RecursionSpec {
    pub max_depth: usize,
    pub fan_in: usize,
}

impl RecursionSpec {
    pub fn validate_batch(&self, proofs: usize) -> HcResult<()> {
        if proofs > self.fan_in {
            return Err(HcError::invalid_argument(format!(
                "recursion fan-in exceeded: {proofs} > {}",
                self.fan_in
            )));
        }
        Ok(())
    }
}

impl Default for RecursionSpec {
    fn default() -> Self {
        Self {
            max_depth: 4,
            fan_in: 8,
        }
    }
}
