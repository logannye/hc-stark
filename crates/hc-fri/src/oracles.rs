use std::sync::Arc;

use hc_core::field::FieldElement;

/// Basic oracle abstraction for FRI layers.
pub trait FriOracle<F: FieldElement> {
    fn len(&self) -> usize;
    fn evaluations(&self) -> &[F];
}

#[derive(Clone, Debug)]
pub struct InMemoryFriOracle<F: FieldElement> {
    values: Arc<Vec<F>>,
}

impl<F: FieldElement> InMemoryFriOracle<F> {
    pub fn new(values: Arc<Vec<F>>) -> Self {
        Self { values }
    }

    pub fn values(&self) -> Arc<Vec<F>> {
        Arc::clone(&self.values)
    }
}

impl<F: FieldElement> FriOracle<F> for InMemoryFriOracle<F> {
    fn len(&self) -> usize {
        self.values.len()
    }

    fn evaluations(&self) -> &[F] {
        &self.values
    }
}
