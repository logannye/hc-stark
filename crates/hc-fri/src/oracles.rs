use hc_core::field::FieldElement;

/// Basic oracle abstraction for FRI layers.
pub trait FriOracle<F: FieldElement> {
    fn len(&self) -> usize;
    fn evaluations(&self) -> &[F];
}

#[derive(Clone, Debug)]
pub struct InMemoryFriOracle<F: FieldElement> {
    values: Vec<F>,
}

impl<F: FieldElement> InMemoryFriOracle<F> {
    pub fn new(values: Vec<F>) -> Self {
        Self { values }
    }

    pub fn into_inner(self) -> Vec<F> {
        self.values
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
